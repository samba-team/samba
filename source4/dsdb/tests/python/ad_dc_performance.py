#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import print_function

import optparse
import sys
sys.path.insert(0, 'bin/python')

import os
import samba
import samba.getopt as options
import random
import tempfile
import shutil
import time

from samba.netcmd.main import cmd_sambatool

# We try to use the test infrastructure of Samba 4.3+, but if it
# doesn't work, we are probably in a back-ported patch and trying to
# run on 4.1 or something.
#
# Don't copy this horror into ordinary tests -- it is special for
# performance tests that want to apply to old versions.
try:
    from samba.tests.subunitrun import SubunitOptions, TestProgram
    ANCIENT_SAMBA = False
except ImportError:
    ANCIENT_SAMBA = True
    samba.ensure_external_module("testtools", "testtools")
    samba.ensure_external_module("subunit", "subunit/python")
    from subunit.run import SubunitTestRunner
    import unittest

from samba.samdb import SamDB
from samba.auth import system_session
from ldb import Message, MessageElement, Dn, LdbError
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from ldb import SCOPE_BASE, SCOPE_SUBTREE, SCOPE_ONELEVEL

parser = optparse.OptionParser("ad_dc_performance.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

if not ANCIENT_SAMBA:
    subunitopts = SubunitOptions(parser)
    parser.add_option_group(subunitopts)

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()


if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

random.seed(1)


class PerfTestException(Exception):
    pass


BATCH_SIZE = 1000
N_GROUPS = 5


class GlobalState(object):
    next_user_id = 0
    n_groups = 0
    next_linked_user = 0
    next_relinked_user = 0
    next_linked_user_3 = 0
    next_removed_link_0 = 0


class UserTests(samba.tests.TestCase):

    def add_if_possible(self, *args, **kwargs):
        """In these tests sometimes things are left in the database
        deliberately, so we don't worry if we fail to add them a second
        time."""
        try:
            self.ldb.add(*args, **kwargs)
        except LdbError:
            pass

    def setUp(self):
        super(UserTests, self).setUp()
        self.state = GlobalState  # the class itself, not an instance
        self.lp = lp
        self.ldb = SamDB(host, credentials=creds,
                         session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.ou = "OU=pid%s,%s" % (os.getpid(), self.base_dn)
        self.ou_users = "OU=users,%s" % self.ou
        self.ou_groups = "OU=groups,%s" % self.ou
        self.ou_computers = "OU=computers,%s" % self.ou

        for dn in (self.ou, self.ou_users, self.ou_groups,
                   self.ou_computers):
            self.add_if_possible({
                "dn": dn,
                "objectclass": "organizationalUnit"})

    def tearDown(self):
        super(UserTests, self).tearDown()

    def test_00_00_do_nothing(self):
        # this gives us an idea of the overhead
        pass

    def _prepare_n_groups(self, n):
        self.state.n_groups = n
        for i in range(n):
            self.add_if_possible({
                "dn": "cn=g%d,%s" % (i, self.ou_groups),
                "objectclass": "group"})

    def _add_users(self, start, end):
        for i in range(start, end):
            self.ldb.add({
                "dn": "cn=u%d,%s" % (i, self.ou_users),
                "objectclass": "user"})

    def _test_join(self):
        tmpdir = tempfile.mkdtemp()
        if '://' in host:
            server = host.split('://', 1)[1]
        else:
            server = host
        cmd = cmd_sambatool.subcommands['domain'].subcommands['join']
        result = cmd._run("samba-tool domain join",
                          creds.get_realm(),
                          "dc", "-U%s%%%s" % (creds.get_username(),
                                              creds.get_password()),
                          '--targetdir=%s' % tmpdir,
                          '--server=%s' % server)

        shutil.rmtree(tmpdir)

    def _test_unindexed_search(self):
        expressions = [
            ('(&(objectclass=user)(description='
             'Built-in account for adminstering the computer/domain))'),
            '(description=Built-in account for adminstering the computer/domain)',
            '(objectCategory=*)',
            '(samaccountname=Administrator*)'
        ]
        for expression in expressions:
            t = time.time()
            for i in range(10):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print('%d %s took %s' % (i, expression,
                                     time.time() - t), file=sys.stderr)

    def _test_indexed_search(self):
        expressions = ['(objectclass=group)',
                       '(samaccountname=Administrator)'
                       ]
        for expression in expressions:
            t = time.time()
            for i in range(100):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print('%d runs %s took %s' % (i, expression,
                                          time.time() - t), file=sys.stderr)

    def _test_add_many_users(self, n=BATCH_SIZE):
        s = self.state.next_user_id
        e = s + n
        self._add_users(s, e)
        self.state.next_user_id = e

    test_00_00_join_empty_dc = _test_join

    test_00_01_adding_users_1000 = _test_add_many_users
    test_00_02_adding_users_2000 = _test_add_many_users
    test_00_03_adding_users_3000 = _test_add_many_users

    test_00_10_join_unlinked_dc = _test_join
    test_00_11_unindexed_search_3k_users = _test_unindexed_search
    test_00_12_indexed_search_3k_users = _test_indexed_search

    def _link_user_and_group(self, u, g):
        m = Message()
        m.dn = Dn(self.ldb, "CN=g%d,%s" % (g, self.ou_groups))
        m["member"] = MessageElement("cn=u%d,%s" % (u, self.ou_users),
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

    def _unlink_user_and_group(self, u, g):
        user = "cn=u%d,%s" % (u, self.ou_users)
        group = "CN=g%d,%s" % (g, self.ou_groups)
        m = Message()
        m.dn = Dn(self.ldb, group)
        m["member"] = MessageElement(user, FLAG_MOD_DELETE, "member")
        self.ldb.modify(m)

    def _test_link_many_users(self, n=BATCH_SIZE):
        self._prepare_n_groups(N_GROUPS)
        s = self.state.next_linked_user
        e = s + n
        for i in range(s, e):
            g = i % N_GROUPS
            self._link_user_and_group(i, g)
        self.state.next_linked_user = e

    test_01_01_link_users_1000 = _test_link_many_users
    test_01_02_link_users_2000 = _test_link_many_users
    test_01_03_link_users_3000 = _test_link_many_users

    def _test_link_many_users_offset_1(self, n=BATCH_SIZE):
        s = self.state.next_relinked_user
        e = s + n
        for i in range(s, e):
            g = (i + 1) % N_GROUPS
            self._link_user_and_group(i, g)
        self.state.next_relinked_user = e

    test_02_01_link_users_again_1000 = _test_link_many_users_offset_1
    test_02_02_link_users_again_2000 = _test_link_many_users_offset_1
    test_02_03_link_users_again_3000 = _test_link_many_users_offset_1

    test_02_10_join_partially_linked_dc = _test_join
    test_02_11_unindexed_search_partially_linked_dc = _test_unindexed_search
    test_02_12_indexed_search_partially_linked_dc = _test_indexed_search

    def _test_link_many_users_3_groups(self, n=BATCH_SIZE, groups=3):
        s = self.state.next_linked_user_3
        e = s + n
        self.state.next_linked_user_3 = e
        for i in range(s, e):
            g = (i + 2) % groups
            if g not in (i % N_GROUPS, (i + 1) % N_GROUPS):
                self._link_user_and_group(i, g)

    test_03_01_link_users_again_1000_few_groups = _test_link_many_users_3_groups
    test_03_02_link_users_again_2000_few_groups = _test_link_many_users_3_groups
    test_03_03_link_users_again_3000_few_groups = _test_link_many_users_3_groups

    def _test_remove_links_0(self, n=BATCH_SIZE):
        s = self.state.next_removed_link_0
        e = s + n
        self.state.next_removed_link_0 = e
        for i in range(s, e):
            g = i % N_GROUPS
            self._unlink_user_and_group(i, g)

    test_04_01_remove_some_links_1000 = _test_remove_links_0
    test_04_02_remove_some_links_2000 = _test_remove_links_0
    test_04_03_remove_some_links_3000 = _test_remove_links_0

    # back to using _test_add_many_users
    test_05_01_adding_users_after_links_4000 = _test_add_many_users

    # reset the link count, to replace the original links
    def test_06_01_relink_users_1000(self):
        self.state.next_linked_user = 0
        self._test_link_many_users()

    test_06_02_link_users_2000 = _test_link_many_users
    test_06_03_link_users_3000 = _test_link_many_users
    test_06_04_link_users_4000 = _test_link_many_users
    test_06_05_link_users_again_4000 = _test_link_many_users_offset_1
    test_06_06_link_users_again_4000_few_groups = _test_link_many_users_3_groups

    test_07_01_adding_users_after_links_5000 = _test_add_many_users

    def _test_link_random_users_and_groups(self, n=BATCH_SIZE, groups=100):
        self._prepare_n_groups(groups)
        for i in range(n):
            u = random.randrange(self.state.next_user_id)
            g = random.randrange(groups)
            try:
                self._link_user_and_group(u, g)
            except LdbError:
                pass

    test_08_01_link_random_users_100_groups = _test_link_random_users_and_groups
    test_08_02_link_random_users_100_groups = _test_link_random_users_and_groups

    test_10_01_unindexed_search_full_dc = _test_unindexed_search
    test_10_02_indexed_search_full_dc = _test_indexed_search
    test_11_02_join_full_dc = _test_join

    def test_20_01_delete_50_groups(self):
        for i in range(self.state.n_groups - 50, self.state.n_groups):
            self.ldb.delete("cn=g%d,%s" % (i, self.ou_groups))
        self.state.n_groups -= 50

    def _test_delete_many_users(self, n=BATCH_SIZE):
        e = self.state.next_user_id
        s = max(0, e - n)
        self.state.next_user_id = s
        for i in range(s, e):
            self.ldb.delete("cn=u%d,%s" % (i, self.ou_users))

    test_21_01_delete_users_5000_lightly_linked = _test_delete_many_users
    test_21_02_delete_users_4000_lightly_linked = _test_delete_many_users
    test_21_03_delete_users_3000 = _test_delete_many_users

    def test_22_01_delete_all_groups(self):
        for i in range(self.state.n_groups):
            self.ldb.delete("cn=g%d,%s" % (i, self.ou_groups))
        self.state.n_groups = 0

    test_23_01_delete_users_after_groups_2000 = _test_delete_many_users
    test_23_00_delete_users_after_groups_1000 = _test_delete_many_users

    test_24_02_join_after_cleanup = _test_join


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


if ANCIENT_SAMBA:
    runner = SubunitTestRunner()
    if not runner.run(unittest.makeSuite(UserTests)).wasSuccessful():
        sys.exit(1)
    sys.exit(0)
else:
    TestProgram(module=__name__, opts=subunitopts)
