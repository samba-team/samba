#!/usr/bin/env python
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
import itertools

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


BATCH_SIZE = 2000
LINK_BATCH_SIZE = 1000
DELETE_BATCH_SIZE = 50
N_GROUPS = 29


class GlobalState(object):
    next_user_id = 0
    n_groups = 0
    next_linked_user = 0
    next_relinked_user = 0
    next_linked_user_3 = 0
    next_removed_link_0 = 0
    test_number = 0
    active_links = set()

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

        self.state.test_number += 1
        random.seed(self.state.test_number)

    def tearDown(self):
        super(UserTests, self).tearDown()

    def test_00_00_do_nothing(self):
        # this gives us an idea of the overhead
        pass

    def test_00_01_do_nothing_relevant(self):
        # takes around 1 second on i7-4770
        j = 0
        for i in range(30000000):
            j += i

    def test_00_02_do_nothing_sleepily(self):
        time.sleep(1)

    def test_00_03_add_ous_and_groups(self):
        # initialise the database
        for dn in (self.ou,
                   self.ou_users,
                   self.ou_groups,
                   self.ou_computers):
            self.ldb.add({
                "dn": dn,
                "objectclass": "organizationalUnit"
            })

        for i in range(N_GROUPS):
            self.ldb.add({
                "dn": "cn=g%d,%s" % (i, self.ou_groups),
                "objectclass": "group"
            })

        self.state.n_groups = N_GROUPS

    def _add_users(self, start, end):
        for i in range(start, end):
            self.ldb.add({
                "dn": "cn=u%d,%s" % (i, self.ou_users),
                "objectclass": "user"
            })

    def _add_users_ldif(self, start, end):
        lines = []
        for i in range(start, end):
            lines.append("dn: cn=u%d,%s" % (i, self.ou_users))
            lines.append("objectclass: user")
            lines.append("")
        self.ldb.add_ldif('\n'.join(lines))

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
            for i in range(25):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print('%d %s took %s' % (i, expression,
                                     time.time() - t),
                  file=sys.stderr)

    def _test_indexed_search(self):
        expressions = ['(objectclass=group)',
                       '(samaccountname=Administrator)'
        ]
        for expression in expressions:
            t = time.time()
            for i in range(4000):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print('%d runs %s took %s' % (i, expression,
                                          time.time() - t),
                  file=sys.stderr)

    def _test_base_search(self):
        for dn in [self.base_dn, self.ou, self.ou_users,
                   self.ou_groups, self.ou_computers]:
            for i in range(4000):
                try:
                    self.ldb.search(dn,
                                    scope=SCOPE_BASE,
                                    attrs=['cn'])
                except LdbError as e:
                    (num, msg) = e.args
                    if num != 32:
                        raise

    def _test_base_search_failing(self):
        pattern = 'missing%d' + self.ou
        for i in range(4000):
            self.ldb.search(pattern % i,
                            scope=SCOPE_BASE,
                            attrs=['cn'])

    def search_expression_list(self, expressions, rounds,
                               attrs=['cn'],
                               scope=SCOPE_SUBTREE):
        for expression in expressions:
            t = time.time()
            for i in range(rounds):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print('%d runs %s took %s' % (i, expression,
                                          time.time() - t),
                  file=sys.stderr)

    def _test_complex_search(self, n=100):
        classes = ['samaccountname', 'objectCategory', 'dn', 'member']
        values = ['*', '*t*', 'g*', 'user']
        comparators = ['=', '<=', '>='] # '~=' causes error
        maybe_not = ['!(', '']
        joiners = ['&', '|']

        # The number of permuations is 18432, which is not huge but
        # would take hours to search. So we take a sample.
        all_permutations = list(itertools.product(joiners,
                                                  classes, classes,
                                                  values, values,
                                                  comparators, comparators,
                                                  maybe_not, maybe_not))

        expressions = []

        for (j, c1, c2, v1, v2,
             o1, o2, n1, n2) in random.sample(all_permutations, n):
            expression = ''.join(['(', j,
                                  '(', n1, c1, o1, v1,
                                  '))' if n1 else ')',
                                  '(', n2, c2, o2, v2,
                                  '))' if n2 else ')',
                                  ')'])
            expressions.append(expression)

        self.search_expression_list(expressions, 1)

    def _test_member_search(self, rounds=10):
        expressions = []
        for d in range(20):
            expressions.append('(member=cn=u%d,%s)' % (d + 500, self.ou_users))
            expressions.append('(member=u%d*)' % (d + 700,))

        self.search_expression_list(expressions, rounds)

    def _test_memberof_search(self, rounds=200):
        expressions = []
        for i in range(min(self.state.n_groups, rounds)):
            expressions.append('(memberOf=cn=g%d,%s)' % (i, self.ou_groups))
            expressions.append('(memberOf=cn=g%d*)' % (i,))
            expressions.append('(memberOf=cn=*%s*)' % self.ou_groups)

        self.search_expression_list(expressions, 2)

    def _test_add_many_users(self, n=BATCH_SIZE):
        s = self.state.next_user_id
        e = s + n
        self._add_users(s, e)
        self.state.next_user_id = e

    def _test_add_many_users_ldif(self, n=BATCH_SIZE):
        s = self.state.next_user_id
        e = s + n
        self._add_users_ldif(s, e)
        self.state.next_user_id = e

    def _link_user_and_group(self, u, g):
        link = (u, g)
        if link in self.state.active_links:
            return False

        m = Message()
        m.dn = Dn(self.ldb, "CN=g%d,%s" % (g, self.ou_groups))
        m["member"] = MessageElement("cn=u%d,%s" % (u, self.ou_users),
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)
        self.state.active_links.add(link)
        return True

    def _unlink_user_and_group(self, u, g):
        link = (u, g)
        if link not in self.state.active_links:
            return False

        user = "cn=u%d,%s" % (u, self.ou_users)
        group = "CN=g%d,%s" % (g, self.ou_groups)
        m = Message()
        m.dn = Dn(self.ldb, group)
        m["member"] = MessageElement(user, FLAG_MOD_DELETE, "member")
        self.ldb.modify(m)
        self.state.active_links.remove(link)
        return True

    def _test_link_many_users(self, n=LINK_BATCH_SIZE):
        # this links unevenly, putting more users in the first group
        # and fewer in the last.
        ng = self.state.n_groups
        nu = self.state.next_user_id
        while n:
            u = random.randrange(nu)
            g = random.randrange(random.randrange(ng) + 1)
            if self._link_user_and_group(u, g):
                n -= 1

    def _test_link_many_users_batch(self, n=(LINK_BATCH_SIZE * 10)):
        # this links unevenly, putting more users in the first group
        # and fewer in the last.
        ng = self.state.n_groups
        nu = self.state.next_user_id
        messages = []
        for g in range(ng):
            m = Message()
            m.dn = Dn(self.ldb, "CN=g%d,%s" % (g, self.ou_groups))
            messages.append(m)

        while n:
            u = random.randrange(nu)
            g = random.randrange(random.randrange(ng) + 1)
            link = (u, g)
            if link in self.state.active_links:
                continue
            m = messages[g]
            m["member%s" % u] = MessageElement("cn=u%d,%s" %
                                               (u, self.ou_users),
                                               FLAG_MOD_ADD, "member")
            self.state.active_links.add(link)
            n -= 1

        for m in messages:
            try:
                self.ldb.modify(m)
            except LdbError as e:
                print(e)
                print(m)

    def _test_remove_some_links(self, n=(LINK_BATCH_SIZE // 2)):
        victims = random.sample(list(self.state.active_links), n)
        for x in victims:
            self._unlink_user_and_group(*x)

    test_00_11_join_empty_dc = _test_join

    test_00_12_adding_users_2000 = _test_add_many_users

    test_00_20_join_unlinked_2k_users = _test_join
    test_00_21_unindexed_search_2k_users = _test_unindexed_search
    test_00_22_indexed_search_2k_users = _test_indexed_search

    test_00_23_complex_search_2k_users = _test_complex_search
    test_00_24_member_search_2k_users = _test_member_search
    test_00_25_memberof_search_2k_users = _test_memberof_search

    test_00_27_base_search_2k_users = _test_base_search
    test_00_28_base_search_failing_2k_users = _test_base_search_failing

    test_01_01_link_2k_users = _test_link_many_users
    test_01_02_link_2k_users_batch = _test_link_many_users_batch

    test_02_10_join_2k_linked_dc = _test_join
    test_02_11_unindexed_search_2k_linked_dc = _test_unindexed_search
    test_02_12_indexed_search_2k_linked_dc = _test_indexed_search

    test_04_01_remove_some_links_2k = _test_remove_some_links

    test_05_01_adding_users_after_links_4k_ldif = _test_add_many_users_ldif

    test_06_04_link_users_4k = _test_link_many_users
    test_06_05_link_users_4k_batch = _test_link_many_users_batch

    test_07_01_adding_users_after_links_6k = _test_add_many_users

    def _test_ldif_well_linked_group(self, link_chance=1.0):
        g = self.state.n_groups
        self.state.n_groups += 1
        lines = ["dn: CN=g%d,%s" % (g, self.ou_groups),
                 "objectclass: group"]

        for i in xrange(self.state.next_user_id):
            if random.random() <= link_chance:
                lines.append("member: cn=u%d,%s" % (i, self.ou_users))
                self.state.active_links.add((i, g))

        lines.append("")
        self.ldb.add_ldif('\n'.join(lines))

    test_09_01_add_fully_linked_group = _test_ldif_well_linked_group

    def test_09_02_add_exponentially_diminishing_linked_groups(self):
        linkage = 0.8
        while linkage > 0.01:
            self._test_ldif_well_linked_group(linkage)
            linkage *= 0.75

    test_09_04_link_users_6k = _test_link_many_users

    test_10_01_unindexed_search_6k_users = _test_unindexed_search
    test_10_02_indexed_search_6k_users = _test_indexed_search

    test_10_27_base_search_6k_users = _test_base_search
    test_10_28_base_search_failing_6k_users = _test_base_search_failing

    def test_10_03_complex_search_6k_users(self):
        self._test_complex_search(n=50)

    def test_10_04_member_search_6k_users(self):
        self._test_member_search(rounds=1)

    def test_10_05_memberof_search_6k_users(self):
        self._test_memberof_search(rounds=5)

    test_11_02_join_full_dc = _test_join

    test_12_01_remove_some_links_6k = _test_remove_some_links

    def _test_delete_many_users(self, n=DELETE_BATCH_SIZE):
        e = self.state.next_user_id
        s = max(0, e - n)
        self.state.next_user_id = s
        for i in range(s, e):
            self.ldb.delete("cn=u%d,%s" % (i, self.ou_users))

        for x in tuple(self.state.active_links):
            if s >= x[0] > e:
                self.state.active_links.remove(x)

    test_20_01_delete_users_6k = _test_delete_many_users

    def test_21_01_delete_10_groups(self):
        for i in range(self.state.n_groups - 10, self.state.n_groups):
            self.ldb.delete("cn=g%d,%s" % (i, self.ou_groups))
        self.state.n_groups -= 10
        for x in tuple(self.state.active_links):
            if x[1] >= self.state.n_groups:
                self.state.active_links.remove(x)

    test_21_02_delete_users_5950 = _test_delete_many_users

    def test_22_01_delete_all_groups(self):
        for i in range(self.state.n_groups):
            self.ldb.delete("cn=g%d,%s" % (i, self.ou_groups))
        self.state.n_groups = 0
        self.state.active_links = set()

    # XXX assert the state is as we think, using searches

    def test_23_01_delete_users_5900_after_groups(self):
        # we do not delete everything because it takes too long
        n = 4 * DELETE_BATCH_SIZE
        self._test_delete_many_users(n=n)

    test_24_02_join_after_partial_cleanup = _test_join


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
