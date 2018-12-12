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

    def _add_users_ldif(self, start, end):
        lines = []
        for i in range(start, end):
            lines.append("dn: cn=u%d,%s" % (i, self.ou_users))
            lines.append("objectclass: user")
            lines.append("")
        self.ldb.add_ldif('\n'.join(lines))

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
            for i in range(50):
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
            for i in range(10000):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print('%d runs %s took %s' % (i, expression,
                                          time.time() - t),
                  file=sys.stderr)

    def _test_complex_search(self):
        classes = ['samaccountname', 'objectCategory', 'dn', 'member']
        values = ['*', '*t*', 'g*', 'user']
        comparators = ['=', '<=', '>=']  # '~=' causes error
        maybe_not = ['!(', '']
        joiners = ['&', '|']

        # The number of permuations is 18432, which is not huge but
        # would take hours to search. So we take a sample.
        all_permutations = list(itertools.product(joiners,
                                                  classes, classes,
                                                  values, values,
                                                  comparators, comparators,
                                                  maybe_not, maybe_not))
        random.seed(1)

        for (j, c1, c2, v1, v2,
             o1, o2, n1, n2) in random.sample(all_permutations, 100):
            expression = ''.join(['(', j,
                                  '(', n1, c1, o1, v1,
                                  '))' if n1 else ')',
                                  '(', n2, c2, o2, v2,
                                  '))' if n2 else ')',
                                  ')'])
            print(expression)
            self.ldb.search(self.ou,
                            expression=expression,
                            scope=SCOPE_SUBTREE,
                            attrs=['cn'])

    def _test_member_search(self, rounds=10):
        expressions = []
        for d in range(50):
            expressions.append('(member=cn=u%d,%s)' % (d + 500, self.ou_users))
            expressions.append('(member=u%d*)' % (d + 700,))
        for i in range(N_GROUPS):
            expressions.append('(memberOf=cn=g%d,%s)' % (i, self.ou_groups))
            expressions.append('(memberOf=cn=g%d*)' % (i,))
            expressions.append('(memberOf=cn=*%s*)' % self.ou_groups)

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
        m = Message()
        m.dn = Dn(self.ldb, "CN=g%d,%s" % (g, self.ou_groups))
        m["member"] = MessageElement("cn=u%d,%s" % (u, self.ou_users),
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

    def _test_link_many_users(self, n=BATCH_SIZE):
        self._prepare_n_groups(N_GROUPS)
        s = self.state.next_linked_user
        e = s + n
        for i in range(s, e):
            # put everyone in group 0, and one other group
            g = i % (N_GROUPS - 1) + 1
            self._link_user_and_group(i, g)
            self._link_user_and_group(i, 0)
        self.state.next_linked_user = e

    test_00_01_adding_users_1000 = _test_add_many_users

    test_00_10_complex_search_1k_users = _test_complex_search
    test_00_11_unindexed_search_1k_users = _test_unindexed_search
    test_00_12_indexed_search_1k_users = _test_indexed_search
    test_00_13_member_search_1k_users = _test_member_search

    test_01_02_adding_users_2000_ldif = _test_add_many_users_ldif
    test_01_03_adding_users_3000 = _test_add_many_users

    test_01_10_complex_search_3k_users = _test_complex_search
    test_01_11_unindexed_search_3k_users = _test_unindexed_search
    test_01_12_indexed_search_3k_users = _test_indexed_search

    def test_01_13_member_search_3k_users(self):
        self._test_member_search(rounds=5)

    test_02_01_link_users_1000 = _test_link_many_users
    test_02_02_link_users_2000 = _test_link_many_users
    test_02_03_link_users_3000 = _test_link_many_users

    test_03_10_complex_search_linked_users = _test_complex_search
    test_03_11_unindexed_search_linked_users = _test_unindexed_search
    test_03_12_indexed_search_linked_users = _test_indexed_search

    def test_03_13_member_search_linked_users(self):
        self._test_member_search(rounds=2)


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
