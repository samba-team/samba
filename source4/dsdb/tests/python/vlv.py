#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Originally based on ./sam.py
from __future__ import print_function
import optparse
import sys
import os
import base64
import random
import re

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
import ldb
from samba.samdb import SamDB
from samba.compat import get_bytes
from samba.compat import get_string

import time

parser = optparse.OptionParser("vlv.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

parser.add_option('--elements', type='int', default=20,
                  help="use this many elements in the tests")

parser.add_option('--delete-in-setup', action='store_true',
                  help="cleanup in next setup rather than teardown")

parser.add_option('--skip-attr-regex',
                  help="ignore attributes matching this regex")

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

N_ELEMENTS = opts.elements


class VlvTestException(Exception):
    pass


def encode_vlv_control(critical=1,
                       before=0, after=0,
                       offset=None,
                       gte=None,
                       n=0, cookie=None):

    s = "vlv:%d:%d:%d:" % (critical, before, after)

    if offset is not None:
        m = "%d:%d" % (offset, n)
    elif b':' in gte or b'\x00' in gte:
        gte = get_string(base64.b64encode(gte))
        m = "base64>=%s" % gte
    else:
        m = ">=%s" % get_string(gte)

    if cookie is None:
        return s + m

    return s + m + ':' + cookie


def get_cookie(controls, expected_n=None):
    """Get the cookie, STILL base64 encoded, or raise ValueError."""
    for c in list(controls):
        cstr = str(c)
        if cstr.startswith('vlv_resp'):
            head, n, _, cookie = cstr.rsplit(':', 3)
            if expected_n is not None and int(n) != expected_n:
                raise ValueError("Expected %s items, server said %s" %
                                 (expected_n, n))
            return cookie
    raise ValueError("there is no VLV response")


class TestsWithUserOU(samba.tests.TestCase):

    def create_user(self, i, n, prefix='vlvtest', suffix='', attrs=None):
        name = "%s%d%s" % (prefix, i, suffix)
        user = {
            'cn': name,
            "objectclass": "user",
            'givenName': "abcdefghijklmnopqrstuvwxyz"[i % 26],
            "roomNumber": "%sbc" % (n - i),
            "carLicense": "后来经",
            "facsimileTelephoneNumber": name,
            "employeeNumber": "%s%sx" % (abs(i * (99 - i)), '\n' * (i & 255)),
            "accountExpires": "%s" % (10 ** 9 + 1000000 * i),
            "msTSExpireDate4": "19%02d0101010000.0Z" % (i % 100),
            "flags": str(i * (n - i)),
            "serialNumber": "abc %s%s%s" % ('AaBb |-/'[i & 7],
                                            ' 3z}'[i & 3],
                                            '"@'[i & 1],),
        }

        # _user_broken_attrs tests are broken due to problems outside
        # of VLV.
        _user_broken_attrs = {
            # Sort doesn't look past a NUL byte.
            "photo": "\x00%d" % (n - i),
            "audio": "%sn octet string %s%s ♫♬\x00lalala" % ('Aa'[i & 1],
                                                             chr(i & 255), i),
            "displayNamePrintable": "%d\x00%c" % (i, i & 255),
            "adminDisplayName": "%d\x00b" % (n - i),
            "title": "%d%sb" % (n - i, '\x00' * i),
            "comment": "Favourite colour is %d" % (n % (i + 1)),

            # Names that vary only in case. Windows returns
            # equivalent addresses in the order they were put
            # in ('a st', 'A st',...).
            "street": "%s st" % (chr(65 | (i & 14) | ((i & 1) * 32))),
        }

        if attrs is not None:
            user.update(attrs)

        user['dn'] = "cn=%s,%s" % (user['cn'], self.ou)

        if opts.skip_attr_regex:
            match = re.compile(opts.skip_attr_regex).search
            for k in user.keys():
                if match(k):
                    del user[k]

        self.users.append(user)
        self.ldb.add(user)
        return user

    def setUp(self):
        super(TestsWithUserOU, self).setUp()
        self.ldb = SamDB(host, credentials=creds,
                         session_info=system_session(lp), lp=lp)
        self.ldb_ro = self.ldb
        self.base_dn = self.ldb.domain_dn()
        self.tree_dn = "ou=vlvtesttree,%s" % self.base_dn
        self.ou = "ou=vlvou,%s" % self.tree_dn
        if opts.delete_in_setup:
            try:
                self.ldb.delete(self.tree_dn, ['tree_delete:1'])
            except ldb.LdbError as e:
                print("tried deleting %s, got error %s" % (self.tree_dn, e))
        self.ldb.add({
            "dn": self.tree_dn,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})

        self.users = []
        for i in range(N_ELEMENTS):
            self.create_user(i, N_ELEMENTS)

        attrs = self.users[0].keys()
        self.binary_sorted_keys = ['audio',
                                   'photo',
                                   "msTSExpireDate4",
                                   'serialNumber',
                                   "displayNamePrintable"]

        self.numeric_sorted_keys = ['flags',
                                    'accountExpires']

        self.timestamp_keys = ['msTSExpireDate4']

        self.int64_keys = set(['accountExpires'])

        self.locale_sorted_keys = [x for x in attrs if
                                   x not in (self.binary_sorted_keys +
                                             self.numeric_sorted_keys)]

        # don't try spaces, etc in cn
        self.delicate_keys = ['cn']

    def tearDown(self):
        super(TestsWithUserOU, self).tearDown()
        if not opts.delete_in_setup:
            self.ldb.delete(self.tree_dn, ['tree_delete:1'])


class VLVTestsBase(TestsWithUserOU):

    # Run a vlv search and return important fields of the response control
    def vlv_search(self, attr, expr, cookie="", after_count=0, offset=1):
        sort_ctrl = "server_sort:1:0:%s" % attr
        ctrl = "vlv:1:0:%d:%d:0" % (after_count, offset)
        if cookie:
            ctrl += ":" + cookie

        res = self.ldb_ro.search(self.ou,
                              expression=expr,
                              scope=ldb.SCOPE_ONELEVEL,
                              attrs=[attr],
                              controls=[ctrl, sort_ctrl])
        results = [str(x[attr][0]) for x in res]

        ctrls = [str(c) for c in res.controls if
                 str(c).startswith('vlv')]
        self.assertEqual(len(ctrls), 1)

        spl = ctrls[0].rsplit(':')
        cookie = ""
        if len(spl) == 6:
            cookie = spl[-1]

        return results, cookie


class VLVTestsRO(VLVTestsBase):
    def test_vlv_simple_double_run(self):
        """Do the simplest possible VLV query to confirm if VLV
           works at all.  Useful for showing VLV as a whole works
           on Global Catalog (for example)"""
        attr = 'roomNumber'
        expr = "(objectclass=user)"

        # Start new search
        full_results, cookie = self.vlv_search(attr, expr,
                                               after_count=len(self.users))

        results, cookie = self.vlv_search(attr, expr, cookie=cookie,
                                          after_count=len(self.users))
        expected_results = full_results
        self.assertEqual(results, expected_results)


class VLVTestsGC(VLVTestsRO):
    def setUp(self):
        super(VLVTestsRO, self).setUp()
        self.ldb_ro = SamDB(host + ":3268", credentials=creds,
                            session_info=system_session(lp), lp=lp)


class VLVTests(VLVTestsBase):
    def get_full_list(self, attr, include_cn=False):
        """Fetch the whole list sorted on the attribute, using the VLV.
        This way you get a VLV cookie."""
        n_users = len(self.users)
        sort_control = "server_sort:1:0:%s" % attr
        half_n = n_users // 2
        vlv_search = "vlv:1:%d:%d:%d:0" % (half_n, half_n, half_n + 1)
        attrs = [attr]
        if include_cn:
            attrs.append('cn')
        res = self.ldb.search(self.ou,
                              scope=ldb.SCOPE_ONELEVEL,
                              attrs=attrs,
                              controls=[sort_control,
                                        vlv_search])
        if include_cn:
            full_results = [(str(x[attr][0]), str(x['cn'][0])) for x in res]
        else:
            full_results = [str(x[attr][0]).lower() for x in res]
        controls = res.controls
        return full_results, controls, sort_control

    def get_expected_order(self, attr, expression=None):
        """Fetch the whole list sorted on the attribute, using sort only."""
        sort_control = "server_sort:1:0:%s" % attr
        res = self.ldb.search(self.ou,
                              scope=ldb.SCOPE_ONELEVEL,
                              expression=expression,
                              attrs=[attr],
                              controls=[sort_control])
        results = [x[attr][0] for x in res]
        return results

    def delete_user(self, user):
        self.ldb.delete(user['dn'])
        del self.users[self.users.index(user)]

    def get_gte_tests_and_order(self, attr, expression=None):
        expected_order = self.get_expected_order(attr, expression=expression)
        gte_users = []
        if attr in self.delicate_keys:
            gte_keys = [
                '3',
                'abc',
                '¹',
                'ŋđ¼³ŧ“«đð',
                '桑巴',
            ]
        elif attr in self.timestamp_keys:
            gte_keys = [
                '18560101010000.0Z',
                '19140103010000.0Z',
                '19560101010010.0Z',
                '19700101000000.0Z',
                '19991231211234.3Z',
                '20061111211234.0Z',
                '20390901041234.0Z',
                '25560101010000.0Z',
            ]
        elif attr not in self.numeric_sorted_keys:
            gte_keys = [
                '3',
                'abc',
                ' ',
                '!@#!@#!',
                'kōkako',
                '¹',
                'ŋđ¼³ŧ“«đð',
                '\n\t\t',
                '桑巴',
                'zzzz',
            ]
            if expected_order:
                gte_keys.append(expected_order[len(expected_order) // 2] + b' tail')

        else:
            # "numeric" means positive integers
            # doesn't work with -1, 3.14, ' 3', '9' * 20
            gte_keys = ['3',
                        '1' * 10,
                        '1',
                        '9' * 7,
                        '0']

            if attr in self.int64_keys:
                gte_keys += ['3' * 12, '71' * 8]

        for i, x in enumerate(gte_keys):
            user = self.create_user(i, N_ELEMENTS,
                                    prefix='gte',
                                    attrs={attr: x})
            gte_users.append(user)

        gte_order = self.get_expected_order(attr)
        for user in gte_users:
            self.delete_user(user)

        # for sanity's sake
        expected_order_2 = self.get_expected_order(attr, expression=expression)
        self.assertEqual(expected_order, expected_order_2)

        # Map gte tests to indexes in expected order. This will break
        # if gte_order and expected_order are differently ordered (as
        # it should).
        gte_map = {}

        # index to the first one with each value
        index_map = {}
        for i, k in enumerate(expected_order):
            if k not in index_map:
                index_map[k] = i

        keys = []
        for k in gte_order:
            if k in index_map:
                i = index_map[k]
                gte_map[k] = i
                for k in keys:
                    gte_map[k] = i
                keys = []
            else:
                keys.append(k)

        for k in keys:
            gte_map[k] = len(expected_order)

        if False:
            print("gte_map:")
            for k in gte_order:
                print("   %10s => %10s" % (k, gte_map[k]))

        return gte_order, expected_order, gte_map

    def assertCorrectResults(self, results, expected_order,
                             offset, before, after):
        """A helper to calculate offsets correctly and say as much as possible
        when something goes wrong."""

        start = max(offset - before - 1, 0)
        end = offset + after
        expected_results = expected_order[start: end]

        # if it is a tuple with the cn, drop the cn
        if expected_results and isinstance(expected_results[0], tuple):
            expected_results = [x[0] for x in expected_results]

        if expected_results == results:
            return

        if expected_order is not None:
            print("expected order: %s" % expected_order[:20])
            if len(expected_order) > 20:
                print("... and %d more not shown" % (len(expected_order) - 20))

        print("offset %d before %d after %d" % (offset, before, after))
        print("start %d end %d" % (start, end))
        print("expected: %s" % expected_results)
        print("got     : %s" % results)
        self.assertEqual(expected_results, results)

    def test_server_vlv_with_cookie(self):
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]
        for attr in attrs:
            expected_order = self.get_expected_order(attr)
            sort_control = "server_sort:1:0:%s" % attr
            res = None
            n = len(self.users)
            for before in [10, 0, 3, 1, 4, 5, 2]:
                for after in [0, 3, 1, 4, 5, 2, 7]:
                    for offset in range(max(1, before - 2),
                                        min(n - after + 2, n)):
                        if res is None:
                            vlv_search = "vlv:1:%d:%d:%d:0" % (before, after,
                                                               offset)
                        else:
                            cookie = get_cookie(res.controls, n)
                            vlv_search = ("vlv:1:%d:%d:%d:%s:%s" %
                                          (before, after, offset, n,
                                           cookie))

                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        vlv_search])

                        results = [x[attr][0] for x in res]

                        self.assertCorrectResults(results, expected_order,
                                                  offset, before, after)

    def run_index_tests_with_expressions(self, expressions):
        # Here we don't test every before/after combination.
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]
        for attr in attrs:
            for expression in expressions:
                expected_order = self.get_expected_order(attr, expression)
                sort_control = "server_sort:1:0:%s" % attr
                res = None
                n = len(expected_order)
                for before in range(0, 11):
                    after = before
                    for offset in range(max(1, before - 2),
                                        min(n - after + 2, n)):
                        if res is None:
                            vlv_search = "vlv:1:%d:%d:%d:0" % (before, after,
                                                               offset)
                        else:
                            cookie = get_cookie(res.controls)
                            vlv_search = ("vlv:1:%d:%d:%d:%s:%s" %
                                          (before, after, offset, n,
                                           cookie))

                        res = self.ldb.search(self.ou,
                                              expression=expression,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        vlv_search])

                        results = [x[attr][0] for x in res]

                        self.assertCorrectResults(results, expected_order,
                                                  offset, before, after)

    def test_server_vlv_with_expression(self):
        """What happens when we run the VLV with an expression?"""
        expressions = ["(objectClass=*)",
                       "(cn=%s)" % self.users[-1]['cn'],
                       "(roomNumber=%s)" % self.users[0]['roomNumber'],
                       ]
        self.run_index_tests_with_expressions(expressions)

    def test_server_vlv_with_failing_expression(self):
        """What happens when we run the VLV on an expression that matches
        nothing?"""
        expressions = ["(samaccountname=testferf)",
                       "(cn=hefalump)",
                       ]
        self.run_index_tests_with_expressions(expressions)

    def run_gte_tests_with_expressions(self, expressions):
        # Here we don't test every before/after combination.
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]
        for expression in expressions:
            for attr in attrs:
                gte_order, expected_order, gte_map = \
                    self.get_gte_tests_and_order(attr, expression)
                # In case there is some order dependency, disorder tests
                gte_tests = gte_order[:]
                random.seed(2)
                random.shuffle(gte_tests)
                res = None
                sort_control = "server_sort:1:0:%s" % attr

                expected_order = self.get_expected_order(attr, expression)
                sort_control = "server_sort:1:0:%s" % attr
                res = None
                for before in range(0, 11):
                    after = before
                    for gte in gte_tests:
                        if res is not None:
                            cookie = get_cookie(res.controls)
                        else:
                            cookie = None
                        vlv_search = encode_vlv_control(before=before,
                                                        after=after,
                                                        gte=get_bytes(gte),
                                                        cookie=cookie)

                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              expression=expression,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        vlv_search])

                        results = [x[attr][0] for x in res]
                        offset = gte_map.get(gte, len(expected_order))

                        # here offset is 0-based
                        start = max(offset - before, 0)
                        end = offset + 1 + after

                        expected_results = expected_order[start: end]

                        self.assertEqual(expected_results, results)

    def test_vlv_gte_with_expression(self):
        """What happens when we run the VLV with an expression?"""
        expressions = ["(objectClass=*)",
                       "(cn=%s)" % self.users[-1]['cn'],
                       "(roomNumber=%s)" % self.users[0]['roomNumber'],
                       ]
        self.run_gte_tests_with_expressions(expressions)

    def test_vlv_gte_with_failing_expression(self):
        """What happens when we run the VLV on an expression that matches
        nothing?"""
        expressions = ["(samaccountname=testferf)",
                       "(cn=hefalump)",
                       ]
        self.run_gte_tests_with_expressions(expressions)

    def test_server_vlv_with_cookie_while_adding_and_deleting(self):
        """What happens if we add or remove items in the middle of the VLV?

        Nothing. The search and the sort is not repeated, and we only
        deal with the objects originally found.
        """
        attrs = ['cn'] + [x for x in self.users[0].keys() if x not in
                          ('dn', 'objectclass')]
        user_number = 0
        iteration = 0
        for attr in attrs:
            full_results, controls, sort_control = \
                            self.get_full_list(attr, True)
            original_n = len(self.users)

            expected_order = full_results
            random.seed(1)

            for before in list(range(0, 3)) + [6, 11, 19]:
                for after in list(range(0, 3)) + [6, 11, 19]:
                    start = max(before - 1, 1)
                    end = max(start + 4, original_n - after + 2)
                    for offset in range(start, end):
                        # if iteration > 2076:
                        #    return
                        cookie = get_cookie(controls, original_n)
                        vlv_search = encode_vlv_control(before=before,
                                                        after=after,
                                                        offset=offset,
                                                        n=original_n,
                                                        cookie=cookie)

                        iteration += 1
                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        vlv_search])

                        controls = res.controls
                        results = [x[attr][0] for x in res]
                        real_offset = max(1, min(offset, len(expected_order)))

                        expected_results = []
                        skipped = 0
                        begin_offset = max(real_offset - before - 1, 0)
                        real_before = min(before, real_offset - 1)
                        real_after = min(after,
                                         len(expected_order) - real_offset)

                        for x in expected_order[begin_offset:]:
                            if x is not None:
                                expected_results.append(get_bytes(x[0]))
                                if (len(expected_results) ==
                                    real_before + real_after + 1):
                                    break
                            else:
                                skipped += 1

                        if expected_results != results:
                            print("attr %s before %d after %d offset %d" %
                                  (attr, before, after, offset))
                        self.assertEqual(expected_results, results)

                        n = len(self.users)
                        if random.random() < 0.1 + (n < 5) * 0.05:
                            if n == 0:
                                i = 0
                            else:
                                i = random.randrange(n)
                            user = self.create_user(i, n, suffix='-%s' %
                                                    user_number)
                            user_number += 1
                        if random.random() < 0.1  + (n > 50) * 0.02 and n:
                            index = random.randrange(n)
                            user = self.users.pop(index)

                            self.ldb.delete(user['dn'])

                            replaced = (user[attr], user['cn'])
                            if replaced in expected_order:
                                i = expected_order.index(replaced)
                                expected_order[i] = None

    def test_server_vlv_with_cookie_while_changing(self):
        """What happens if we modify items in the middle of the VLV?

        The expected behaviour (as found on Windows) is the sort is
        not repeated, but the changes in attributes are reflected.
        """
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass', 'cn')]
        for attr in attrs:
            n_users = len(self.users)
            expected_order = [x.upper() for x in self.get_expected_order(attr)]
            sort_control = "server_sort:1:0:%s" % attr
            res = None
            i = 0

            # First we'll fetch the whole list so we know the original
            # sort order. This is necessary because we don't know how
            # the server will order equivalent items. We are using the
            # dn as a key.
            half_n = n_users // 2
            vlv_search = "vlv:1:%d:%d:%d:0" % (half_n, half_n, half_n + 1)
            res = self.ldb.search(self.ou,
                                  scope=ldb.SCOPE_ONELEVEL,
                                  attrs=['dn', attr],
                                  controls=[sort_control, vlv_search])

            results = [x[attr][0].upper() for x in res]
            #self.assertEqual(expected_order, results)

            dn_order = [str(x['dn']) for x in res]
            values = results[:]

            for before in range(0, 3):
                for after in range(0, 3):
                    for offset in range(1 + before, n_users - after):
                        cookie = get_cookie(res.controls, len(self.users))
                        vlv_search = ("vlv:1:%d:%d:%d:%s:%s" %
                                      (before, after, offset, len(self.users),
                                       cookie))

                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=['dn', attr],
                                              controls=[sort_control,
                                                        vlv_search])

                        dn_results = [str(x['dn']) for x in res]
                        dn_expected = dn_order[offset - before - 1:
                                               offset + after]

                        self.assertEqual(dn_expected, dn_results)

                        results = [x[attr][0].upper() for x in res]

                        self.assertCorrectResults(results, values,
                                                  offset, before, after)

                        i += 1
                        if i % 3 == 2:
                            if (attr in self.locale_sorted_keys or
                                attr in self.binary_sorted_keys):
                                i1 = i % n_users
                                i2 = (i ^ 255) % n_users
                                dn1 = dn_order[i1]
                                dn2 = dn_order[i2]
                                v2 = values[i2]

                                if v2 in self.locale_sorted_keys:
                                    v2 += '-%d' % i
                                cn1 = dn1.split(',', 1)[0][3:]
                                cn2 = dn2.split(',', 1)[0][3:]

                                values[i1] = v2

                                m = ldb.Message()
                                m.dn = ldb.Dn(self.ldb, dn1)
                                m[attr] = ldb.MessageElement(v2,
                                                             ldb.FLAG_MOD_REPLACE,
                                                             attr)

                                self.ldb.modify(m)

    def test_server_vlv_fractions_with_cookie(self):
        """What happens when the count is set to an arbitrary number?

        In that case the offset and the count form a fraction, and the
        VLV should be centred at a point offset/count of the way
        through. For example, if offset is 3 and count is 6, the VLV
        should be looking around halfway. The actual algorithm is a
        bit fiddlier than that, because of the one-basedness of VLV.
        """
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]

        n_users = len(self.users)

        random.seed(4)

        for attr in attrs:
            full_results, controls, sort_control = self.get_full_list(attr)
            self.assertEqual(len(full_results), n_users)
            for before in range(0, 2):
                for after in range(0, 2):
                    for denominator in range(1, 20):
                        for offset in range(1, denominator + 3):
                            cookie = get_cookie(controls, len(self.users))
                            vlv_search = ("vlv:1:%d:%d:%d:%s:%s" %
                                          (before, after, offset,
                                           denominator,
                                           cookie))
                            try:
                                res = self.ldb.search(self.ou,
                                                      scope=ldb.SCOPE_ONELEVEL,
                                                      attrs=[attr],
                                                      controls=[sort_control,
                                                                vlv_search])
                            except ldb.LdbError as e:
                                if offset != 0:
                                    raise
                                print("offset %d denominator %d raised error "
                                      "expected error %s\n"
                                      "(offset zero is illegal unless "
                                      "content count is zero)" %
                                      (offset, denominator, e))
                                continue

                            results = [str(x[attr][0]).lower() for x in res]

                            if denominator == 0:
                                denominator = n_users
                                if offset == 0:
                                    offset = denominator
                            elif denominator == 1:
                                # the offset can only be 1, but the 1/1 case
                                # means something special
                                if offset == 1:
                                    real_offset = n_users
                                else:
                                    real_offset = 1
                            else:
                                if offset > denominator:
                                    offset = denominator
                                real_offset = (1 +
                                               int(round((n_users - 1) *
                                                         (offset - 1) /
                                                         (denominator - 1.0)))
                                               )

                            self.assertCorrectResults(results, full_results,
                                                      real_offset, before,
                                                      after)

                            controls = res.controls
                            if False:
                                for c in list(controls):
                                    cstr = str(c)
                                    if cstr.startswith('vlv_resp'):
                                        bits = cstr.rsplit(':')
                                        print("the answer is %s; we said %d" %
                                              (bits[2], real_offset))
                                        break

    def test_server_vlv_no_cookie(self):
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]

        for attr in attrs:
            expected_order = self.get_expected_order(attr)
            sort_control = "server_sort:1:0:%s" % attr
            for before in range(0, 5):
                for after in range(0, 7):
                    for offset in range(1 + before, len(self.users) - after):
                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        "vlv:1:%d:%d:%d:0" %
                                                        (before, after,
                                                         offset)])
                        results = [x[attr][0] for x in res]
                        self.assertCorrectResults(results, expected_order,
                                                  offset, before, after)

    def get_expected_order_showing_deleted(self, attr,
                                           expression="(|(cn=vlvtest*)(cn=vlv-deleted*))",
                                           base=None,
                                           scope=ldb.SCOPE_SUBTREE
                                           ):
        """Fetch the whole list sorted on the attribute, using sort only,
        searching in the entire tree, not just our OU. This is the
        way to find deleted objects.
        """
        if base is None:
            base = self.base_dn
        sort_control = "server_sort:1:0:%s" % attr
        controls = [sort_control, "show_deleted:1"]

        res = self.ldb.search(base,
                              scope=scope,
                              expression=expression,
                              attrs=[attr],
                              controls=controls)
        results = [x[attr][0] for x in res]
        return results

    def add_deleted_users(self, n):
        deleted_users = [self.create_user(i, n, prefix='vlv-deleted')
                         for i in range(n)]

        for user in deleted_users:
            self.delete_user(user)

    def test_server_vlv_no_cookie_show_deleted(self):
        """What do we see with the show_deleted control?"""
        attrs = ['objectGUID',
                 'cn',
                 'sAMAccountName',
                 'objectSid',
                 'name',
                 'whenChanged',
                 'usnChanged'
                 ]

        # add some deleted users first, just in case there are none
        self.add_deleted_users(6)
        random.seed(22)
        expression = "(|(cn=vlvtest*)(cn=vlv-deleted*))"

        for attr in attrs:
            show_deleted_control = "show_deleted:1"
            expected_order = self.get_expected_order_showing_deleted(attr,
                                                                     expression)
            n = len(expected_order)
            sort_control = "server_sort:1:0:%s" % attr
            for before in [3, 1, 0]:
                for after in [0, 2]:
                    # don't test every position, because there could be hundreds.
                    # jump back and forth instead
                    for i in range(20):
                        offset = random.randrange(max(1, before - 2),
                                                  min(n - after + 2, n))
                        res = self.ldb.search(self.base_dn,
                                              expression=expression,
                                              scope=ldb.SCOPE_SUBTREE,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        show_deleted_control,
                                                        "vlv:1:%d:%d:%d:0" %
                                                        (before, after,
                                                         offset)
                                                        ]
                                              )
                        results = [x[attr][0] for x in res]
                        self.assertCorrectResults(results, expected_order,
                                                  offset, before, after)

    def test_server_vlv_no_cookie_show_deleted_only(self):
        """What do we see with the show_deleted control when we're not looking
        at any non-deleted things"""
        attrs = ['objectGUID',
                 'cn',
                 'sAMAccountName',
                 'objectSid',
                 'whenChanged',
                 ]

        # add some deleted users first, just in case there are none
        self.add_deleted_users(4)
        base = 'CN=Deleted Objects,%s' % self.base_dn
        expression = "(cn=vlv-deleted*)"
        for attr in attrs:
            show_deleted_control = "show_deleted:1"
            expected_order = self.get_expected_order_showing_deleted(attr,
                                                                     expression=expression,
                                                                     base=base,
                                                                     scope=ldb.SCOPE_ONELEVEL)
            print("searching for attr %s amongst %d deleted objects" %
                  (attr, len(expected_order)))
            sort_control = "server_sort:1:0:%s" % attr
            step = max(len(expected_order) // 10, 1)
            for before in [3, 0]:
                for after in [0, 2]:
                    for offset in range(1 + before,
                                        len(expected_order) - after,
                                        step):
                        res = self.ldb.search(base,
                                              expression=expression,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        show_deleted_control,
                                                        "vlv:1:%d:%d:%d:0" %
                                                        (before, after,
                                                         offset)])
                        results = [x[attr][0] for x in res]
                        self.assertCorrectResults(results, expected_order,
                                                  offset, before, after)

    def test_server_vlv_with_cookie_show_deleted(self):
        """What do we see with the show_deleted control?"""
        attrs = ['objectGUID',
                 'cn',
                 'sAMAccountName',
                 'objectSid',
                 'name',
                 'whenChanged',
                 'usnChanged'
                 ]
        self.add_deleted_users(6)
        random.seed(23)
        for attr in attrs:
            expected_order = self.get_expected_order(attr)
            sort_control = "server_sort:1:0:%s" % attr
            res = None
            show_deleted_control = "show_deleted:1"
            expected_order = self.get_expected_order_showing_deleted(attr)
            n = len(expected_order)
            expression = "(|(cn=vlvtest*)(cn=vlv-deleted*))"
            for before in [3, 2, 1, 0]:
                after = before
                for i in range(20):
                    offset = random.randrange(max(1, before - 2),
                                              min(n - after + 2, n))
                    if res is None:
                        vlv_search = "vlv:1:%d:%d:%d:0" % (before, after,
                                                           offset)
                    else:
                        cookie = get_cookie(res.controls, n)
                        vlv_search = ("vlv:1:%d:%d:%d:%s:%s" %
                                      (before, after, offset, n,
                                       cookie))

                    res = self.ldb.search(self.base_dn,
                                          expression=expression,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=[attr],
                                          controls=[sort_control,
                                                    vlv_search,
                                                    show_deleted_control])

                    results = [x[attr][0] for x in res]

                    self.assertCorrectResults(results, expected_order,
                                              offset, before, after)

    def test_server_vlv_gte_with_cookie(self):
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]
        for attr in attrs:
            gte_order, expected_order, gte_map = \
                                        self.get_gte_tests_and_order(attr)
            # In case there is some order dependency, disorder tests
            gte_tests = gte_order[:]
            random.seed(1)
            random.shuffle(gte_tests)
            res = None
            sort_control = "server_sort:1:0:%s" % attr
            for before in [0, 1, 2, 4]:
                for after in [0, 1, 3, 6]:
                    for gte in gte_tests:
                        if res is not None:
                            cookie = get_cookie(res.controls, len(self.users))
                        else:
                            cookie = None
                        vlv_search = encode_vlv_control(before=before,
                                                        after=after,
                                                        gte=get_bytes(gte),
                                                        cookie=cookie)

                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        vlv_search])

                        results = [x[attr][0] for x in res]
                        offset = gte_map.get(gte, len(expected_order))

                        # here offset is 0-based
                        start = max(offset - before, 0)
                        end = offset + 1 + after

                        expected_results = expected_order[start: end]

                        self.assertEqual(expected_results, results)

    def test_server_vlv_gte_no_cookie(self):
        attrs = [x for x in self.users[0].keys() if x not in
                 ('dn', 'objectclass')]
        iteration = 0
        for attr in attrs:
            gte_order, expected_order, gte_map = \
                                        self.get_gte_tests_and_order(attr)
            # In case there is some order dependency, disorder tests
            gte_tests = gte_order[:]
            random.seed(1)
            random.shuffle(gte_tests)

            sort_control = "server_sort:1:0:%s" % attr
            for before in [0, 1, 3]:
                for after in [0, 4]:
                    for gte in gte_tests:
                        vlv_search = encode_vlv_control(before=before,
                                                        after=after,
                                                        gte=get_bytes(gte))

                        res = self.ldb.search(self.ou,
                                              scope=ldb.SCOPE_ONELEVEL,
                                              attrs=[attr],
                                              controls=[sort_control,
                                                        vlv_search])
                        results = [x[attr][0] for x in res]

                        # here offset is 0-based
                        offset = gte_map.get(gte, len(expected_order))
                        start = max(offset - before, 0)
                        end = offset + after + 1
                        expected_results = expected_order[start: end]
                        iteration += 1
                        if expected_results != results:
                            middle = expected_order[len(expected_order) // 2]
                            print(expected_results, results)
                            print(middle)
                            print(expected_order)
                            print()
                            print("\nattr %s offset %d before %d "
                                  "after %d gte %s" %
                                  (attr, offset, before, after, gte))
                        self.assertEqual(expected_results, results)

    def test_multiple_searches(self):
        """The maximum number of concurrent vlv searches per connection is
        currently set at 3. That means if you open 4 VLV searches the
        cookie on the first one should fail.
        """
        # Windows has a limit of 10 VLVs where there are low numbers
        # of objects in each search.
        attrs = ([x for x in self.users[0].keys() if x not in
                  ('dn', 'objectclass')] * 2)[:12]

        vlv_cookies = []
        for attr in attrs:
            sort_control = "server_sort:1:0:%s" % attr

            res = self.ldb.search(self.ou,
                                  scope=ldb.SCOPE_ONELEVEL,
                                  attrs=[attr],
                                  controls=[sort_control,
                                            "vlv:1:1:1:1:0"])

            cookie = get_cookie(res.controls, len(self.users))
            vlv_cookies.append(cookie)
            time.sleep(0.2)

        # now this one should fail
        self.assertRaises(ldb.LdbError,
                          self.ldb.search,
                          self.ou,
                          scope=ldb.SCOPE_ONELEVEL,
                          attrs=[attr],
                          controls=[sort_control,
                                    "vlv:1:1:1:1:0:%s" % vlv_cookies[0]])

        # and this one should succeed
        res = self.ldb.search(self.ou,
                              scope=ldb.SCOPE_ONELEVEL,
                              attrs=[attr],
                              controls=[sort_control,
                                        "vlv:1:1:1:1:0:%s" % vlv_cookies[-1]])

        # this one should fail because it is a new connection and
        # doesn't share cookies
        new_ldb = SamDB(host, credentials=creds,
                        session_info=system_session(lp), lp=lp)

        self.assertRaises(ldb.LdbError,
                          new_ldb.search, self.ou,
                          scope=ldb.SCOPE_ONELEVEL,
                          attrs=[attr],
                          controls=[sort_control,
                                    "vlv:1:1:1:1:0:%s" % vlv_cookies[-1]])

        # but now without the critical flag it just does no VLV.
        new_ldb.search(self.ou,
                       scope=ldb.SCOPE_ONELEVEL,
                       attrs=[attr],
                       controls=[sort_control,
                                 "vlv:0:1:1:1:0:%s" % vlv_cookies[-1]])

    def test_vlv_modify_during_view(self):
        attr = 'roomNumber'
        expr = "(objectclass=user)"

        # Start new search
        full_results, cookie = self.vlv_search(attr, expr,
                                               after_count=len(self.users))

        # Edit a user
        edit_index = len(self.users)//2
        edit_attr = full_results[edit_index]
        users_with_attr = [u for u in self.users if u[attr] == edit_attr]
        self.assertEqual(len(users_with_attr), 1)
        edit_user = users_with_attr[0]

        # Put z at the front of the val so it comes last in ordering
        edit_val = "z_" + edit_user[attr]

        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, edit_user['dn'])
        m[attr] = ldb.MessageElement(edit_val, ldb.FLAG_MOD_REPLACE, attr)
        self.ldb.modify(m)

        results, cookie = self.vlv_search(attr, expr, cookie=cookie,
                                          after_count=len(self.users))

        # Make expected_results by copying and editing full_results
        expected_results = full_results[:]
        expected_results[edit_index] = edit_val
        self.assertEqual(results, expected_results)

    # Test changing the search expression in a request on an initialised view
    # Expected failure on samba, passes on windows
    def test_vlv_change_search_expr(self):
        attr = 'roomNumber'
        expr = "(objectclass=user)"

        # Start new search
        full_results, cookie = self.vlv_search(attr, expr,
                                               after_count=len(self.users))

        middle_index = len(full_results)//2
        # Search that excludes the old value but includes the new one
        expr = "%s>=%s" % (attr, full_results[middle_index])
        results, cookie = self.vlv_search(attr, expr, cookie=cookie,
                                          after_count=len(self.users))
        self.assertEqual(results, full_results[middle_index:])

    # Check you can't add a value to a vlv view
    def test_vlv_add_during_view(self):
        attr = 'roomNumber'
        expr = "(objectclass=user)"

        # Start new search
        full_results, cookie = self.vlv_search(attr, expr,
                                               after_count=len(self.users))

        # Add a user at the end of the sort order
        add_val = "z_addedval"
        user = {'cn': add_val, "objectclass": "user", attr: add_val}
        user['dn'] = "cn=%s,%s" % (user['cn'], self.ou)
        self.ldb.add(user)

        results, cookie = self.vlv_search(attr, expr, cookie=cookie,
                                          after_count=len(self.users)+1)
        self.assertEqual(results, full_results)

    def test_vlv_delete_during_view(self):
        attr = 'roomNumber'
        expr = "(objectclass=user)"

        # Start new search
        full_results, cookie = self.vlv_search(attr, expr,
                                               after_count=len(self.users))

        # Delete one of the users
        del_index = len(self.users)//2
        del_user = self.users[del_index]
        self.ldb.delete(del_user['dn'])

        results, cookie = self.vlv_search(attr, expr, cookie=cookie,
                                          after_count=len(self.users))
        expected_results = [r for r in full_results if r != del_user[attr]]
        self.assertEqual(results, expected_results)



class PagedResultsTests(TestsWithUserOU):

    def paged_search(self, expr, cookie="", page_size=0, extra_ctrls=None,
                     attrs=None, ou=None, subtree=False, sort=True):
        ou = ou or self.ou
        if cookie:
            cookie = ":" + cookie
        ctrl = "paged_results:1:" + str(page_size) + cookie
        controls = [ctrl]

        # If extra controls are provided then add them, else default to
        # sort control on 'cn' attribute
        if extra_ctrls is not None:
            controls += extra_ctrls
        elif sort:
            sort_ctrl = "server_sort:1:0:cn"
            controls.append(sort_ctrl)

        kwargs = {}
        if attrs is not None:
            kwargs = {"attrs": attrs}

        scope = ldb.SCOPE_ONELEVEL
        if subtree:
            scope = ldb.SCOPE_SUBTREE

        res = self.ldb_ro.search(ou,
                                 expression=expr,
                                 scope=scope,
                                 controls=controls,
                                 **kwargs)
        results = [str(r['cn'][0]) for r in res]

        ctrls = [str(c) for c in res.controls if
                 str(c).startswith("paged_results")]
        assert len(ctrls) == 1, "no paged_results response"

        spl = ctrls[0].rsplit(':', 3)
        cookie = ""
        if len(spl) == 3:
            cookie = spl[-1]
        return results, cookie


class PagedResultsTestsRO(PagedResultsTests):

    def test_paged_search_lockstep(self):
        expr = "(objectClass=*)"
        ps = 3

        all_results, _ = self.paged_search(expr, page_size=len(self.users)+1)

        # Run two different but overlapping paged searches simultaneously.
        set_1_index = int((len(all_results))//3)
        set_2_index = int((2*len(all_results))//3)
        set_1 = all_results[set_1_index:]
        set_2 = all_results[:set_2_index+1]
        set_1_expr = "(cn>=%s)" % (all_results[set_1_index])
        set_2_expr = "(cn<=%s)" % (all_results[set_2_index])

        results, cookie1 = self.paged_search(set_1_expr, page_size=ps)
        self.assertEqual(results, set_1[:ps])
        results, cookie2 = self.paged_search(set_2_expr, page_size=ps)
        self.assertEqual(results, set_2[:ps])

        results, cookie1 = self.paged_search(set_1_expr, cookie=cookie1,
                                             page_size=ps)
        self.assertEqual(results, set_1[ps:ps*2])
        results, cookie2 = self.paged_search(set_2_expr, cookie=cookie2,
                                             page_size=ps)
        self.assertEqual(results, set_2[ps:ps*2])

        results, _ = self.paged_search(set_1_expr, cookie=cookie1,
                                       page_size=len(self.users))
        self.assertEqual(results, set_1[ps*2:])
        results, _ = self.paged_search(set_2_expr, cookie=cookie2,
                                       page_size=len(self.users))
        self.assertEqual(results, set_2[ps*2:])


class PagedResultsTestsGC(PagedResultsTestsRO):

    def setUp(self):
        super(PagedResultsTestsRO, self).setUp()
        self.ldb_ro = SamDB(host + ":3268", credentials=creds,
                            session_info=system_session(lp), lp=lp)


class PagedResultsTestsRW(PagedResultsTests):

    def test_paged_delete_during_search(self, sort=True):
        expr = "(objectClass=*)"

        # Start new search
        first_page_size = 3
        results, cookie = self.paged_search(expr, sort=sort,
                                            page_size=first_page_size)

        # Run normal search to get expected results
        unedited_results, _ = self.paged_search(expr, sort=sort,
                                                page_size=len(self.users))

        # Get remaining users not returned by the search above
        unreturned_users = [u for u in self.users if u['cn'] not in results]

        # Delete one of the users
        del_index = len(self.users)//2
        del_user = unreturned_users[del_index]
        self.ldb.delete(del_user['dn'])

        # Run test
        results, _ = self.paged_search(expr, cookie=cookie, sort=sort,
                                       page_size=len(self.users))
        expected_results = [r for r in unedited_results[first_page_size:]
                            if r != del_user['cn']]
        self.assertEqual(results, expected_results)

    def test_paged_delete_during_search_unsorted(self):
        self.test_paged_delete_during_search(sort=False)

    def test_paged_show_deleted(self):
        unique = time.strftime("%s", time.gmtime())[-5:]
        prefix = "show_deleted_test_%s_" % (unique)
        expr = "(&(objectClass=user)(cn=%s*))" % (prefix)
        del_ctrl = "show_deleted:1"

        num_users = 10
        users = []
        for i in range(num_users):
            user = self.create_user(i, num_users, prefix=prefix)
            users.append(user)

        first_user = users[0]
        self.ldb.delete(first_user['dn'])

        # Start new search
        first_page_size = 3
        results, cookie = self.paged_search(expr, page_size=first_page_size,
                                            extra_ctrls=[del_ctrl],
                                            ou=self.base_dn,
                                            subtree=True)

        # Get remaining users not returned by the search above
        unreturned_users = [u for u in users if u['cn'] not in results]

        # Delete one of the users
        del_index = len(users)//2
        del_user = unreturned_users[del_index]
        self.ldb.delete(del_user['dn'])

        results2, _ = self.paged_search(expr, cookie=cookie,
                                        page_size=len(users)*2,
                                        extra_ctrls=[del_ctrl],
                                        ou=self.base_dn,
                                        subtree=True)

        user_cns = {str(u['cn']) for u in users}
        deleted_cns = {first_user['cn'], del_user['cn']}

        all_results = results + results2
        normal_results = {r for r in all_results if "DEL:" not in r}
        self.assertEqual(normal_results, user_cns - deleted_cns)

        # Deleted results get "\nDEL:<GUID>" added to the CN, so cut it out.
        deleted_results = {r[:r.index('\n')] for r in all_results
                           if "DEL:" in r}
        self.assertEqual(deleted_results, deleted_cns)

    def test_paged_add_during_search(self, sort=True):
        expr = "(objectClass=*)"

        # Start new search
        first_page_size = 3
        results, cookie = self.paged_search(expr, sort=sort,
                                            page_size=first_page_size)

        unedited_results, _ = self.paged_search(expr, sort=sort,
                                                page_size=len(self.users)+1)

        # Get remaining users not returned by the search above
        unwalked_users = [cn for cn in unedited_results if cn not in results]

        # Add a user in the middle of the sort order
        middle_index = len(unwalked_users)//2
        middle_user = unwalked_users[middle_index]

        user = {'cn': middle_user + '_2', "objectclass": "user"}
        user['dn'] = "cn=%s,%s" % (user['cn'], self.ou)
        self.ldb.add(user)

        results, _ = self.paged_search(expr, sort=sort, cookie=cookie,
                                       page_size=len(self.users)+1)
        expected_results = unwalked_users[:]

        # Uncomment this line to assert that adding worked.
        # expected_results.insert(middle_index+1, user['cn'])

        self.assertEqual(results, expected_results)

    # On Windows, when server_sort ctrl is NOT provided in the initial search,
    # adding a record during the search will cause the modified record to
    # be returned in a future page if it belongs there in the ordering.
    # When server_sort IS provided, the added record will not be returned.
    # Samba implements the latter behaviour. This test confirms Samba's
    # implementation and will fail on Windows.
    def test_paged_add_during_search_unsorted(self):
        self.test_paged_add_during_search(sort=False)

    def test_paged_modify_during_search(self, sort=True):
        expr = "(objectClass=*)"

        # Start new search
        first_page_size = 3
        results, cookie = self.paged_search(expr, sort=sort,
                                            page_size=first_page_size)

        unedited_results, _ = self.paged_search(expr, sort=sort,
                                                page_size=len(self.users)+1)

        # Modify user in the middle of the remaining sort order
        unwalked_users = [cn for cn in unedited_results if cn not in results]
        middle_index = len(unwalked_users)//2
        middle_cn = unwalked_users[middle_index]

        # Find user object
        users_with_middle_cn = [u for u in self.users if u['cn'] == middle_cn]
        self.assertEqual(len(users_with_middle_cn), 1)
        middle_user = users_with_middle_cn[0]

        # Rename object
        edit_cn = "z_" + middle_cn
        new_dn = middle_user['dn'].replace(middle_cn, edit_cn)
        self.ldb.rename(middle_user['dn'], new_dn)

        results, _ = self.paged_search(expr, cookie=cookie, sort=sort,
                                       page_size=len(self.users)+1)
        expected_results = unwalked_users[:]
        expected_results[middle_index] = edit_cn
        self.assertEqual(results, expected_results)

    # On Windows, when server_sort ctrl is NOT provided in the initial search,
    # modifying a record during the search will cause the modified record to
    # be returned in its new place in a CN ordering.
    # When server_sort IS provided, the record will be returned its old place
    # in the control-specified ordering.
    # Samba implements the latter behaviour. This test confirms Samba's
    # implementation and will fail on Windows.
    def test_paged_modify_during_search_unsorted(self):
        self.test_paged_modify_during_search(sort=False)

    def test_paged_modify_object_scope(self):
        expr = "(objectClass=*)"

        ou2 = "OU=vlvtestou2,%s" % (self.tree_dn)
        self.ldb.add({"dn": ou2, "objectclass": "organizationalUnit"})

        # Do a separate, full search to get all results
        unedited_results, _ = self.paged_search(expr,
                                                page_size=len(self.users)+1)

        # Rename before starting a search
        first_cn = self.users[0]['cn']
        new_dn = "CN=%s,%s" % (first_cn, ou2)
        self.ldb.rename(self.users[0]['dn'], new_dn)

        # Start new search under the original OU
        first_page_size = 3
        results, cookie = self.paged_search(expr, page_size=first_page_size)
        self.assertEqual(results, unedited_results[1:1+first_page_size])

        # Get one of the users that is yet to be returned
        unwalked_users = [cn for cn in unedited_results if cn not in results]
        middle_index = len(unwalked_users)//2
        middle_cn = unwalked_users[middle_index]

        # Find user object
        users_with_middle_cn = [u for u in self.users if u['cn'] == middle_cn]
        self.assertEqual(len(users_with_middle_cn), 1)
        middle_user = users_with_middle_cn[0]

        # Rename
        new_dn = "CN=%s,%s" % (middle_cn, ou2)
        self.ldb.rename(middle_user['dn'], new_dn)

        results, _ = self.paged_search(expr, cookie=cookie,
                                       page_size=len(self.users)+1)

        expected_results = unwalked_users[:]

        # We should really expect that the object renamed into a different
        # OU should vanish from the results, but turns out Windows does return
        # the object in this case.  Our module matches the Windows behaviour.

        # If behaviour changes, this line inverts the test's expectations to
        # what you might expect.
        # del expected_results[middle_index]

        # But still expect the user we removed before the search to be gone
        del expected_results[0]

        self.assertEqual(results, expected_results)

    def test_paged_modify_one_during_search(self):
        prefix = "change_during_search_"
        num_users = 5
        users = [self.create_user(i, num_users, prefix=prefix)
                 for i in range(num_users)]
        expr = "(&(objectClass=user)(facsimileTelephoneNumber=%s*))" % (prefix)

        # Get the first page, then change the searched attribute and
        # try for the second page.
        results, cookie = self.paged_search(expr, page_size=1)
        self.assertEqual(len(results), 1)
        unwalked_users = [u for u in users if u['cn'] != results[0]]
        self.assertEqual(len(unwalked_users), num_users-1)

        mod_dn = unwalked_users[0]['dn']
        self.ldb.modify_ldif("dn: %s\n"
                             "changetype: modify\n"
                             "replace: facsimileTelephoneNumber\n"
                             "facsimileTelephoneNumber: 123" % mod_dn)

        results, _ = self.paged_search(expr, cookie=cookie,
                                       page_size=len(self.users))
        expected_cns = {u['cn'] for u in unwalked_users if u['dn'] != mod_dn}
        self.assertEqual(set(results), expected_cns)

    def test_paged_modify_all_during_search(self):
        prefix = "change_during_search_"
        num_users = 5
        users = [self.create_user(i, num_users, prefix=prefix)
                 for i in range(num_users)]
        expr = "(&(objectClass=user)(facsimileTelephoneNumber=%s*))" % (prefix)

        # Get the first page, then change the searched attribute and
        # try for the second page.
        results, cookie = self.paged_search(expr, page_size=1)
        unwalked_users = [u for u in users if u['cn'] != results[0]]

        for u in users:
            self.ldb.modify_ldif("dn: %s\n"
                                 "changetype: modify\n"
                                 "replace: facsimileTelephoneNumber\n"
                                 "facsimileTelephoneNumber: 123" % u['dn'])

        results, _ = self.paged_search(expr, cookie=cookie,
                                       page_size=len(self.users))
        self.assertEqual(results, [])

    def assertPagedSearchRaises(self, err_num, expr, cookie, attrs=None,
                                extra_ctrls=None):
        try:
            results, _ = self.paged_search(expr, cookie=cookie,
                                           page_size=2,
                                           extra_ctrls=extra_ctrls,
                                           attrs=attrs)
        except ldb.LdbError as e:
            self.assertEqual(e.args[0], err_num)
            return

        self.fail("No error raised by invalid search")

    def test_paged_changed_expr(self):
        # Initiate search then use a different expr in subsequent req
        expr = "(objectClass=*)"
        results, cookie = self.paged_search(expr, page_size=3)
        expr = "cn>=a"
        expected_error_num = 12
        self.assertPagedSearchRaises(expected_error_num, expr, cookie)

    def test_paged_changed_controls(self):
        expr = "(objectClass=*)"
        sort_ctrl = "server_sort:1:0:cn"
        del_ctrl = "show_deleted:1"
        expected_error_num = 12
        ps = 3

        # Initiate search with a sort control then remove in subsequent req
        results, cookie = self.paged_search(expr, page_size=ps,
                                            extra_ctrls=[sort_ctrl])
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, extra_ctrls=[])

        # Initiate search with no sort control then add one in subsequent req
        results, cookie = self.paged_search(expr, page_size=ps,
                                            extra_ctrls=[])
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, extra_ctrls=[sort_ctrl])

        # Initiate search with show-deleted control then
        # remove it in subsequent req
        results, cookie = self.paged_search(expr, page_size=ps,
                                            extra_ctrls=[del_ctrl])
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, extra_ctrls=[])

        # Initiate normal search then add show-deleted control
        # in subsequent req
        results, cookie = self.paged_search(expr, page_size=ps,
                                            extra_ctrls=[])
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, extra_ctrls=[del_ctrl])

        # Changing order of controls shouldn't break the search
        results, cookie = self.paged_search(expr, page_size=ps,
                                            extra_ctrls=[del_ctrl, sort_ctrl])
        try:
            results, cookie = self.paged_search(expr, page_size=ps,
                                                extra_ctrls=[sort_ctrl,
                                                             del_ctrl])
        except ldb.LdbError as e:
            self.fail(e)

    def test_paged_cant_change_controls_data(self):
        # Some defaults for the rest of the tests
        expr = "(objectClass=*)"
        sort_ctrl = "server_sort:1:0:cn"
        expected_error_num = 12

        # Initiate search with sort control then change it in subsequent req
        results, cookie = self.paged_search(expr, page_size=3,
                                            extra_ctrls=[sort_ctrl])
        changed_sort_ctrl = "server_sort:1:0:roomNumber"
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, extra_ctrls=[changed_sort_ctrl])

        # Initiate search with a control with crit=1, then use crit=0
        results, cookie = self.paged_search(expr, page_size=3,
                                            extra_ctrls=[sort_ctrl])
        changed_sort_ctrl = "server_sort:0:0:cn"
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, extra_ctrls=[changed_sort_ctrl])

    def test_paged_search_referrals(self):
        expr = "(objectClass=*)"
        paged_ctrl = "paged_results:1:5"
        res = self.ldb.search(self.base_dn,
                              expression=expr,
                              attrs=['cn'],
                              scope=ldb.SCOPE_SUBTREE,
                              controls=[paged_ctrl])

        # Do a paged search walk over the whole database and save a list
        # of all the referrals returned by each search.
        referral_lists = []

        while True:
            referral_lists.append(res.referals)

            ctrls = [str(c) for c in res.controls if
                     str(c).startswith("paged_results")]
            self.assertEqual(len(ctrls), 1)
            spl = ctrls[0].rsplit(':')
            if len(spl) != 3:
                break

            cookie = spl[-1]
            res = self.ldb.search(self.base_dn,
                                  expression=expr,
                                  attrs=['cn'],
                                  scope=ldb.SCOPE_SUBTREE,
                                  controls=[paged_ctrl + ":" + cookie])

        ref_list = referral_lists[0]

        # Sanity check to make sure the search actually did something
        self.assertGreater(len(referral_lists), 2)

        # Check the first referral set contains stuff
        self.assertGreater(len(ref_list), 0)

        # Check the others don't
        self.assertTrue(all([len(l) == 0 for l in referral_lists[1:]]))

        # Check the entries in the first referral list look like referrals
        self.assertTrue(all([s.startswith('ldap://') for s in ref_list]))

    def test_paged_change_attrs(self):
        expr = "(objectClass=*)"
        attrs = ['cn']
        expected_error_num = 12

        results, cookie = self.paged_search(expr, page_size=3, attrs=attrs)
        results, cookie = self.paged_search(expr, cookie=cookie, page_size=3,
                                            attrs=attrs)

        changed_attrs = attrs + ['roomNumber']
        self.assertPagedSearchRaises(expected_error_num, expr,
                                     cookie, attrs=changed_attrs,
                                     extra_ctrls=[])

    def test_vlv_paged(self):
        """Testing behaviour with VLV and paged_results set.

        A strange combination, certainly

        Thankfully combining both of these gives
        unavailable-critical-extension against Windows 1709

        """
        sort_control = "server_sort:1:0:cn"

        try:
            msgs = self.ldb.search(base=self.base_dn,
                                   scope=ldb.SCOPE_SUBTREE,
                                   attrs=["objectGUID", "cn", "member"],
                                   controls=["vlv:1:20:20:11:0",
                                             sort_control,
                                             "paged_results:1:1024"])
            self.fail("should have failed with LDAP_UNAVAILABLE_CRITICAL_EXTENSION")
        except ldb.LdbError as e:
            (enum, estr) = e.args
            self.assertEqual(enum, ldb.ERR_UNSUPPORTED_CRITICAL_EXTENSION)


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)
