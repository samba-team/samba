#!/usr/bin/env python
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
    elif ':' in gte or '\x00' in gte:
        gte = base64.b64encode(gte)
        m = "base64>=%s" % gte
    else:
        m = ">=%s" % gte

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


class VLVTests(samba.tests.TestCase):

    def create_user(self, i, n, prefix='vlvtest', suffix='', attrs=None):
        name = "%s%d%s" % (prefix, i, suffix)
        user = {
            'cn': name,
            "objectclass": "user",
            'givenName': "abcdefghijklmnopqrstuvwxyz"[i % 26],
            "roomNumber": "%sbc" % (n - i),
            "carLicense": "后来经",
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
            "adminDisplayName": "%d\x00b" % (n-i),
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
        super(VLVTests, self).setUp()
        self.ldb = SamDB(host, credentials=creds,
                         session_info=system_session(lp), lp=lp)

        self.base_dn = self.ldb.domain_dn()
        self.ou = "ou=vlv,%s" % self.base_dn
        if opts.delete_in_setup:
            try:
                self.ldb.delete(self.ou, ['tree_delete:1'])
            except ldb.LdbError as e:
                print("tried deleting %s, got error %s" % (self.ou, e))
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
        super(VLVTests, self).tearDown()
        if not opts.delete_in_setup:
            self.ldb.delete(self.ou, ['tree_delete:1'])

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
            full_results = [(x[attr][0], x['cn'][0]) for x in res]
        else:
            full_results = [x[attr][0].lower() for x in res]
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
                gte_keys.append(expected_order[len(expected_order) // 2] + ' tail')

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
        self.assertEquals(expected_results, results)

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
                                                        gte=gte,
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

                        self.assertEquals(expected_results, results)

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

            for before in range(0, 3) + [6, 11, 19]:
                for after in range(0, 3) + [6, 11, 19]:
                    start = max(before - 1, 1)
                    end = max(start + 4, original_n - after + 2)
                    for offset in range(start, end):
                        #if iteration > 2076:
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
                                expected_results.append(x[0])
                                if (len(expected_results) ==
                                    real_before + real_after + 1):
                                    break
                            else:
                                skipped += 1

                        if expected_results != results:
                            print ("attr %s before %d after %d offset %d" %
                                   (attr, before, after, offset))
                        self.assertEquals(expected_results, results)

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
            #self.assertEquals(expected_order, results)

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

                        self.assertEquals(dn_expected, dn_results)

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
                                print ("offset %d denominator %d raised error "
                                       "expected error %s\n"
                                       "(offset zero is illegal unless "
                                       "content count is zero)" %
                                       (offset, denominator, e))
                                continue

                            results = [x[attr][0].lower() for x in res]

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
                                        print ("the answer is %s; we said %d" %
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
            print ("searching for attr %s amongst %d deleted objects" %
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
                                                        gte=gte,
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

                        self.assertEquals(expected_results, results)

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
                                                        gte=gte)

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
                            print ("\nattr %s offset %d before %d "
                                   "after %d gte %s" %
                                   (attr, offset, before, after, gte))
                        self.assertEquals(expected_results, results)

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


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


TestProgram(module=__name__, opts=subunitopts)
