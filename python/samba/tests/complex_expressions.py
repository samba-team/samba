# -*- coding: utf-8 -*-

# Copyright Andrew Bartlett 2018
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import print_function
import optparse
import samba
import samba.getopt as options
import sys
import os
import time
from samba.auth import system_session
from samba.tests import TestCase
import ldb

ERRCODE_ENTRY_EXISTS = 68
ERRCODE_OPERATIONS_ERROR = 1
ERRCODE_INVALID_VALUE = 21
ERRCODE_CLASS_VIOLATION = 65

parser = optparse.OptionParser("{0} <host>".format(sys.argv[0]))
sambaopts = options.SambaOptions(parser)

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
parser.add_option("-v", action="store_true", dest="verbose",
                  help="print successful expression outputs")
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

# Set properly at end of file.
host = None

global ou_count
ou_count = 0


class ComplexExpressionTests(TestCase):
    # Using setUpClass instead of setup because we're not modifying any
    # records in the tests
    @classmethod
    def setUpClass(cls):
        super(ComplexExpressionTests, cls).setUpClass()
        cls.samdb = samba.samdb.SamDB(host, lp=lp,
                                      session_info=system_session(),
                                      credentials=creds)

        ou_name = "ComplexExprTest"
        cls.base_dn = "OU={0},{1}".format(ou_name, cls.samdb.domain_dn())

        try:
            cls.samdb.delete(cls.base_dn, ["tree_delete:1"])
        except:
            pass

        try:
            cls.samdb.create_ou(cls.base_dn)
        except ldb.LdbError as e:
            if e.args[0] == ERRCODE_ENTRY_EXISTS:
                print(('test ou {ou} already exists. Delete with '
                       '"samba-tool group delete OU={ou} '
                       '--force-subtree-delete"').format(ou=ou_name))
            raise e

        cls.name_template = "testuser{0}"
        cls.default_n = 10

        # These fields are carefully hand-picked from the schema. They have
        # syntax and handling appropriate for our test structure.
        cls.largeint_f = "accountExpires"
        cls.str_f = "accountNameHistory"
        cls.int_f = "flags"
        cls.enum_f = "preferredDeliveryMethod"
        cls.time_f = "msTSExpireDate"
        cls.ranged_int_f = "countryCode"

    @classmethod
    def tearDownClass(cls):
        cls.samdb.delete(cls.base_dn, ["tree_delete:1"])

    # Make test OU containing users with field=val for each val
    def make_test_objects(self, field, vals):
        global ou_count
        ou_count += 1
        ou_dn = "OU=testou{0},{1}".format(ou_count, self.base_dn)
        self.samdb.create_ou(ou_dn)

        ldap_objects = [{"dn": "CN=testuser{0},{1}".format(n, ou_dn),
                         "name": self.name_template.format(n),
                         "objectClass": "user",
                         field: n}
                        for n in vals]

        for ldap_object in ldap_objects:
            # It's useful to keep appropriate python types in the ldap_object
            # dict but smdb's 'add' function expects strings.
            stringed_ldap_object = {k: str(v)
                                    for (k, v) in ldap_object.items()}
            try:
                self.samdb.add(stringed_ldap_object)
            except ldb.LdbError as e:
                print("failed to add %s" % (stringed_ldap_object))
                raise e

        return ou_dn, ldap_objects

    # Run search expr and print out time.  This function should be used for
    # almost all searching.
    def time_ldap_search(self, expr, dn):
        time_taken = 0
        try:
            start_time = time.time()
            res = self.samdb.search(base=dn,
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression=expr)
            time_taken = time.time() - start_time
        except Exception as e:
            print("failed expr " + expr)
            raise e
        print("{0} took {1}s".format(expr, time_taken))
        return res, time_taken

    # Take an ldap expression and an equivalent python expression.
    # Run and time the ldap expression and compare the result to the python
    # expression run over the a list of ldap_object dicts.
    def assertLDAPQuery(self, ldap_expr, ou_dn, py_expr, ldap_objects):

        # run (and time) the LDAP search expression over the DB
        res, time_taken = self.time_ldap_search(ldap_expr, ou_dn)
        results = {str(row.get('name')[0]) for row in res}

        # build the set of expected results by evaluating the python-equivalent
        # of the search expression over the same set of objects
        expected_results = set()
        for ldap_object in ldap_objects:
            try:
                final_expr = py_expr.format(**ldap_object)
            except KeyError:
                # If the format on the py_expr hits a key error, then
                # ldap_object doesn't have the field, so it shouldn't match.
                continue

            if eval(final_expr):
                expected_results.add(str(ldap_object['name']))

        self.assertEqual(results, expected_results)

        if opts.verbose:
            ldap_object_names = {l['name'] for l in ldap_objects}
            excluded = ldap_object_names - results
            excluded = "\n  ".join(excluded) or "[NOTHING]"
            returned = "\n  ".join(expected_results) or "[NOTHING]"

            print("PASS: Expression {0} took {1}s and returned:"
                  "\n  {2}\n"
                  "Excluded:\n  {3}\n".format(ldap_expr,
                                              time_taken,
                                              returned,
                                              excluded))

    # Basic integer range test
    def test_int_range(self, field=None):
        n = self.default_n
        field = field or self.int_f
        ou_dn, ldap_objects = self.make_test_objects(field, range(n))

        expr = "(&(%s>=%s)(%s<=%s))" % (field, n-1, field, n+1)
        py_expr = "%d <= {%s} <= %d" % (n-1, field, n+1)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        half_n = int(n/2)

        expr = "(%s<=%s)" % (field, half_n)
        py_expr = "{%s} <= %d" % (field, half_n)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        expr = "(%s>=%s)" % (field, half_n)
        py_expr = "{%s} >= %d" % (field, half_n)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    # Same test again for largeint and enum
    def test_largeint_range(self):
        self.test_int_range(self.largeint_f)

    def test_enum_range(self):
        self.test_int_range(self.enum_f)

    # Special range test for integer field with upper and lower bounds defined.
    # The bounds are checked on insertion, not search, so we should be able
    # to compare to a constant that is outside bounds.
    def test_ranged_int_range(self):
        field = self.ranged_int_f
        ubound = 2**16
        width = 8

        vals = list(range(ubound-width, ubound))
        ou_dn, ldap_objects = self.make_test_objects(field, vals)

        # Check <= value above overflow returns all vals
        expr = "(%s<=%d)" % (field, ubound+5)
        py_expr = "{%s} <= %d" % (field, ubound+5)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    # Test range also works for time fields
    def test_time_range(self):
        n = self.default_n
        field = self.time_f
        n = self.default_n
        width = int(n/2)

        base_time = 20050116175514
        time_range = [base_time + t for t in range(-width, width)]
        time_range = [str(t) + ".0Z" for t in time_range]
        ou_dn, ldap_objects = self.make_test_objects(field, time_range)

        expr = "(%s<=%s)" % (field, str(base_time) + ".0Z")
        py_expr = 'int("{%s}"[:-3]) <= %d' % (field, base_time)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        expr = "(&(%s>=%s)(%s<=%s))" % (field, str(base_time-1) + ".0Z",
                                        field, str(base_time+1) + ".0Z")
        py_expr = '%d <= int("{%s}"[:-3]) <= %d' % (base_time-1,
                                                    field,
                                                    base_time+1)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    # Run each comparison op on a simple test set.  Time taken will be printed.
    def test_int_single_cmp_op_speeds(self, field=None):
        n = self.default_n
        field = field or self.int_f
        ou_dn, ldap_objects = self.make_test_objects(field, range(n))

        comp_ops = ['=', '<=', '>=']
        py_comp_ops = ['==', '<=', '>=']
        exprs = ["(%s%s%d)" % (field, c, n) for c in comp_ops]
        py_exprs = ["{%s}%s%d" % (field, c, n) for c in py_comp_ops]

        for expr, py_expr in zip(exprs, py_exprs):
            self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    def test_largeint_single_cmp_op_speeds(self):
        self.test_int_single_cmp_op_speeds(self.largeint_f)

    def test_enum_single_cmp_op_speeds(self):
        self.test_int_single_cmp_op_speeds(self.enum_f)

    # Check strings are ordered using a naive ordering.
    def test_str_ordering(self):
        field = self.str_f
        a_ord = ord('A')
        n = 10
        str_range = ['abc{0}d'.format(chr(c)) for c in range(a_ord, a_ord+n)]
        ou_dn, ldap_objects = self.make_test_objects(field, str_range)
        half_n = int(a_ord + n/2)

        # Basic <= and >= statements
        expr = "(%s>=abc%s)" % (field, chr(half_n))
        py_expr = "'{%s}' >= 'abc%s'" % (field, chr(half_n))
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        expr = "(%s<=abc%s)" % (field, chr(half_n))
        py_expr = "'{%s}' <= 'abc%s'" % (field, chr(half_n))
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        # String range
        expr = "(&(%s>=abc%s)(%s<=abc%s))" % (field, chr(half_n-2),
                                              field, chr(half_n+2))
        py_expr = "'abc%s' <= '{%s}' <= 'abc%s'" % (chr(half_n-2),
                                                    field,
                                                    chr(half_n+2))
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        # Integers treated as string
        expr = "(%s>=1)" % (field)
        py_expr = "'{%s}' >= '1'" % (field)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    # Windows returns nothing for invalid expressions. Expected fail on samba.
    def test_invalid_expressions(self, field=None):
        field = field or self.int_f
        n = self.default_n
        ou_dn, ldap_objects = self.make_test_objects(field, list(range(n)))
        int_expressions = ["(%s>=abc)",
                           "(%s<=abc)",
                           "(%s=abc)"]

        for expr in int_expressions:
            expr = expr % (field)
            self.assertLDAPQuery(expr, ou_dn, "False", ldap_objects)

    def test_largeint_invalid_expressions(self):
        self.test_invalid_expressions(self.largeint_f)

    def test_enum_invalid_expressions(self):
        self.test_invalid_expressions(self.enum_f)

    def test_case_insensitive(self):
        str_range = ["äbc"+str(n) for n in range(10)]
        ou_dn, ldap_objects = self.make_test_objects(self.str_f, str_range)

        expr = "(%s=äbc1)" % (self.str_f)
        pyexpr = '"{%s}"=="äbc1"' % (self.str_f)
        self.assertLDAPQuery(expr, ou_dn, pyexpr, ldap_objects)

        expr = "(%s=ÄbC1)" % (self.str_f)
        self.assertLDAPQuery(expr, ou_dn, pyexpr, ldap_objects)

    # Check negative numbers can be entered and compared
    def test_negative_cmp(self, field=None):
        field = field or self.int_f
        width = 6
        around_zero = list(range(-width, width))
        ou_dn, ldap_objects = self.make_test_objects(field, around_zero)

        expr = "(%s>=-3)" % (field)
        py_expr = "{%s} >= -3" % (field)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    def test_negative_cmp_largeint(self):
        self.test_negative_cmp(self.largeint_f)

    def test_negative_cmp_enum(self):
        self.test_negative_cmp(self.enum_f)

    # Check behaviour on insertion and comparison of zero-prefixed numbers.
    # Samba errors on insertion, Windows strips the leading zeroes.
    def test_zero_prefix(self, field=None):
        field = field or self.int_f

        # Test comparison with 0-prefixed constants.
        n = self.default_n
        ou_dn, ldap_objects = self.make_test_objects(field, list(range(n)))

        expr = "(%s>=00%d)" % (field, n/2)
        py_expr = "{%s} >= %d" % (field, n/2)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        # Delete the test OU so we don't mix it up with the next one.
        self.samdb.delete(ou_dn, ["tree_delete:1"])

        # Try inserting 0-prefixed numbers, check it fails.
        zero_pref_nums = ['00'+str(num) for num in range(n)]
        try:
            ou_dn, ldap_objects = self.make_test_objects(field, zero_pref_nums)
        except ldb.LdbError as e:
            if e.args[0] != ERRCODE_INVALID_VALUE:
                raise e
            return

        # Samba doesn't get this far - the exception is raised.  Windows allows
        # the insertion and removes the leading 0s as tested below.
        # Either behaviour is fine.
        print("LDAP allowed insertion of 0-prefixed nums for field " + field)

        res = self.samdb.search(base=ou_dn,
                                scope=ldb.SCOPE_SUBTREE,
                                expression="(objectClass=user)")
        returned_nums = [str(r.get(field)[0]) for r in res]
        expect = [str(n) for n in range(n)]
        self.assertEqual(set(returned_nums), set(expect))

        expr = "(%s>=%d)" % (field, n/2)
        py_expr = "{%s} >= %d" % (field, n/2)
        for ldap_object in ldap_objects:
            ldap_object[field] = int(ldap_object[field])

        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

    def test_zero_prefix_largeint(self):
        self.test_zero_prefix(self.largeint_f)

    def test_zero_prefix_enum(self):
        self.test_zero_prefix(self.enum_f)

    # Check integer overflow is handled as best it can be.
    def test_int_overflow(self, field=None, of=None):
        field = field or self.int_f
        of = of or 2**31-1
        width = 8

        vals = list(range(of-width, of+width))
        ou_dn, ldap_objects = self.make_test_objects(field, vals)

        # Check ">=overflow" doesn't return vals past overflow
        expr = "(%s>=%d)" % (field, of-3)
        py_expr = "%d <= {%s} <= %d" % (of-3, field, of)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        # "<=overflow" returns everything
        expr = "(%s<=%d)" % (field, of)
        py_expr = "True"
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        # Values past overflow should be negative
        expr = "(&(%s<=%d)(%s>=0))" % (field, of, field)
        py_expr = "{%s} <= %d" % (field, of)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)
        expr = "(%s<=0)" % (field)
        py_expr = "{%s} >= %d" % (field, of+1)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        # Get the values back out and check vals past overflow are negative.
        res = self.samdb.search(base=ou_dn,
                                scope=ldb.SCOPE_SUBTREE,
                                expression="(objectClass=user)")
        returned_nums = [str(r.get(field)[0]) for r in res]

        # Note: range(a,b) == [a..b-1] (confusing)
        up_to_overflow = list(range(of-width, of+1))
        negatives = list(range(-of-1, -of+width-2))

        expect = [str(n) for n in up_to_overflow + negatives]
        self.assertEqual(set(returned_nums), set(expect))

    def test_enum_overflow(self):
        self.test_int_overflow(self.enum_f, 2**31-1)

    # Check cmp works on uSNChanged. We can't insert uSNChanged vals, they get
    # added automatically so we'll just insert some objects and go with what
    # we get.
    def test_usnchanged(self):
        field = "uSNChanged"
        n = 10
        # Note we can't actually set uSNChanged via LDAP (LDB ignores it),
        # so the input val range doesn't matter here
        ou_dn, _ = self.make_test_objects(field, list(range(n)))

        # Get the assigned uSNChanged values
        res = self.samdb.search(base=ou_dn,
                                scope=ldb.SCOPE_SUBTREE,
                                expression="(objectClass=user)")

        # Our vals got ignored so make ldap_objects from search result
        ldap_objects = [{'name': str(r['name'][0]),
                         field: int(r[field][0])}
                        for r in res]

        # Get the median val and use as the number in the test search expr.
        nums = [l[field] for l in ldap_objects]
        nums = list(sorted(nums))
        search_num = nums[int(len(nums)/2)]

        expr = "(&(%s<=%d)(objectClass=user))" % (field, search_num)
        py_expr = "{%s} <= %d" % (field, search_num)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)

        expr = "(&(%s>=%d)(objectClass=user))" % (field, search_num)
        py_expr = "{%s} >= %d" % (field, search_num)
        self.assertLDAPQuery(expr, ou_dn, py_expr, ldap_objects)


# If we're called independently then import subunit, get host from first
# arg and run.  Otherwise, subunit ran us so just set host from env.
# We always try to run over LDAP rather than direct file, so that
# search timings are not impacted by opening and closing the tdb file.
if __name__ == "__main__":
    from samba.tests.subunitrun import TestProgram
    host = args[0]

    if "://" not in host:
        if os.path.isfile(host):
            host = "tdb://%s" % host
        else:
            host = "ldap://%s" % host
    TestProgram(module=__name__)
else:
    host = "ldap://" + os.getenv("SERVER")
