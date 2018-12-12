#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tests that confidential attributes (or attributes protected by a ACL that
# denies read access) cannot be guessed through wildcard DB searches.
#
# Copyright (C) Catalyst.Net Ltd
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
import optparse
import sys
sys.path.insert(0, "bin/python")

import samba
import os
from samba.tests.subunitrun import SubunitOptions, TestProgram
import samba.getopt as options
from ldb import SCOPE_BASE, SCOPE_SUBTREE
from samba.dsdb import SEARCH_FLAG_CONFIDENTIAL, SEARCH_FLAG_PRESERVEONDELETE
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE, FLAG_MOD_ADD
from samba.auth import system_session
from samba import gensec, sd_utils
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
import samba.dsdb

parser = optparse.OptionParser("confidential_attr.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
if "://" not in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start + 3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

# When a user does not have access rights to view the objects' attributes,
# Windows and Samba behave slightly differently.
# A windows DC will always act as if the hidden attribute doesn't exist AT ALL
# (for an unprivileged user). So, even for a user that lacks access rights,
# the inverse/'!' queries should return ALL objects. This is similar to the
# kludgeaclredacted behaviour on Samba.
# However, on Samba (for implementation simplicity) we never return a matching
# result for an unprivileged user.
# Either approach is OK, so long as it gets applied consistently and we don't
# disclose any sensitive details by varying what gets returned by the search.
DC_MODE_RETURN_NONE = 0
DC_MODE_RETURN_ALL = 1


#
# Tests start here
#
class ConfidentialAttrCommon(samba.tests.TestCase):

    def setUp(self):
        super(ConfidentialAttrCommon, self).setUp()

        self.ldb_admin = SamDB(ldaphost, credentials=creds,
                               session_info=system_session(lp), lp=lp)
        self.user_pass = "samba123@"
        self.base_dn = self.ldb_admin.domain_dn()
        self.schema_dn = self.ldb_admin.get_schema_basedn()
        self.sd_utils = sd_utils.SDUtils(self.ldb_admin)

        # the tests work by setting the 'Confidential' bit in the searchFlags
        # for an existing schema attribute. This only works against Windows if
        # the systemFlags does not have FLAG_SCHEMA_BASE_OBJECT set for the
        # schema attribute being modified. There are only a few attributes that
        # meet this criteria (most of which only apply to 'user' objects)
        self.conf_attr = "homePostalAddress"
        attr_cn = "CN=Address-Home"
        # schemaIdGuid for homePostalAddress (used for ACE tests)
        self.conf_attr_guid = "16775781-47f3-11d1-a9c3-0000f80367c1"
        self.conf_attr_sec_guid = "77b5b886-944a-11d1-aebd-0000f80367c1"
        self.attr_dn = "{0},{1}".format(attr_cn, self.schema_dn)

        userou = "OU=conf-attr-test"
        self.ou = "{0},{1}".format(userou, self.base_dn)
        self.ldb_admin.create_ou(self.ou)

        # use a common username prefix, so we can use sAMAccountName=CATC-* as
        # a search filter to only return the users we're interested in
        self.user_prefix = "catc-"

        # add a test object with this attribute set
        self.conf_value = "abcdef"
        self.conf_user = "{0}conf-user".format(self.user_prefix)
        self.ldb_admin.newuser(self.conf_user, self.user_pass, userou=userou)
        self.conf_dn = self.get_user_dn(self.conf_user)
        self.add_attr(self.conf_dn, self.conf_attr, self.conf_value)

        # add a sneaky user that will try to steal our secrets
        self.user = "{0}sneaky-user".format(self.user_prefix)
        self.ldb_admin.newuser(self.user, self.user_pass, userou=userou)
        self.ldb_user = self.get_ldb_connection(self.user, self.user_pass)

        self.all_users = [self.user, self.conf_user]

        # add some other users that also have confidential attributes, so we
        # check we don't disclose their details, particularly in '!' searches
        for i in range(1, 3):
            username = "{0}other-user{1}".format(self.user_prefix, i)
            self.ldb_admin.newuser(username, self.user_pass, userou=userou)
            userdn = self.get_user_dn(username)
            self.add_attr(userdn, self.conf_attr, "xyz{0}".format(i))
            self.all_users.append(username)

        # there are 4 users in the OU, plus the OU itself
        self.test_dn = self.ou
        self.total_objects = len(self.all_users) + 1
        self.objects_with_attr = 3

        # sanity-check the flag is not already set (this'll cause problems if
        # previous test run didn't clean up properly)
        search_flags = self.get_attr_search_flags(self.attr_dn)
        self.assertTrue(int(search_flags) & SEARCH_FLAG_CONFIDENTIAL == 0,
                        "{0} searchFlags already {1}".format(self.conf_attr,
                                                             search_flags))

    def tearDown(self):
        super(ConfidentialAttrCommon, self).tearDown()
        self.ldb_admin.delete(self.ou, ["tree_delete:1"])

    def add_attr(self, dn, attr, value):
        m = Message()
        m.dn = Dn(self.ldb_admin, dn)
        m[attr] = MessageElement(value, FLAG_MOD_ADD, attr)
        self.ldb_admin.modify(m)

    def set_attr_search_flags(self, attr_dn, flags):
        """Modifies the searchFlags for an object in the schema"""
        m = Message()
        m.dn = Dn(self.ldb_admin, attr_dn)
        m['searchFlags'] = MessageElement(flags, FLAG_MOD_REPLACE,
                                          'searchFlags')
        self.ldb_admin.modify(m)

        # note we have to update the schema for this change to take effect (on
        # Windows, at least)
        self.ldb_admin.set_schema_update_now()

    def get_attr_search_flags(self, attr_dn):
        """Marks the attribute under test as being confidential"""
        res = self.ldb_admin.search(attr_dn, scope=SCOPE_BASE,
                                    attrs=['searchFlags'])
        return res[0]['searchFlags'][0]

    def make_attr_confidential(self):
        """Marks the attribute under test as being confidential"""

        # work out the original 'searchFlags' value before we overwrite it
        old_value = self.get_attr_search_flags(self.attr_dn)

        self.set_attr_search_flags(self.attr_dn, str(SEARCH_FLAG_CONFIDENTIAL))

        # reset the value after the test completes
        self.addCleanup(self.set_attr_search_flags, self.attr_dn, old_value)

    # The behaviour of the DC can differ in some cases, depending on whether
    # we're talking to a Windows DC or a Samba DC
    def guess_dc_mode(self):
        # if we're in selftest, we can be pretty sure it's a Samba DC
        if os.environ.get('SAMBA_SELFTEST') == '1':
            return DC_MODE_RETURN_NONE

        searches = self.get_negative_match_all_searches()
        res = self.ldb_user.search(self.test_dn, expression=searches[0],
                                   scope=SCOPE_SUBTREE)

        # we default to DC_MODE_RETURN_NONE (samba).Update this if it
        # looks like we're talking to a Windows DC
        if len(res) == self.total_objects:
            return DC_MODE_RETURN_ALL

        # otherwise assume samba DC behaviour
        return DC_MODE_RETURN_NONE

    def get_user_dn(self, name):
        return "CN={0},{1}".format(name, self.ou)

    def get_user_sid_string(self, username):
        user_dn = self.get_user_dn(username)
        user_sid = self.sd_utils.get_object_sid(user_dn)
        return str(user_sid)

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        features = creds_tmp.get_gensec_features() | gensec.FEATURE_SEAL
        creds_tmp.set_gensec_features(features)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS)
        ldb_target = SamDB(url=ldaphost, credentials=creds_tmp, lp=lp)
        return ldb_target

    def assert_search_result(self, expected_num, expr, samdb):

        # try asking for different attributes back: None/all, the confidential
        # attribute itself, and a random unrelated attribute
        attr_filters = [None, ["*"], [self.conf_attr], ['name']]
        for attr in attr_filters:
            res = samdb.search(self.test_dn, expression=expr,
                               scope=SCOPE_SUBTREE, attrs=attr)
            self.assertTrue(len(res) == expected_num,
                            "%u results, not %u for search %s, attr %s" %
                            (len(res), expected_num, expr, str(attr)))

    # return a selection of searches that match exactly against the test object
    def get_exact_match_searches(self):
        first_char = self.conf_value[:1]
        last_char = self.conf_value[-1:]
        test_attr = self.conf_attr

        searches = [
            # search for the attribute using a sub-string wildcard
            # (which could reveal the attribute's actual value)
            "({0}={1}*)".format(test_attr, first_char),
            "({0}=*{1})".format(test_attr, last_char),

            # sanity-check equality against an exact match on value
            "({0}={1})".format(test_attr, self.conf_value),

            # '~=' searches don't work against Samba
            # sanity-check an approx search against an exact match on value
            # "({0}~={1})".format(test_attr, self.conf_value),

            # check wildcard in an AND search...
            "(&({0}={1}*)(objectclass=*))".format(test_attr, first_char),

            # ...an OR search (against another term that will never match)
            "(|({0}={1}*)(objectclass=banana))".format(test_attr, first_char)]

        return searches

    # return searches that match any object with the attribute under test
    def get_match_all_searches(self):
        searches = [
            # check a full wildcard against the confidential attribute
            # (which could reveal the attribute's presence/absence)
            "({0}=*)".format(self.conf_attr),

            # check wildcard in an AND search...
            "(&(objectclass=*)({0}=*))".format(self.conf_attr),

            # ...an OR search (against another term that will never match)
            "(|(objectclass=banana)({0}=*))".format(self.conf_attr),

            # check <=, and >= expressions that would normally find a match
            "({0}>=0)".format(self.conf_attr),
            "({0}<=ZZZZZZZZZZZ)".format(self.conf_attr)]

        return searches

    def assert_conf_attr_searches(self, has_rights_to=0, samdb=None):
        """Check searches against the attribute under test work as expected"""

        if samdb is None:
            samdb = self.ldb_user

        if has_rights_to == "all":
            has_rights_to = self.objects_with_attr

        # these first few searches we just expect to match against the one
        # object under test that we're trying to guess the value of
        expected_num = 1 if has_rights_to > 0 else 0
        for search in self.get_exact_match_searches():
            self.assert_search_result(expected_num, search, samdb)

        # these next searches will match any objects we have rights to see
        expected_num = has_rights_to
        for search in self.get_match_all_searches():
            self.assert_search_result(expected_num, search, samdb)

    # The following are double negative searches (i.e. NOT non-matching-
    # condition) which will therefore match ALL objects, including the test
    # object(s).
    def get_negative_match_all_searches(self):
        first_char = self.conf_value[:1]
        last_char = self.conf_value[-1:]
        not_first_char = chr(ord(first_char) + 1)
        not_last_char = chr(ord(last_char) + 1)

        searches = [
            "(!({0}={1}*))".format(self.conf_attr, not_first_char),
            "(!({0}=*{1}))".format(self.conf_attr, not_last_char)]
        return searches

    # the following searches will not match against the test object(s). So
    # a user with sufficient rights will see an inverse sub-set of objects.
    # (An unprivileged user would either see all objects on Windows, or no
    # objects on Samba)
    def get_inverse_match_searches(self):
        first_char = self.conf_value[:1]
        last_char = self.conf_value[-1:]
        searches = [
            "(!({0}={1}*))".format(self.conf_attr, first_char),
            "(!({0}=*{1}))".format(self.conf_attr, last_char)]
        return searches

    def negative_searches_all_rights(self, total_objects=None):
        expected_results = {}

        if total_objects is None:
            total_objects = self.total_objects

        # these searches should match ALL objects (including the OU)
        for search in self.get_negative_match_all_searches():
            expected_results[search] = total_objects

        # a ! wildcard should only match the objects without the attribute
        search = "(!({0}=*))".format(self.conf_attr)
        expected_results[search] = total_objects - self.objects_with_attr

        # whereas the inverse searches should match all objects *except* the
        # one under test
        for search in self.get_inverse_match_searches():
            expected_results[search] = total_objects - 1

        return expected_results

    # Returns the expected negative (i.e. '!') search behaviour when talking to
    # a DC with DC_MODE_RETURN_ALL behaviour, i.e. we assert that users
    # without rights always see ALL objects in '!' searches
    def negative_searches_return_all(self, has_rights_to=0,
                                     total_objects=None):
        """Asserts user without rights cannot see objects in '!' searches"""
        expected_results = {}

        if total_objects is None:
            total_objects = self.total_objects

        # Windows 'hides' objects by always returning all of them, so negative
        # searches that match all objects will simply return all objects
        for search in self.get_negative_match_all_searches():
            expected_results[search] = total_objects

        # if we're matching on everything except the one object under test
        # (i.e. the inverse subset), we'll still see all objects if
        # has_rights_to == 0. Or we'll see all bar one if has_rights_to == 1.
        inverse_searches = self.get_inverse_match_searches()
        inverse_searches += ["(!({0}=*))".format(self.conf_attr)]

        for search in inverse_searches:
            expected_results[search] = total_objects - has_rights_to

        return expected_results

    # Returns the expected negative (i.e. '!') search behaviour when talking to
    # a DC with DC_MODE_RETURN_NONE behaviour, i.e. we assert that users
    # without rights cannot see objects in '!' searches at all
    def negative_searches_return_none(self, has_rights_to=0):
        expected_results = {}

        # the 'match-all' searches should only return the objects we have
        # access rights to (if any)
        for search in self.get_negative_match_all_searches():
            expected_results[search] = has_rights_to

        # for inverse matches, we should NOT be told about any objects at all
        inverse_searches = self.get_inverse_match_searches()
        inverse_searches += ["(!({0}=*))".format(self.conf_attr)]
        for search in inverse_searches:
            expected_results[search] = 0

        return expected_results

    # Returns the expected negative (i.e. '!') search behaviour. This varies
    # depending on what type of DC we're talking to (i.e. Windows or Samba)
    # and what access rights the user has.
    # Note we only handle has_rights_to="all", 1 (the test object), or 0 (i.e.
    # we don't have rights to any objects)
    def negative_search_expected_results(self, has_rights_to, dc_mode,
                                         total_objects=None):

        if has_rights_to == "all":
            expect_results = self.negative_searches_all_rights(total_objects)

        # if it's a Samba DC, we only expect the 'match-all' searches to return
        # the objects that we have access rights to (all others are hidden).
        # Whereas Windows 'hides' the objects by always returning all of them
        elif dc_mode == DC_MODE_RETURN_NONE:
            expect_results = self.negative_searches_return_none(has_rights_to)
        else:
            expect_results = self.negative_searches_return_all(has_rights_to,
                                                               total_objects)
        return expect_results

    def assert_negative_searches(self, has_rights_to=0,
                                 dc_mode=DC_MODE_RETURN_NONE, samdb=None):
        """Asserts user without rights cannot see objects in '!' searches"""

        if samdb is None:
            samdb = self.ldb_user

        # build a dictionary of key=search-expr, value=expected_num assertions
        expected_results = self.negative_search_expected_results(has_rights_to,
                                                                 dc_mode)

        for search, expected_num in expected_results.items():
            self.assert_search_result(expected_num, search, samdb)

    def assert_attr_returned(self, expect_attr, samdb, attrs):
        # does a query that should always return a successful result, and
        # checks whether the confidential attribute is present
        res = samdb.search(self.conf_dn, expression="(objectClass=*)",
                           scope=SCOPE_SUBTREE, attrs=attrs)
        self.assertTrue(len(res) == 1)

        attr_returned = False
        for msg in res:
            if self.conf_attr in msg:
                attr_returned = True
        self.assertEqual(expect_attr, attr_returned)

    def assert_attr_visible(self, expect_attr, samdb=None):
        if samdb is None:
            samdb = self.ldb_user

        # sanity-check confidential attribute is/isn't returned as expected
        # based on the filter attributes we ask for
        self.assert_attr_returned(expect_attr, samdb, attrs=None)
        self.assert_attr_returned(expect_attr, samdb, attrs=["*"])
        self.assert_attr_returned(expect_attr, samdb, attrs=[self.conf_attr])

        # filtering on a different attribute should never return the conf_attr
        self.assert_attr_returned(expect_attr=False, samdb=samdb,
                                  attrs=['name'])

    def assert_attr_visible_to_admin(self):
        # sanity-check the admin user can always see the confidential attribute
        self.assert_conf_attr_searches(has_rights_to="all",
                                       samdb=self.ldb_admin)
        self.assert_negative_searches(has_rights_to="all",
                                      samdb=self.ldb_admin)
        self.assert_attr_visible(expect_attr=True, samdb=self.ldb_admin)


class ConfidentialAttrTest(ConfidentialAttrCommon):
    def test_basic_search(self):
        """Basic test confidential attributes aren't disclosed via searches"""

        # check we can see a non-confidential attribute in a basic searches
        self.assert_conf_attr_searches(has_rights_to="all")
        self.assert_negative_searches(has_rights_to="all")
        self.assert_attr_visible(expect_attr=True)

        # now make the attribute confidential. Repeat the tests and check that
        # an ordinary user can't see the attribute, or indirectly match on the
        # attribute via the search expression
        self.make_attr_confidential()

        self.assert_conf_attr_searches(has_rights_to=0)
        dc_mode = self.guess_dc_mode()
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)
        self.assert_attr_visible(expect_attr=False)

        # sanity-check we haven't hidden the attribute from the admin as well
        self.assert_attr_visible_to_admin()

    def _test_search_with_allow_acl(self, allow_ace):
        """Checks a ACE with 'CR' rights can override a confidential attr"""
        # make the test attribute confidential and check user can't see it
        self.make_attr_confidential()

        self.assert_conf_attr_searches(has_rights_to=0)
        dc_mode = self.guess_dc_mode()
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)
        self.assert_attr_visible(expect_attr=False)

        # apply the allow ACE to the object under test
        self.sd_utils.dacl_add_ace(self.conf_dn, allow_ace)

        # the user should now be able to see the attribute for the one object
        # we gave it rights to
        self.assert_conf_attr_searches(has_rights_to=1)
        self.assert_negative_searches(has_rights_to=1, dc_mode=dc_mode)
        self.assert_attr_visible(expect_attr=True)

        # sanity-check the admin can still see the attribute
        self.assert_attr_visible_to_admin()

    def test_search_with_attr_acl_override(self):
        """Make the confidential attr visible via an OA attr ACE"""

        # set the SEC_ADS_CONTROL_ACCESS bit ('CR') for the user for the
        # attribute under test, so the user can see it once more
        user_sid = self.get_user_sid_string(self.user)
        ace = "(OA;;CR;{0};;{1})".format(self.conf_attr_guid, user_sid)

        self._test_search_with_allow_acl(ace)

    def test_search_with_propset_acl_override(self):
        """Make the confidential attr visible via a Property-set ACE"""

        # set the SEC_ADS_CONTROL_ACCESS bit ('CR') for the user for the
        # property-set containing the attribute under test (i.e. the
        # attributeSecurityGuid), so the user can see it once more
        user_sid = self.get_user_sid_string(self.user)
        ace = "(OA;;CR;{0};;{1})".format(self.conf_attr_sec_guid, user_sid)

        self._test_search_with_allow_acl(ace)

    def test_search_with_acl_override(self):
        """Make the confidential attr visible via a general 'allow' ACE"""

        # set the allow SEC_ADS_CONTROL_ACCESS bit ('CR') for the user
        user_sid = self.get_user_sid_string(self.user)
        ace = "(A;;CR;;;{0})".format(user_sid)

        self._test_search_with_allow_acl(ace)

    def test_search_with_blanket_oa_acl(self):
        """Make the confidential attr visible via a non-specific OA ACE"""

        # this just checks that an Object Access (OA) ACE without a GUID
        # specified will work the same as an 'Access' (A) ACE
        user_sid = self.get_user_sid_string(self.user)
        ace = "(OA;;CR;;;{0})".format(user_sid)

        self._test_search_with_allow_acl(ace)

    def _test_search_with_neutral_acl(self, neutral_ace):
        """Checks that a user does NOT gain access via an unrelated ACE"""

        # make the test attribute confidential and check user can't see it
        self.make_attr_confidential()

        self.assert_conf_attr_searches(has_rights_to=0)
        dc_mode = self.guess_dc_mode()
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)
        self.assert_attr_visible(expect_attr=False)

        # apply the ACE to the object under test
        self.sd_utils.dacl_add_ace(self.conf_dn, neutral_ace)

        # this should make no difference to the user's ability to see the attr
        self.assert_conf_attr_searches(has_rights_to=0)
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)
        self.assert_attr_visible(expect_attr=False)

        # sanity-check the admin can still see the attribute
        self.assert_attr_visible_to_admin()

    def test_search_with_neutral_acl(self):
        """Give the user all rights *except* CR for any attributes"""

        # give the user all rights *except* CR and check it makes no difference
        user_sid = self.get_user_sid_string(self.user)
        ace = "(A;;RPWPCCDCLCLORCWOWDSDDTSW;;;{0})".format(user_sid)
        self._test_search_with_neutral_acl(ace)

    def test_search_with_neutral_attr_acl(self):
        """Give the user all rights *except* CR for the attribute under test"""

        # giving user all OA rights *except* CR should make no difference
        user_sid = self.get_user_sid_string(self.user)
        rights = "RPWPCCDCLCLORCWOWDSDDTSW"
        ace = "(OA;;{0};{1};;{2})".format(rights, self.conf_attr_guid, user_sid)
        self._test_search_with_neutral_acl(ace)

    def test_search_with_neutral_cr_acl(self):
        """Give the user CR rights for *another* unrelated attribute"""

        # giving user object-access CR rights to an unrelated attribute
        user_sid = self.get_user_sid_string(self.user)
        # use the GUID for sAMAccountName here (for no particular reason)
        unrelated_attr = "3e0abfd0-126a-11d0-a060-00aa006c33ed"
        ace = "(OA;;CR;{0};;{1})".format(unrelated_attr, user_sid)
        self._test_search_with_neutral_acl(ace)


# Check that a Deny ACL on an attribute doesn't reveal confidential info
class ConfidentialAttrTestDenyAcl(ConfidentialAttrCommon):

    def assert_not_in_result(self, res, exclude_dn):
        for msg in res:
            self.assertNotEqual(msg.dn, exclude_dn,
                                "Search revealed object {0}".format(exclude_dn))

    # deny ACL tests are slightly different as we are only denying access to
    # the one object under test (rather than any objects with that attribute).
    # Therefore we need an extra check that we don't reveal the test object
    # in the search, if we're not supposed to
    def assert_search_result(self, expected_num, expr, samdb,
                             excl_testobj=False):

        # try asking for different attributes back: None/all, the confidential
        # attribute itself, and a random unrelated attribute
        attr_filters = [None, ["*"], [self.conf_attr], ['name']]
        for attr in attr_filters:
            res = samdb.search(self.test_dn, expression=expr,
                               scope=SCOPE_SUBTREE, attrs=attr)
            self.assertTrue(len(res) == expected_num,
                            "%u results, not %u for search %s, attr %s" %
                            (len(res), expected_num, expr, str(attr)))

            # assert we haven't revealed the hidden test-object
            if excl_testobj:
                self.assert_not_in_result(res, exclude_dn=self.conf_dn)

    # we make a few tweaks to the regular version of this function to cater to
    # denying specifically one object via an ACE
    def assert_conf_attr_searches(self, has_rights_to=0, samdb=None):
        """Check searches against the attribute under test work as expected"""

        if samdb is None:
            samdb = self.ldb_user

        # make sure the test object is not returned if we've been denied rights
        # to it via an ACE
        excl_testobj = True if has_rights_to == "deny-one" else False

        # these first few searches we just expect to match against the one
        # object under test that we're trying to guess the value of
        expected_num = 1 if has_rights_to == "all" else 0

        for search in self.get_exact_match_searches():
            self.assert_search_result(expected_num, search, samdb,
                                      excl_testobj)

        # these next searches will match any objects with the attribute that
        # we have rights to see (i.e. all except the object under test)
        if has_rights_to == "all":
            expected_num = self.objects_with_attr
        elif has_rights_to == "deny-one":
            expected_num = self.objects_with_attr - 1

        for search in self.get_match_all_searches():
            self.assert_search_result(expected_num, search, samdb,
                                      excl_testobj)

    # override method specifically for deny ACL test cases. Instead of being
    # granted access to either no objects or only one, we are being denied
    # access to only one object (but can still access the rest).
    def negative_searches_return_none(self, has_rights_to=0):
        expected_results = {}

        # on Samba we will see the objects we have rights to, but the one we
        # are denied access to will be hidden
        searches = self.get_negative_match_all_searches()
        searches += self.get_inverse_match_searches()
        for search in searches:
            expected_results[search] = self.total_objects - 1

        # The wildcard returns the objects without this attribute as normal.
        search = "(!({0}=*))".format(self.conf_attr)
        expected_results[search] = self.total_objects - self.objects_with_attr
        return expected_results

    # override method specifically for deny ACL test cases
    def negative_searches_return_all(self, has_rights_to=0,
                                     total_objects=None):
        expected_results = {}

        # When a user lacks access rights to an object, Windows 'hides' it in
        # '!' searches by always returning it, regardless of whether it matches
        searches = self.get_negative_match_all_searches()
        searches += self.get_inverse_match_searches()
        for search in searches:
            expected_results[search] = self.total_objects

        # in the wildcard case, the one object we don't have rights to gets
        # bundled in with the objects that don't have the attribute at all
        search = "(!({0}=*))".format(self.conf_attr)
        has_rights_to = self.objects_with_attr - 1
        expected_results[search] = self.total_objects - has_rights_to
        return expected_results

    # override method specifically for deny ACL test cases
    def assert_negative_searches(self, has_rights_to=0,
                                 dc_mode=DC_MODE_RETURN_NONE, samdb=None):
        """Asserts user without rights cannot see objects in '!' searches"""

        if samdb is None:
            samdb = self.ldb_user

        # As the deny ACL is only denying access to one particular object, add
        # an extra check that the denied object is not returned. (We can only
        # assert this if the '!'/negative search behaviour is to suppress any
        # objects we don't have access rights to)
        excl_testobj = False
        if has_rights_to != "all" and dc_mode == DC_MODE_RETURN_NONE:
            excl_testobj = True

        # build a dictionary of key=search-expr, value=expected_num assertions
        expected_results = self.negative_search_expected_results(has_rights_to,
                                                                 dc_mode)

        for search, expected_num in expected_results.items():
            self.assert_search_result(expected_num, search, samdb,
                                      excl_testobj=excl_testobj)

    def _test_search_with_deny_acl(self, ace):
        # check the user can see the attribute initially
        self.assert_conf_attr_searches(has_rights_to="all")
        self.assert_negative_searches(has_rights_to="all")
        self.assert_attr_visible(expect_attr=True)

        # add the ACE that denies access to the attr under test
        self.sd_utils.dacl_add_ace(self.conf_dn, ace)

        # the user shouldn't be able to see the attribute anymore
        self.assert_conf_attr_searches(has_rights_to="deny-one")
        dc_mode = self.guess_dc_mode()
        self.assert_negative_searches(has_rights_to="deny-one",
                                      dc_mode=dc_mode)
        self.assert_attr_visible(expect_attr=False)

        # sanity-check we haven't hidden the attribute from the admin as well
        self.assert_attr_visible_to_admin()

    def test_search_with_deny_attr_acl(self):
        """Checks a deny ACE works the same way as a confidential attribute"""

        # add an ACE that denies the user Read Property (RP) access to the attr
        # (which is similar to making the attribute confidential)
        user_sid = self.get_user_sid_string(self.user)
        ace = "(OD;;RP;{0};;{1})".format(self.conf_attr_guid, user_sid)

        # check the user cannot see the attribute anymore
        self._test_search_with_deny_acl(ace)

    def test_search_with_deny_acl(self):
        """Checks a blanket deny ACE denies access to an object's attributes"""

        # add an blanket deny ACE for Read Property (RP) rights
        user_dn = self.get_user_dn(self.user)
        user_sid = self.sd_utils.get_object_sid(user_dn)
        ace = "(D;;RP;;;{0})".format(str(user_sid))

        # check the user cannot see the attribute anymore
        self._test_search_with_deny_acl(ace)

    def test_search_with_deny_propset_acl(self):
        """Checks a deny ACE on the attribute's Property-Set"""

        # add an blanket deny ACE for Read Property (RP) rights
        user_sid = self.get_user_sid_string(self.user)
        ace = "(OD;;RP;{0};;{1})".format(self.conf_attr_sec_guid, user_sid)

        # check the user cannot see the attribute anymore
        self._test_search_with_deny_acl(ace)

    def test_search_with_blanket_oa_deny_acl(self):
        """Checks a non-specific 'OD' ACE works the same as a 'D' ACE"""

        # this just checks that adding a 'Object Deny' (OD) ACE without
        # specifying a GUID will work the same way as a 'Deny' (D) ACE
        user_sid = self.get_user_sid_string(self.user)
        ace = "(OD;;RP;;;{0})".format(user_sid)

        # check the user cannot see the attribute anymore
        self._test_search_with_deny_acl(ace)


# Check that using the dirsync controls doesn't reveal confidential attributes
class ConfidentialAttrTestDirsync(ConfidentialAttrCommon):

    def setUp(self):
        super(ConfidentialAttrTestDirsync, self).setUp()
        self.dirsync = ["dirsync:1:1:1000"]

        # because we need to search on the base DN when using the dirsync
        # controls, we need an extra filter for the inverse ('!') search,
        # so we don't get thousands of objects returned
        self.extra_filter = \
            "(&(samaccountname={0}*)(!(isDeleted=*)))".format(self.user_prefix)
        self.single_obj_filter = \
            "(&(samaccountname={0})(!(isDeleted=*)))".format(self.conf_user)

        self.attr_filters = [None, ["*"], ["name"]]

        # Note dirsync behaviour is slighty different for the attribute under
        # test - when you have full access rights, it only returns the objects
        # that actually have this attribute (i.e. it doesn't return an empty
        # message with just the DN). So we add the 'name' attribute into the
        # attribute filter to avoid complicating our assertions further
        self.attr_filters += [[self.conf_attr, "name"]]

    # override method specifically for dirsync, i.e. add dirsync controls
    def assert_search_result(self, expected_num, expr, samdb, base_dn=None):

        # Note dirsync must always search on the partition base DN
        base_dn = self.base_dn

        # we need an extra filter for dirsync because:
        # - we search on the base DN, so otherwise the '!' searches return
        #   thousands of unrelated results, and
        # - we make the test attribute preserve-on-delete in one case, so we
        #   want to weed out results from any previous test runs
        search = "(&{0}{1})".format(expr, self.extra_filter)

        for attr in self.attr_filters:
            res = samdb.search(base_dn, expression=search, scope=SCOPE_SUBTREE,
                               attrs=attr, controls=self.dirsync)
            self.assertTrue(len(res) == expected_num,
                            "%u results, not %u for search %s, attr %s" %
                            (len(res), expected_num, search, str(attr)))

    # override method specifically for dirsync, i.e. add dirsync controls
    def assert_attr_returned(self, expect_attr, samdb, attrs,
                             no_result_ok=False):

        # When using dirsync, the base DN we search on needs to be a naming
        # context. Add an extra filter to ignore all the objects we aren't
        # interested in
        expr = self.single_obj_filter
        res = samdb.search(self.base_dn, expression=expr, scope=SCOPE_SUBTREE,
                           attrs=attrs, controls=self.dirsync)
        self.assertTrue(len(res) == 1 or no_result_ok)

        attr_returned = False
        for msg in res:
            if self.conf_attr in msg and len(msg[self.conf_attr]) > 0:
                attr_returned = True
        self.assertEqual(expect_attr, attr_returned)

    # override method specifically for dirsync (it has slightly different
    # behaviour to normal when requesting specific attributes)
    def assert_attr_visible(self, expect_attr, samdb=None):
        if samdb is None:
            samdb = self.ldb_user

        # sanity-check confidential attribute is/isn't returned as expected
        # based on the filter attributes we ask for
        self.assert_attr_returned(expect_attr, samdb, attrs=None)
        self.assert_attr_returned(expect_attr, samdb, attrs=["*"])

        if expect_attr:
            self.assert_attr_returned(expect_attr, samdb,
                                      attrs=[self.conf_attr])
        else:
            # The behaviour with dirsync when asking solely for an attribute
            # that you don't have rights to is a bit strange. Samba returns
            # no result rather than an empty message with just the DN.
            # Presumably this is due to dirsync module behaviour. It's not
            # disclosive in that the DC behaves the same way as if you asked
            # for a garbage/non-existent attribute
            self.assert_attr_returned(expect_attr, samdb,
                                      attrs=[self.conf_attr],
                                      no_result_ok=True)
            self.assert_attr_returned(expect_attr, samdb,
                                      attrs=["garbage"], no_result_ok=True)

        # filtering on a different attribute should never return the conf_attr
        self.assert_attr_returned(expect_attr=False, samdb=samdb,
                                  attrs=['name'])

    # override method specifically for dirsync (total object count differs)
    def assert_negative_searches(self, has_rights_to=0,
                                 dc_mode=DC_MODE_RETURN_NONE, samdb=None):
        """Asserts user without rights cannot see objects in '!' searches"""

        if samdb is None:
            samdb = self.ldb_user

        # because dirsync uses an extra filter, the total objects we expect
        # here only includes the user objects (not the parent OU)
        total_objects = len(self.all_users)
        expected_results = self.negative_search_expected_results(has_rights_to,
                                                                 dc_mode,
                                                                 total_objects)

        for search, expected_num in expected_results.items():
            self.assert_search_result(expected_num, search, samdb)

    def test_search_with_dirsync(self):
        """Checks dirsync controls don't reveal confidential attributes"""

        self.assert_conf_attr_searches(has_rights_to="all")
        self.assert_attr_visible(expect_attr=True)
        self.assert_negative_searches(has_rights_to="all")

        # make the test attribute confidential and check user can't see it,
        # even if they use the dirsync controls
        self.make_attr_confidential()

        self.assert_conf_attr_searches(has_rights_to=0)
        self.assert_attr_visible(expect_attr=False)
        dc_mode = self.guess_dc_mode()
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)

        # as a final sanity-check, make sure the admin can still see the attr
        self.assert_conf_attr_searches(has_rights_to="all",
                                       samdb=self.ldb_admin)
        self.assert_attr_visible(expect_attr=True, samdb=self.ldb_admin)
        self.assert_negative_searches(has_rights_to="all",
                                      samdb=self.ldb_admin)

    def get_guid(self, dn):
        """Returns an object's GUID (in string format)"""
        res = self.ldb_admin.search(base=dn, attrs=["objectGUID"],
                                    scope=SCOPE_BASE)
        guid = res[0]['objectGUID'][0]
        return self.ldb_admin.schema_format_value("objectGUID", guid)

    def make_attr_preserve_on_delete(self):
        """Marks the attribute under test as being preserve on delete"""

        # work out the original 'searchFlags' value before we overwrite it
        search_flags = int(self.get_attr_search_flags(self.attr_dn))

        # check we've already set the confidential flag
        self.assertTrue(search_flags & SEARCH_FLAG_CONFIDENTIAL != 0)
        search_flags |= SEARCH_FLAG_PRESERVEONDELETE

        self.set_attr_search_flags(self.attr_dn, str(search_flags))

    def change_attr_under_test(self, attr_name, attr_cn):
        # change the attribute that the test code uses
        self.conf_attr = attr_name
        self.attr_dn = "{0},{1}".format(attr_cn, self.schema_dn)

        # set the new attribute for the user-under-test
        self.add_attr(self.conf_dn, self.conf_attr, self.conf_value)

        # 2 other users also have the attribute-under-test set (to a randomish
        # value). Set the new attribute for them now (normally this gets done
        # in the setUp())
        for username in self.all_users:
            if "other-user" in username:
                dn = self.get_user_dn(username)
                self.add_attr(dn, self.conf_attr, "xyz-blah")

    def test_search_with_dirsync_deleted_objects(self):
        """Checks dirsync doesn't reveal confidential info for deleted objs"""

        # change the attribute we're testing (we'll preserve on delete for this
        # test case, which means the attribute-under-test hangs around after
        # the test case finishes, and would interfere with the searches for
        # subsequent other test cases)
        self.change_attr_under_test("carLicense", "CN=carLicense")

        # Windows dirsync behaviour is a little strange when you request
        # attributes that deleted objects no longer have, so just request 'all
        # attributes' to simplify the test logic
        self.attr_filters = [None, ["*"]]

        # normally dirsync uses extra filters to exclude deleted objects that
        # we're not interested in. Override these filters so they WILL include
        # deleted objects, but only from this particular test run. We can do
        # this by matching lastKnownParent against this test case's OU, which
        # will match any deleted child objects.
        ou_guid = self.get_guid(self.ou)
        deleted_filter = "(lastKnownParent=<GUID={0}>)".format(ou_guid)

        # the extra-filter will get combined via AND with the search expression
        # we're testing, i.e. filter on the confidential attribute AND only
        # include non-deleted objects, OR deleted objects from this test run
        exclude_deleted_objs_filter = self.extra_filter
        self.extra_filter = "(|{0}{1})".format(exclude_deleted_objs_filter,
                                               deleted_filter)

        # for matching on a single object, the search expresseion becomes:
        # match exactly by account-name AND either a non-deleted object OR a
        # deleted object from this test run
        match_by_name = "(samaccountname={0})".format(self.conf_user)
        not_deleted = "(!(isDeleted=*))"
        self.single_obj_filter = "(&{0}(|{1}{2}))".format(match_by_name,
                                                          not_deleted,
                                                          deleted_filter)

        # check that the search filters work as expected
        self.assert_conf_attr_searches(has_rights_to="all")
        self.assert_attr_visible(expect_attr=True)
        self.assert_negative_searches(has_rights_to="all")

        # make the test attribute confidential *and* preserve on delete.
        self.make_attr_confidential()
        self.make_attr_preserve_on_delete()

        # check we can't see the objects now, even with using dirsync controls
        self.assert_conf_attr_searches(has_rights_to=0)
        self.assert_attr_visible(expect_attr=False)
        dc_mode = self.guess_dc_mode()
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)

        # now delete the users (except for the user whose LDB connection
        # we're currently using)
        for user in self.all_users:
            if user != self.user:
                self.ldb_admin.delete(self.get_user_dn(user))

        # check we still can't see the objects
        self.assert_conf_attr_searches(has_rights_to=0)
        self.assert_negative_searches(has_rights_to=0, dc_mode=dc_mode)

TestProgram(module=__name__, opts=subunitopts)
