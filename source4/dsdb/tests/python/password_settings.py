#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tests for Password Settings Objects.
#
# This also tests the default password complexity (i.e. pwdProperties),
# minPwdLength, pwdHistoryLength settings as a side-effect.
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018
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

#
# Usage:
#  export SERVER_IP=target_dc
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/dsdb/tests/python" $SUBUNITRUN \
#       password_settings -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import samba.tests
import ldb
from ldb import FLAG_MOD_DELETE, FLAG_MOD_ADD, FLAG_MOD_REPLACE
from samba import dsdb
import time
from samba.tests.password_test import PasswordTestCase
from samba.tests.pso import TestUser
from samba.tests.pso import PasswordSettings
from samba.tests import env_get_var_value
from samba.credentials import Credentials
from samba import gensec
import base64


class PasswordSettingsTestCase(PasswordTestCase):
    def setUp(self):
        super(PasswordSettingsTestCase, self).setUp()

        self.host_url = "ldap://%s" % env_get_var_value("SERVER_IP")
        self.ldb = samba.tests.connect_samdb(self.host_url)

        # create a temp OU to put this test's users into
        self.ou = samba.tests.create_test_ou(self.ldb, "password_settings")

        # update DC to allow password changes for the duration of this test
        self.allow_password_changes()

        # store the current password-settings for the domain
        self.pwd_defaults = PasswordSettings(None, self.ldb)
        self.test_objs = []

    def tearDown(self):
        super(PasswordSettingsTestCase, self).tearDown()

        # remove all objects under the top-level OU
        self.ldb.delete(self.ou, ["tree_delete:1"])

        # PSOs can't reside within an OU so they get cleaned up separately
        for obj in self.test_objs:
            self.ldb.delete(obj)

    def add_obj_cleanup(self, dn_list):
        """Handles cleanup of objects outside of the test OU in the tearDown"""
        self.test_objs.extend(dn_list)

    def add_group(self, group_name):
        """Creates a new group"""
        dn = "CN=%s,%s" % (group_name, self.ou)
        self.ldb.add({"dn": dn, "objectclass": "group"})
        return dn

    def set_attribute(self, dn, attr, value, operation=FLAG_MOD_ADD,
                      samdb=None):
        """Modifies an attribute for an object"""
        if samdb is None:
            samdb = self.ldb
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, dn)
        m[attr] = ldb.MessageElement(value, operation, attr)
        samdb.modify(m)

    def add_user(self, username):
        # add a new user to the DB under our top-level OU
        userou = "ou=%s" % self.ou.get_component_value(0)
        return TestUser(username, self.ldb, userou=userou)

    def assert_password_invalid(self, user, password):
        """
        Check we can't set a password that violates complexity or length
        constraints
        """
        try:
            user.set_password(password)
            # fail the test if no exception was encountered
            self.fail("Password '%s' should have been rejected" % password)
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ldb.ERR_CONSTRAINT_VIOLATION, msg)
            self.assertTrue('0000052D' in msg, msg)

    def assert_password_valid(self, user, password):
        """Checks that we can set a password successfully"""
        try:
            user.set_password(password)
        except ldb.LdbError as e:
            (num, msg) = e.args
            # fail the test (rather than throw an error)
            self.fail("Password '%s' unexpectedly rejected: %s" % (password,
                                                                   msg))

    def assert_PSO_applied(self, user, pso):
        """
        Asserts the expected PSO is applied by checking the msDS-ResultantPSO
        attribute, as well as checking the corresponding password-length,
        complexity, and history are enforced correctly
        """
        resultant_pso = user.get_resultant_PSO()
        self.assertTrue(resultant_pso == pso.dn,
                        "Expected PSO %s, not %s" % (pso.name,
                                                     str(resultant_pso)))

        # we're mirroring the pwd_history for the user, so make sure this is
        # up-to-date, before we start making password changes
        if user.last_pso:
            user.pwd_history_change(user.last_pso.history_len, pso.history_len)
        user.last_pso = pso

        # check if we can set a sufficiently long, but non-complex, password.
        # (We use the history-size to generate a unique password for each
        # assertion - otherwise, if the password is already in the history,
        # then it'll be rejected)
        unique_char = chr(ord('a') + len(user.all_old_passwords))
        noncomplex_pwd = "%cabcdefghijklmnopqrst" % unique_char

        if pso.complexity:
            self.assert_password_invalid(user, noncomplex_pwd)
        else:
            self.assert_password_valid(user, noncomplex_pwd)

        # use a unique and sufficiently complex base-string to check pwd-length
        pass_phrase = "%d#AaBbCcDdEeFfGgHhIi" % len(user.all_old_passwords)

        # check that passwords less than the specified length are rejected
        for i in range(3, pso.password_len):
            self.assert_password_invalid(user, pass_phrase[:i])

        # check we can set a password that's exactly the minimum length
        self.assert_password_valid(user, pass_phrase[:pso.password_len])

        # check the password history is enforced correctly.
        # first, check the last n items in the password history are invalid
        invalid_passwords = user.old_invalid_passwords(pso.history_len)
        for pwd in invalid_passwords:
            self.assert_password_invalid(user, pwd)

        # next, check any passwords older than the history-len can be re-used
        valid_passwords = user.old_valid_passwords(pso.history_len)
        for pwd in valid_passwords:
            self.assert_set_old_password(user, pwd, pso)

    def password_is_complex(self, password):
        # non-complex passwords used in the tests are all lower-case letters
        # If it's got a number in the password, assume it's complex
        return any(c.isdigit() for c in password)

    def assert_set_old_password(self, user, password, pso):
        """
        Checks a user password can be set (if the password conforms to the PSO
        settings). Used to check an old password that falls outside the history
        length, but might still be invalid for other reasons.
        """
        if self.password_is_complex(password):
            # check password conforms to length requirements
            if len(password) < pso.password_len:
                self.assert_password_invalid(user, password)
            else:
                self.assert_password_valid(user, password)
        else:
            # password is not complex, check PSO handles it appropriately
            if pso.complexity:
                self.assert_password_invalid(user, password)
            else:
                self.assert_password_valid(user, password)

    def test_pso_basics(self):
        """Simple tests that a PSO takes effect when applied to a group/user"""

        # create some PSOs that vary in priority and basic password-len
        best_pso = PasswordSettings("highest-priority-PSO", self.ldb,
                                    precedence=5, password_len=16,
                                    history_len=6)
        medium_pso = PasswordSettings("med-priority-PSO", self.ldb,
                                      precedence=15, password_len=10,
                                      history_len=4)
        worst_pso = PasswordSettings("lowest-priority-PSO", self.ldb,
                                     precedence=100, complexity=False,
                                     password_len=4, history_len=2)

        # handle PSO clean-up (as they're outside the top-level test OU)
        self.add_obj_cleanup([worst_pso.dn, medium_pso.dn, best_pso.dn])

        # create some groups and apply the PSOs to the groups
        group1 = self.add_group("Group-1")
        group2 = self.add_group("Group-2")
        group3 = self.add_group("Group-3")
        group4 = self.add_group("Group-4")
        worst_pso.apply_to(group1)
        medium_pso.apply_to(group2)
        best_pso.apply_to(group3)
        worst_pso.apply_to(group4)

        # create a user and check the default settings apply to it
        user = self.add_user("testuser")
        self.assert_PSO_applied(user, self.pwd_defaults)

        # add user to a group. Check that the group's PSO applies to the user
        self.set_attribute(group1, "member", user.dn)
        self.assert_PSO_applied(user, worst_pso)

        # add the user to a group with a higher precedence PSO and and check
        # that now trumps the previous PSO
        self.set_attribute(group2, "member", user.dn)
        self.assert_PSO_applied(user, medium_pso)

        # add the user to the remaining groups. The highest precedence PSO
        # should now take effect
        self.set_attribute(group3, "member", user.dn)
        self.set_attribute(group4, "member", user.dn)
        self.assert_PSO_applied(user, best_pso)

        # delete a group membership and check the PSO changes
        self.set_attribute(group3, "member", user.dn,
                           operation=FLAG_MOD_DELETE)
        self.assert_PSO_applied(user, medium_pso)

        # apply the low-precedence PSO directly to the user
        # (directly applied PSOs should trump higher precedence group PSOs)
        worst_pso.apply_to(user.dn)
        self.assert_PSO_applied(user, worst_pso)

        # remove applying the PSO directly to the user and check PSO changes
        worst_pso.unapply(user.dn)
        self.assert_PSO_applied(user, medium_pso)

        # remove all appliesTo and check we have the default settings again
        worst_pso.unapply(group1)
        medium_pso.unapply(group2)
        worst_pso.unapply(group4)
        self.assert_PSO_applied(user, self.pwd_defaults)

    def test_pso_nested_groups(self):
        """PSOs operate correctly when applied to nested groups"""

        # create some PSOs that vary in priority and basic password-len
        group1_pso = PasswordSettings("group1-PSO", self.ldb, precedence=50,
                                      password_len=12, history_len=3)
        group2_pso = PasswordSettings("group2-PSO", self.ldb, precedence=25,
                                      password_len=10, history_len=5,
                                      complexity=False)
        group3_pso = PasswordSettings("group3-PSO", self.ldb, precedence=10,
                                      password_len=6, history_len=2)

        # create some groups and apply the PSOs to the groups
        group1 = self.add_group("Group-1")
        group2 = self.add_group("Group-2")
        group3 = self.add_group("Group-3")
        group4 = self.add_group("Group-4")
        group1_pso.apply_to(group1)
        group2_pso.apply_to(group2)
        group3_pso.apply_to(group3)

        # create a PSO and apply it to a group that the user is not a member
        # of - it should not have any effect on the user
        unused_pso = PasswordSettings("unused-PSO", self.ldb, precedence=1,
                                      password_len=20)
        unused_pso.apply_to(group4)

        # handle PSO clean-up (as they're outside the top-level test OU)
        self.add_obj_cleanup([group1_pso.dn, group2_pso.dn, group3_pso.dn,
                              unused_pso.dn])

        # create a user and check the default settings apply to it
        user = self.add_user("testuser")
        self.assert_PSO_applied(user, self.pwd_defaults)

        # add user to a group. Check that the group's PSO applies to the user
        self.set_attribute(group1, "member", user.dn)
        self.set_attribute(group2, "member", group1)
        self.assert_PSO_applied(user, group2_pso)

        # add another level to the group heirachy & check this PSO takes effect
        self.set_attribute(group3, "member", group2)
        self.assert_PSO_applied(user, group3_pso)

        # invert the PSO precedence and check the new lowest value takes effect
        group1_pso.set_precedence(3)
        group2_pso.set_precedence(13)
        group3_pso.set_precedence(33)
        self.assert_PSO_applied(user, group1_pso)

        # delete a PSO and check it no longer applies
        self.ldb.delete(group1_pso.dn)
        self.test_objs.remove(group1_pso.dn)
        self.assert_PSO_applied(user, group2_pso)

    def get_guid(self, dn):
        res = self.ldb.search(base=dn, attrs=["objectGUID"],
                              scope=ldb.SCOPE_BASE)
        return res[0]['objectGUID'][0]

    def guid_string(self, guid):
        return self.ldb.schema_format_value("objectGUID", guid)

    def PSO_with_lowest_GUID(self, pso_list):
        """Returns the PSO object in the list with the lowest GUID"""
        # go through each PSO and fetch its GUID
        guid_list = []
        mapping = {}
        for pso in pso_list:
            guid = self.get_guid(pso.dn)
            guid_list.append(guid)
            # remember which GUID maps to what PSO
            mapping[guid] = pso

        # sort the GUID list to work out the lowest/best GUID
        guid_list.sort()
        best_guid = guid_list[0]

        # sanity-check the mapping between GUID and DN is correct
        best_pso_dn = mapping[best_guid].dn
        self.assertEqual(self.guid_string(self.get_guid(best_pso_dn)),
                         self.guid_string(best_guid))

        # return the PSO that this GUID corresponds to
        return mapping[best_guid]

    def test_pso_equal_precedence(self):
        """Tests expected PSO wins when several have the same precedence"""

        # create some PSOs that vary in priority and basic password-len
        pso1 = PasswordSettings("PSO-1", self.ldb, precedence=5, history_len=1,
                                password_len=11)
        pso2 = PasswordSettings("PSO-2", self.ldb, precedence=5, history_len=2,
                                password_len=8)
        pso3 = PasswordSettings("PSO-3", self.ldb, precedence=5, history_len=3,
                                password_len=5, complexity=False)
        pso4 = PasswordSettings("PSO-4", self.ldb, precedence=5, history_len=4,
                                password_len=13, complexity=False)

        # handle PSO clean-up (as they're outside the top-level test OU)
        self.add_obj_cleanup([pso1.dn, pso2.dn, pso3.dn, pso4.dn])

        # create some groups and apply the PSOs to the groups
        group1 = self.add_group("Group-1")
        group2 = self.add_group("Group-2")
        group3 = self.add_group("Group-3")
        group4 = self.add_group("Group-4")
        pso1.apply_to(group1)
        pso2.apply_to(group2)
        pso3.apply_to(group3)
        pso4.apply_to(group4)

        # create a user and check the default settings apply to it
        user = self.add_user("testuser")
        self.assert_PSO_applied(user, self.pwd_defaults)

        # add the user to all the groups
        self.set_attribute(group1, "member", user.dn)
        self.set_attribute(group2, "member", user.dn)
        self.set_attribute(group3, "member", user.dn)
        self.set_attribute(group4, "member", user.dn)

        # precedence is equal, so the PSO with lowest GUID gets applied
        pso_list = [pso1, pso2, pso3, pso4]
        best_pso = self.PSO_with_lowest_GUID(pso_list)
        self.assert_PSO_applied(user, best_pso)

        # excluding the winning PSO, apply the other PSOs directly to the user
        pso_list.remove(best_pso)
        for pso in pso_list:
            pso.apply_to(user.dn)

        # we should now have a different PSO applied (the 2nd lowest GUID)
        next_best_pso = self.PSO_with_lowest_GUID(pso_list)
        self.assertTrue(next_best_pso is not best_pso)
        self.assert_PSO_applied(user, next_best_pso)

        # bump the precedence of another PSO and it should now win
        pso_list.remove(next_best_pso)
        best_pso = pso_list[0]
        best_pso.set_precedence(4)
        self.assert_PSO_applied(user, best_pso)

    def test_pso_invalid_location(self):
        """Tests that PSOs in an invalid location have no effect"""

        # PSOs should only be able to be created within a Password Settings
        # Container object. Trying to create one under an OU should fail
        try:
            rogue_pso = PasswordSettings("rogue-PSO", self.ldb, precedence=1,
                                         complexity=False, password_len=20,
                                         container=self.ou)
            self.fail()
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ldb.ERR_NAMING_VIOLATION, msg)
            # Windows returns 2099 (Illegal superior), Samba returns 2037
            # (Naming violation - "not a valid child class")
            self.assertTrue('00002099' in msg or '00002037' in msg, msg)

        # we can't create Password Settings Containers under an OU either
        try:
            rogue_psc = "CN=Rogue-PSO-container,%s" % self.ou
            self.ldb.add({"dn": rogue_psc,
                          "objectclass": "msDS-PasswordSettingsContainer"})
            self.fail()
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ldb.ERR_NAMING_VIOLATION, msg)
            self.assertTrue('00002099' in msg or '00002037' in msg, msg)

        base_dn = self.ldb.get_default_basedn()
        rogue_psc = "CN=Rogue-PSO-container,CN=Computers,%s" % base_dn
        self.ldb.add({"dn": rogue_psc,
                      "objectclass": "msDS-PasswordSettingsContainer"})

        rogue_pso = PasswordSettings("rogue-PSO", self.ldb, precedence=1,
                                     container=rogue_psc, password_len=20)
        self.add_obj_cleanup([rogue_pso.dn, rogue_psc])

        # apply the PSO to a group and check it has no effect on the user
        user = self.add_user("testuser")
        group = self.add_group("Group-1")
        rogue_pso.apply_to(group)
        self.set_attribute(group, "member", user.dn)
        self.assert_PSO_applied(user, self.pwd_defaults)

        # apply the PSO directly to the user and check it has no effect
        rogue_pso.apply_to(user.dn)
        self.assert_PSO_applied(user, self.pwd_defaults)

    # the PSOs created in these test-cases all use a default min-age of zero.
    # This is the only test case that checks the PSO's min-age is enforced
    def test_pso_min_age(self):
        """Tests that a PSO's min-age is enforced"""
        pso = PasswordSettings("min-age-PSO", self.ldb, password_len=10,
                               password_age_min=2, complexity=False)
        self.add_obj_cleanup([pso.dn])

        # create a user and apply the PSO
        user = self.add_user("testuser")
        pso.apply_to(user.dn)
        self.assertTrue(user.get_resultant_PSO() == pso.dn)

        # changing the password immediately should fail, even if the password
        # is valid
        valid_password = "min-age-passwd"
        self.assert_password_invalid(user, valid_password)
        # then trying the same password later should succeed
        time.sleep(pso.password_age_min + 0.5)
        self.assert_password_valid(user, valid_password)

    def test_pso_max_age(self):
        """Tests that a PSO's max-age is used"""

        # create PSOs that use the domain's max-age +/- 1 day
        domain_max_age = self.pwd_defaults.password_age_max
        day_in_secs = 60 * 60 * 24
        higher_max_age = domain_max_age + day_in_secs
        lower_max_age = domain_max_age - day_in_secs
        longer_pso = PasswordSettings("longer-age-PSO", self.ldb, precedence=5,
                                      password_age_max=higher_max_age)
        shorter_pso = PasswordSettings("shorter-age-PSO", self.ldb,
                                       precedence=1,
                                       password_age_max=lower_max_age)
        self.add_obj_cleanup([longer_pso.dn, shorter_pso.dn])

        user = self.add_user("testuser")

        # we can't wait around long enough for the max-age to expire, so
        # instead just check the msDS-UserPasswordExpiryTimeComputed for
        # the user
        attrs = ['msDS-UserPasswordExpiryTimeComputed']
        res = self.ldb.search(user.dn, attrs=attrs)
        domain_expiry = int(res[0]['msDS-UserPasswordExpiryTimeComputed'][0])

        # apply the longer PSO and check the expiry-time becomes longer
        longer_pso.apply_to(user.dn)
        self.assertTrue(user.get_resultant_PSO() == longer_pso.dn)
        res = self.ldb.search(user.dn, attrs=attrs)
        new_expiry = int(res[0]['msDS-UserPasswordExpiryTimeComputed'][0])

        # use timestamp diff of 1 day - 1 minute. The new expiry should still
        # be greater than this, without getting into nano-second granularity
        approx_timestamp_diff = (day_in_secs - 60) * (1e7)
        self.assertTrue(new_expiry > domain_expiry + approx_timestamp_diff)

        # apply the shorter PSO and check the expiry-time is shorter
        shorter_pso.apply_to(user.dn)
        self.assertTrue(user.get_resultant_PSO() == shorter_pso.dn)
        res = self.ldb.search(user.dn, attrs=attrs)
        new_expiry = int(res[0]['msDS-UserPasswordExpiryTimeComputed'][0])
        self.assertTrue(new_expiry < domain_expiry - approx_timestamp_diff)

    def test_pso_special_groups(self):
        """Checks applying a PSO to built-in AD groups takes effect"""

        # create some PSOs that will apply to special groups
        default_pso = PasswordSettings("default-PSO", self.ldb, precedence=20,
                                       password_len=8, complexity=False)
        guest_pso = PasswordSettings("guest-PSO", self.ldb, history_len=4,
                                     precedence=5, password_len=5)
        builtin_pso = PasswordSettings("builtin-PSO", self.ldb, history_len=9,
                                       precedence=1, password_len=9)
        admin_pso = PasswordSettings("admin-PSO", self.ldb, history_len=0,
                                     precedence=2, password_len=10)
        self.add_obj_cleanup([default_pso.dn, guest_pso.dn, admin_pso.dn,
                              builtin_pso.dn])
        base_dn = self.ldb.domain_dn()
        domain_users = "CN=Domain Users,CN=Users,%s" % base_dn
        domain_guests = "CN=Domain Guests,CN=Users,%s" % base_dn
        admin_users = "CN=Domain Admins,CN=Users,%s" % base_dn

        # if we apply a PSO to Domain Users (which all users are a member of)
        # then that PSO should take effect on a new user
        default_pso.apply_to(domain_users)
        user = self.add_user("testuser")
        self.assert_PSO_applied(user, default_pso)

        # Apply a PSO to a builtin group. 'Domain Users' should be a member of
        # Builtin/Users, but builtin groups should be excluded from the PSO
        # calculation, so this should have no effect
        builtin_pso.apply_to("CN=Users,CN=Builtin,%s" % base_dn)
        builtin_pso.apply_to("CN=Administrators,CN=Builtin,%s" % base_dn)
        self.assert_PSO_applied(user, default_pso)

        # change the user's primary group to another group (the primaryGroupID
        # is a little odd in that there's no memberOf backlink for it)
        self.set_attribute(domain_guests, "member", user.dn)
        user.set_primary_group(domain_guests)
        # No PSO is applied to the Domain Guests yet, so the default PSO should
        # still apply
        self.assert_PSO_applied(user, default_pso)

        # now apply a PSO to the guests group, which should trump the default
        # PSO (because the guest PSO has a better precedence)
        guest_pso.apply_to(domain_guests)
        self.assert_PSO_applied(user, guest_pso)

        # create a new group that's a member of Admin Users
        nested_group = self.add_group("nested-group")
        self.set_attribute(admin_users, "member", nested_group)
        # set the user's primary-group to be the new group
        self.set_attribute(nested_group, "member", user.dn)
        user.set_primary_group(nested_group)
        # we've only changed group membership so far, not the PSO
        self.assert_PSO_applied(user, guest_pso)

        # now apply the best-precedence PSO to Admin Users and check it applies
        # to the user (via the nested-group's membership)
        admin_pso.apply_to(admin_users)
        self.assert_PSO_applied(user, admin_pso)

        # restore the default primaryGroupID so we can safely delete the group
        user.set_primary_group(domain_users)

    def test_pso_none_applied(self):
        """Tests cases where no Resultant PSO should be returned"""

        # create a PSO that we will check *doesn't* get returned
        dummy_pso = PasswordSettings("dummy-PSO", self.ldb, password_len=20)
        self.add_obj_cleanup([dummy_pso.dn])

        # you can apply a PSO to other objects (like OUs), but the resultantPSO
        # attribute should only be returned for users
        dummy_pso.apply_to(str(self.ou))
        res = self.ldb.search(self.ou, attrs=['msDS-ResultantPSO'])
        self.assertFalse('msDS-ResultantPSO' in res[0])

        # create a dummy user and apply the PSO
        user = self.add_user("testuser")
        dummy_pso.apply_to(user.dn)
        self.assertTrue(user.get_resultant_PSO() == dummy_pso.dn)

        # now clear the ADS_UF_NORMAL_ACCOUNT flag for the user, which should
        # mean a resultant PSO is no longer returned (we're essentially turning
        # the user into a DC here, which is a little overkill but tests
        # behaviour as per the Windows specification)
        self.set_attribute(user.dn, "userAccountControl",
                           str(dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                           operation=FLAG_MOD_REPLACE)
        self.assertIsNone(user.get_resultant_PSO())

        # reset it back to a normal user account
        self.set_attribute(user.dn, "userAccountControl",
                           str(dsdb.UF_NORMAL_ACCOUNT),
                           operation=FLAG_MOD_REPLACE)
        self.assertTrue(user.get_resultant_PSO() == dummy_pso.dn)

        # no PSO should be returned if RID is equal to DOMAIN_USER_RID_KRBTGT
        # (note this currently fails against Windows due to a Windows bug)
        krbtgt_user = "CN=krbtgt,CN=Users,%s" % self.ldb.domain_dn()
        dummy_pso.apply_to(krbtgt_user)
        res = self.ldb.search(krbtgt_user, attrs=['msDS-ResultantPSO'])
        self.assertFalse('msDS-ResultantPSO' in res[0])

    def get_ldb_connection(self, username, password, ldaphost):
        """Returns an LDB connection using the specified user's credentials"""
        creds = self.get_credentials()
        creds_tmp = Credentials()
        creds_tmp.set_username(username)
        creds_tmp.set_password(password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        features = creds_tmp.get_gensec_features() | gensec.FEATURE_SEAL
        creds_tmp.set_gensec_features(features)
        return samba.tests.connect_samdb(ldaphost, credentials=creds_tmp)

    def test_pso_permissions(self):
        """Checks that regular users can't modify/view PSO objects"""

        user = self.add_user("testuser")

        # get an ldb connection with the new user's privileges
        user_ldb = self.get_ldb_connection("testuser", user.get_password(),
                                           self.host_url)

        # regular users should not be able to create a PSO (at least, not in
        # the default Password Settings container)
        try:
            priv_pso = PasswordSettings("priv-PSO", user_ldb, password_len=20)
            self.fail()
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, msg)

        # create a PSO as the admin user
        priv_pso = PasswordSettings("priv-PSO", self.ldb, password_len=20)
        self.add_obj_cleanup([priv_pso.dn])

        # regular users should not be able to apply a PSO to a user
        try:
            self.set_attribute(priv_pso.dn, "msDS-PSOAppliesTo", user.dn,
                               samdb=user_ldb)
            self.fail()
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, msg)
            self.assertTrue('00002098' in msg, msg)

        self.set_attribute(priv_pso.dn, "msDS-PSOAppliesTo", user.dn,
                           samdb=self.ldb)

        # regular users should not be able to change a PSO's precedence
        try:
            priv_pso.set_precedence(100, samdb=user_ldb)
            self.fail()
        except ldb.LdbError as e:
            (num, msg) = e.args
            self.assertEqual(num, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, msg)
            self.assertTrue('00002098' in msg, msg)

        priv_pso.set_precedence(100, samdb=self.ldb)

        # regular users should not be able to view a PSO's settings
        pso_attrs = ["msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence",
                     "msDS-PasswordHistoryLength", "msDS-LockoutThreshold",
                     "msDS-PasswordComplexityEnabled"]

        # users can see the PSO object's DN, but not its attributes
        res = user_ldb.search(priv_pso.dn, scope=ldb.SCOPE_BASE,
                              attrs=pso_attrs)
        self.assertTrue(str(priv_pso.dn) == str(res[0].dn))
        for attr in pso_attrs:
            self.assertFalse(attr in res[0])

        # whereas admin users can see everything
        res = self.ldb.search(priv_pso.dn, scope=ldb.SCOPE_BASE,
                              attrs=pso_attrs)
        for attr in pso_attrs:
            self.assertTrue(attr in res[0])

        # check replace/delete operations can't be performed by regular users
        operations = [FLAG_MOD_REPLACE, FLAG_MOD_DELETE]

        for oper in operations:
            try:
                self.set_attribute(priv_pso.dn, "msDS-PSOAppliesTo", user.dn,
                                   samdb=user_ldb, operation=oper)
                self.fail()
            except ldb.LdbError as e:
                (num, msg) = e.args
                self.assertEqual(num, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS, msg)
                self.assertTrue('00002098' in msg, msg)

            # ...but can be performed by the admin user
            self.set_attribute(priv_pso.dn, "msDS-PSOAppliesTo", user.dn,
                               samdb=self.ldb, operation=oper)

    def format_password_for_ldif(self, password):
        """Encodes/decodes the password so that it's accepted in an LDIF"""
        pwd = '"{0}"'.format(password)
        return base64.b64encode(pwd.encode('utf-16-le')).decode('utf8')

    # The 'user add' case is a bit more complicated as you can't really query
    # the msDS-ResultantPSO attribute on a user that doesn't exist yet (it
    # won't have any group membership or PSOs applied directly against it yet).
    # In theory it's possible to still get an applicable PSO via the user's
    # primaryGroupID (i.e. 'Domain Users' by default). However, testing aginst
    # Windows shows that the PSO doesn't take effect during the user add
    # operation. (However, the Windows GUI tools presumably adds the user in 2
    # steps, because it does enforce the PSO for users added via the GUI).
    def test_pso_add_user(self):
        """Tests against a 'Domain Users' PSO taking effect on a new user"""

        # create a PSO that will apply to users by default
        default_pso = PasswordSettings("default-PSO", self.ldb, precedence=20,
                                       password_len=12, complexity=False)
        self.add_obj_cleanup([default_pso.dn])

        # apply the PSO to Domain Users (which all users are a member of). In
        # theory, this PSO *could* take effect on a new user (but it doesn't)
        domain_users = "CN=Domain Users,CN=Users,%s" % self.ldb.domain_dn()
        default_pso.apply_to(domain_users)

        # first try to add a user with a password that doesn't meet the domain
        # defaults, to prove that the DC will reject bad passwords during a
        # user add
        userdn = "CN=testuser,%s" % self.ou
        password = self.format_password_for_ldif('abcdef')

        # Note we use an LDIF operation to ensure that the password gets set
        # as part of the 'add' operation (whereas self.add_user() adds the user
        # first, then sets the password later in a 2nd step)
        try:
            ldif = """
dn: %s
objectClass: user
sAMAccountName: testuser
unicodePwd:: %s
""" % (userdn, password)
            self.ldb.add_ldif(ldif)
            self.fail()
        except ldb.LdbError as e:
                (num, msg) = e.args
                # error codes differ between Samba and Windows
                self.assertTrue(num == ldb.ERR_UNWILLING_TO_PERFORM or
                                num == ldb.ERR_CONSTRAINT_VIOLATION, msg)
                self.assertTrue('0000052D' in msg, msg)

        # now use a password that meets the domain defaults, but doesn't meet
        # the PSO requirements. Note that Windows allows this, i.e. it doesn't
        # honour the PSO during the add operation
        password = self.format_password_for_ldif('abcde12#')
        ldif = """
dn: %s
objectClass: user
sAMAccountName: testuser
unicodePwd:: %s
""" % (userdn, password)
        self.ldb.add_ldif(ldif)

        # Now do essentially the same thing, but set the password in a 2nd step
        # which proves that the same password doesn't meet the PSO requirements
        userdn = "CN=testuser2,%s" % self.ou
        ldif = """
dn: %s
objectClass: user
sAMAccountName: testuser2
""" % userdn
        self.ldb.add_ldif(ldif)

        # now that the user exists, assert that the PSO is honoured
        try:
            ldif = """
dn: %s
changetype: modify
delete: unicodePwd
add: unicodePwd
unicodePwd:: %s
""" % (userdn, password)
            self.ldb.modify_ldif(ldif)
            self.fail()
        except ldb.LdbError as e:
                (num, msg) = e.args
                self.assertEqual(num, ldb.ERR_CONSTRAINT_VIOLATION, msg)
                self.assertTrue('0000052D' in msg, msg)

        # check setting a password that meets the PSO settings works
        password = self.format_password_for_ldif('abcdefghijkl')
        ldif = """
dn: %s
changetype: modify
delete: unicodePwd
add: unicodePwd
unicodePwd:: %s
""" % (userdn, password)
        self.ldb.modify_ldif(ldif)

    def set_domain_pwdHistoryLength(self, value):
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, self.ldb.domain_dn())
        m["pwdHistoryLength"] = ldb.MessageElement(value,
                                                   ldb.FLAG_MOD_REPLACE,
                                                   "pwdHistoryLength")
        self.ldb.modify(m)

    def test_domain_pwd_history(self):
        """Non-PSO test for domain's pwdHistoryLength setting"""

        # restore the current pwdHistoryLength setting after the test completes
        curr_hist_len = str(self.pwd_defaults.history_len)
        self.addCleanup(self.set_domain_pwdHistoryLength, curr_hist_len)

        self.set_domain_pwdHistoryLength("4")
        user = self.add_user("testuser")

        initial_pwd = user.get_password()
        passwords = ["First12#", "Second12#", "Third12#", "Fourth12#"]

        # we should be able to set the password to new values OK
        for pwd in passwords:
            self.assert_password_valid(user, pwd)

        # the 2nd time round it should fail because they're in the history now
        for pwd in passwords:
            self.assert_password_invalid(user, pwd)

        # but the initial password is now outside the history, so should be OK
        self.assert_password_valid(user, initial_pwd)

        # if we set the history to zero, all the old passwords should now be OK
        self.set_domain_pwdHistoryLength("0")
        for pwd in passwords:
            self.assert_password_valid(user, pwd)

    def test_domain_pwd_history_zero(self):
        """Non-PSO test for pwdHistoryLength going from zero to non-zero"""

        # restore the current pwdHistoryLength setting after the test completes
        curr_hist_len = str(self.pwd_defaults.history_len)
        self.addCleanup(self.set_domain_pwdHistoryLength, curr_hist_len)

        self.set_domain_pwdHistoryLength("0")
        user = self.add_user("testuser")

        self.assert_password_valid(user, "NewPwd12#")
        # we can set the exact same password again because there's no history
        self.assert_password_valid(user, "NewPwd12#")

        # There is a difference in behaviour here between Windows and Samba.
        # When going from zero to non-zero password-history, Windows treats
        # the current user's password as invalid (even though the password has
        # not been altered since the setting changed). Whereas Samba accepts
        # the current password (because it's not in the history until the
        # *next* time the user's password changes.
        self.set_domain_pwdHistoryLength("1")
        self.assert_password_invalid(user, "NewPwd12#")
