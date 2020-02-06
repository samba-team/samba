# Test 'samba-tool domain passwordsettings' sub-commands
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

import os
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba.tests.pso import PasswordSettings, TestUser


class PwdSettingsCmdTestCase(SambaToolCmdTest):
    """Tests for 'samba-tool domain passwordsettings' subcommands"""

    def setUp(self):
        super(PwdSettingsCmdTestCase, self).setUp()
        self.server = "ldap://%s" % os.environ["DC_SERVER"]
        self.user_auth = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                       os.environ["DC_PASSWORD"])
        self.ldb = self.getSamDB("-H", self.server, self.user_auth)
        system_dn = "CN=System,%s" % self.ldb.domain_dn()
        self.pso_container = "CN=Password Settings Container,%s" % system_dn
        self.obj_cleanup = []

    def tearDown(self):
        super(PwdSettingsCmdTestCase, self).tearDown()
        # clean-up any objects the test has created
        for dn in self.obj_cleanup:
            self.ldb.delete(dn)

    def check_pso(self, pso_name, pso):
        """Checks the PSO info in the DB matches what's expected"""

        # lookup the PSO in the DB
        dn = "CN=%s,%s" % (pso_name, self.pso_container)
        pso_attrs = ['name', 'msDS-PasswordSettingsPrecedence',
                     'msDS-PasswordReversibleEncryptionEnabled',
                     'msDS-PasswordHistoryLength',
                     'msDS-MinimumPasswordLength',
                     'msDS-PasswordComplexityEnabled',
                     'msDS-MinimumPasswordAge',
                     'msDS-MaximumPasswordAge',
                     'msDS-LockoutObservationWindow',
                     'msDS-LockoutThreshold', 'msDS-LockoutDuration']
        res = self.ldb.search(dn, scope=ldb.SCOPE_BASE, attrs=pso_attrs)
        self.assertEqual(len(res), 1, "PSO lookup failed")

        # convert types in the PSO-settings to what the search returns, i.e.
        # boolean --> string, seconds --> timestamps in -100 nanosecond units
        complexity_str = "TRUE" if pso.complexity else "FALSE"
        plaintext_str = "TRUE" if pso.store_plaintext else "FALSE"
        lockout_duration = -int(pso.lockout_duration * (1e7))
        lockout_window = -int(pso.lockout_window * (1e7))
        min_age = -int(pso.password_age_min * (1e7))
        max_age = -int(pso.password_age_max * (1e7))

        # check the PSO's settings match the search results
        self.assertEqual(str(res[0]['msDS-PasswordComplexityEnabled'][0]),
                          complexity_str)
        plaintext_res = res[0]['msDS-PasswordReversibleEncryptionEnabled'][0]
        self.assertEqual(str(plaintext_res), plaintext_str)
        self.assertEqual(int(res[0]['msDS-PasswordHistoryLength'][0]),
                          pso.history_len)
        self.assertEqual(int(res[0]['msDS-MinimumPasswordLength'][0]),
                          pso.password_len)
        self.assertEqual(int(res[0]['msDS-MinimumPasswordAge'][0]), min_age)
        self.assertEqual(int(res[0]['msDS-MaximumPasswordAge'][0]), max_age)
        self.assertEqual(int(res[0]['msDS-LockoutObservationWindow'][0]),
                          lockout_window)
        self.assertEqual(int(res[0]['msDS-LockoutDuration'][0]),
                          lockout_duration)
        self.assertEqual(int(res[0]['msDS-LockoutThreshold'][0]),
                          pso.lockout_attempts)
        self.assertEqual(int(res[0]['msDS-PasswordSettingsPrecedence'][0]),
                          pso.precedence)

        # check we can also display the PSO via the show command
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "show"), pso_name,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertTrue(len(out.split(":")) >= 10,
                        "Expect 10 fields displayed")

        # for a few settings, sanity-check the display is what we expect
        self.assertIn("Minimum password length: %u" % pso.password_len, out)
        self.assertIn("Password history length: %u" % pso.history_len, out)
        lockout_str = "lockout threshold (attempts): %u" % pso.lockout_attempts
        self.assertIn(lockout_str, out)

    def test_pso_create(self):
        """Tests basic PSO creation using the samba-tool"""

        # we expect the PSO to take the current domain settings by default
        # (we'll set precedence/complexity, the rest should be the defaults)
        expected_pso = PasswordSettings(None, self.ldb)
        expected_pso.complexity = False
        expected_pso.precedence = 100

        # check basic PSO creation works
        pso_name = "test-create-PSO"
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "create"), pso_name,
                                                 "100", "--complexity=off",
                                                 "-H", self.server,
                                                 self.user_auth)
        # make sure we clean-up after the test completes
        self.obj_cleanup.append("CN=%s,%s" % (pso_name, self.pso_container))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("successfully created", out)
        self.check_pso(pso_name, expected_pso)

        # check creating a PSO with the same name fails
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "create"), pso_name,
                                                 "100", "--complexity=off",
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdFail(result, "Ensure that create for existing PSO fails")
        self.assertIn("already exists", err)

        # check we need to specify at least one password policy argument
        pso_name = "test-create-PSO2"
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "create"), pso_name,
                                                 "100", "-H", self.server,
                                                 self.user_auth)
        self.assertCmdFail(result, "Ensure that create for existing PSO fails")
        self.assertIn("specify at least one password policy setting", err)

        # create a PSO with different settings and check they match
        expected_pso.complexity = True
        expected_pso.store_plaintext = True
        expected_pso.precedence = 50
        expected_pso.password_len = 12
        day_in_secs = 60 * 60 * 24
        expected_pso.password_age_min = 11 * day_in_secs
        expected_pso.password_age_max = 50 * day_in_secs

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "create"), pso_name,
                                                 "50", "--complexity=on",
                                                 "--store-plaintext=on",
                                                 "--min-pwd-length=12",
                                                 "--min-pwd-age=11",
                                                 "--max-pwd-age=50",
                                                 "-H", self.server,
                                                 self.user_auth)
        self.obj_cleanup.append("CN=%s,%s" % (pso_name, self.pso_container))
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("successfully created", out)
        self.check_pso(pso_name, expected_pso)

        # check the PSOs we created are present in the 'list' command
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "list"),
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertIn("test-create-PSO", out)
        self.assertIn("test-create-PSO2", out)

    def _create_pso(self, pso_name):
        """Creates a PSO for use in other tests"""
        # the new PSO will take the current domain settings by default
        pso_settings = PasswordSettings(None, self.ldb)
        pso_settings.name = pso_name
        pso_settings.password_len = 10
        pso_settings.precedence = 200

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "create"), pso_name,
                                                 "200", "--min-pwd-length=10",
                                                 "-H", self.server,
                                                 self.user_auth)
        # make sure we clean-up after the test completes
        pso_settings.dn = "CN=%s,%s" % (pso_name, self.pso_container)
        self.obj_cleanup.append(pso_settings.dn)

        # sanity-check the cmd was successful
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("successfully created", out)
        self.check_pso(pso_name, pso_settings)

        return pso_settings

    def test_pso_set(self):
        """Tests we can modify a PSO using the samba-tool"""

        pso_name = "test-set-PSO"
        pso_settings = self._create_pso(pso_name)

        # check we can update a PSO's settings
        pso_settings.precedence = 99
        pso_settings.lockout_attempts = 10
        pso_settings.lockout_duration = 60 * 17
        (res, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                              "pso", "set"), pso_name,
                                              "--precedence=99",
                                              "--account-lockout-threshold=10",
                                              "--account-lockout-duration=17",
                                              "-H", self.server,
                                              self.user_auth)
        self.assertCmdSuccess(res, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("Successfully updated", out)

        # check the PSO's settings now reflect the new values
        self.check_pso(pso_name, pso_settings)

    def test_pso_delete(self):
        """Tests we can delete a PSO using the samba-tool"""

        pso_name = "test-delete-PSO"
        self._create_pso(pso_name)

        # check we can successfully delete the PSO
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "delete"), pso_name,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("Deleted PSO", out)
        dn = "CN=%s,%s" % (pso_name, self.pso_container)
        self.obj_cleanup.remove(dn)

        # check the object no longer exists in the DB
        try:
            self.ldb.search(dn, scope=ldb.SCOPE_BASE, attrs=['name'])
            self.fail("PSO shouldn't exist")
        except ldb.LdbError as e:
            (enum, estr) = e.args
            self.assertEqual(enum, ldb.ERR_NO_SUCH_OBJECT)

        # run the same cmd again - it should fail because PSO no longer exists
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "delete"), pso_name,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdFail(result, "Deleteing a non-existent PSO should fail")
        self.assertIn("Unable to find PSO", err)

    def check_pso_applied(self, user, pso):
        """Checks that the correct PSO is applied to a given user"""

        # first check the samba-tool output tells us the correct PSO is applied
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "show-user"),
                                                 user.name, "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        if pso is None:
            self.assertIn("No PSO applies to user", out)
        else:
            self.assertIn(pso.name, out)

        # then check the DB tells us the same thing
        if pso is None:
            self.assertEqual(user.get_resultant_PSO(), None)
        else:
            self.assertEqual(user.get_resultant_PSO(), pso.dn)

    def test_pso_apply_to_user(self):
        """Checks we can apply/unapply a PSO to a user"""

        pso_name = "test-apply-PSO"
        test_pso = self._create_pso(pso_name)

        # check that a new user has no PSO applied by default
        user = TestUser("test-PSO-user", self.ldb)
        self.obj_cleanup.append(user.dn)
        self.check_pso_applied(user, pso=None)

        # add the user to a new group
        group_name = "test-PSO-group"
        dn = "CN=%s,%s" % (group_name, self.ldb.domain_dn())
        self.ldb.add({"dn": dn, "objectclass": "group",
                      "sAMAccountName": group_name})
        self.obj_cleanup.append(dn)
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, dn)
        m["member"] = ldb.MessageElement(user.dn, ldb.FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # check samba-tool can successfully link a PSO to a group
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "apply"), pso_name,
                                                 group_name, "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.check_pso_applied(user, pso=test_pso)

        # we should fail if we try to apply the same PSO/group twice though
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "apply"), pso_name,
                                                 group_name, "-H", self.server,
                                                 self.user_auth)
        self.assertCmdFail(result, "Shouldn't be able to apply PSO twice")
        self.assertIn("already applies", err)

        # check samba-tool can successfully link a PSO to a user
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "apply"), pso_name,
                                                 user.name, "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.check_pso_applied(user, pso=test_pso)

        # check samba-tool can successfully unlink a group from a PSO
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "unapply"), pso_name,
                                                 group_name, "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        # PSO still applies directly to the user, even though group was removed
        self.check_pso_applied(user, pso=test_pso)

        # check samba-tool can successfully unlink a user from a PSO
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "unapply"), pso_name,
                                                 user.name, "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.check_pso_applied(user, pso=None)

    def test_pso_unpriv(self):
        """Checks unprivileged users can't modify PSOs via samba-tool"""

        # create a dummy PSO and a non-admin user
        pso_name = "test-unpriv-PSO"
        self._create_pso(pso_name)
        user = TestUser("test-unpriv-user", self.ldb)
        self.obj_cleanup.append(user.dn)
        unpriv_auth = "-U%s%%%s" % (user.name, user.get_password())

        # check we need admin privileges to be able to do anything to PSOs
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "set"), pso_name,
                                                 "--complexity=off", "-H",
                                                 self.server, unpriv_auth)
        self.assertCmdFail(result, "Need admin privileges to modify PSO")
        self.assertIn("You may not have permission", err)

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "create"), "bad-perm",
                                                 "250", "--complexity=off",
                                                 "-H", self.server,
                                                 unpriv_auth)
        self.assertCmdFail(result, "Need admin privileges to modify PSO")
        self.assertIn("Administrator permissions are needed", err)

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "delete"), pso_name,
                                                 "-H", self.server,
                                                 unpriv_auth)
        self.assertCmdFail(result, "Need admin privileges to delete PSO")
        self.assertIn("You may not have permission", err)

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "show"), pso_name,
                                                 "-H", self.server,
                                                 unpriv_auth)
        self.assertCmdFail(result, "Need admin privileges to view PSO")
        self.assertIn("You may not have permission", err)

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "apply"), pso_name,
                                                 user.name, "-H", self.server,
                                                 unpriv_auth)
        self.assertCmdFail(result, "Need admin privileges to modify PSO")
        self.assertIn("You may not have permission", err)

        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "unapply"), pso_name,
                                                 user.name, "-H", self.server,
                                                 unpriv_auth)
        self.assertCmdFail(result, "Need admin privileges to modify PSO")
        self.assertIn("You may not have permission", err)

        # The 'list' command actually succeeds because it's not easy to tell
        # whether we got no results due to lack of permissions, or because
        # there were no PSOs to display
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "pso", "list"), "-H",
                                                 self.server, unpriv_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertIn("No PSOs", out)
        self.assertIn("permission", out)

    def test_domain_passwordsettings(self):
        """Checks the 'set/show' commands for the domain settings (non-PSO)"""

        # check the 'show' cmd for the domain settings
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "show"), "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")

        # check an arbitrary setting is displayed correctly
        min_pwd_len = self.ldb.get_minPwdLength()
        self.assertIn("Minimum password length: %s" % min_pwd_len, out)

        # check we can change the domain setting
        self.addCleanup(self.ldb.set_minPwdLength, min_pwd_len)
        new_len = int(min_pwd_len) + 3
        min_pwd_args = "--min-pwd-length=%u" % new_len
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "set"), min_pwd_args,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("successful", out)
        self.assertEqual(new_len, self.ldb.get_minPwdLength())

        # check the updated value is now displayed
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "show"), "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("Minimum password length: %u" % new_len, out)

    def test_domain_passwordsettings_pwdage(self):
        """Checks the 'set' command for the domain password age (non-PSO)"""

        # check we can set the domain max password age
        max_pwd_age = self.ldb.get_maxPwdAge()
        self.addCleanup(self.ldb.set_maxPwdAge, max_pwd_age)
        max_pwd_args = "--max-pwd-age=270"
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "set"), max_pwd_args,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("successful", out)
        self.assertNotEquals(max_pwd_age, self.ldb.get_maxPwdAge())

        # check we can't set the domain min password age to more than the max
        min_pwd_age = self.ldb.get_minPwdAge()
        self.addCleanup(self.ldb.set_minPwdAge, min_pwd_age)
        min_pwd_args = "--min-pwd-age=271"
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "set"), min_pwd_args,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdFail(result, "minPwdAge > maxPwdAge should be rejected")
        self.assertIn("Maximum password age", err)

        # check we can set the domain min password age to less than the max
        min_pwd_args = "--min-pwd-age=269"
        (result, out, err) = self.runsublevelcmd("domain", ("passwordsettings",
                                                 "set"), min_pwd_args,
                                                 "-H", self.server,
                                                 self.user_auth)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("successful", out)
        self.assertNotEquals(min_pwd_age, self.ldb.get_minPwdAge())
