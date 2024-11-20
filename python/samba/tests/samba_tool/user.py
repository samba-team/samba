# Unix SMB/CIFS implementation.
# Copyright (C) Sean Dague <sdague@linux.vnet.ibm.com> 2011
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
import time
import base64
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import (
        credentials,
        nttime2unix,
        dsdb,
        werror,
        )
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba.common import get_bytes
from samba.common import get_string
from samba.tests import env_loadparm


class UserCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool user subcommands"""
    users = []
    samdb = None

    def setUp(self):
        super().setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

        # Modify the default template homedir
        lp = self.get_loadparm()
        self.template_homedir = lp.get('template homedir')
        lp.set('template homedir', '/home/test/%D/%U')

        self.users = []
        self.users.append(self._randomUser({"name": "sambatool1", "company": "comp1"}))
        self.users.append(self._randomUser({"name": "sambatool2", "company": "comp1"}))
        self.users.append(self._randomUser({"name": "sambatool3", "company": "comp2"}))
        self.users.append(self._randomUser({"name": "sambatool4", "company": "comp2"}))
        self.users.append(self._randomPosixUser({"name": "posixuser1"}))
        self.users.append(self._randomPosixUser({"name": "posixuser2"}))
        self.users.append(self._randomPosixUser({"name": "posixuser3"}))
        self.users.append(self._randomPosixUser({"name": "posixuser4"}))
        self.users.append(self._randomUnixUser({"name": "unixuser1"}))
        self.users.append(self._randomUnixUser({"name": "unixuser2"}))
        self.users.append(self._randomUnixUser({"name": "unixuser3"}))
        self.users.append(self._randomUnixUser({"name": "unixuser4"}))

        # Make sure users don't exist
        for user in self.users:
            if self._find_user(user["name"]):
                self.runsubcmd("user", "delete", user["name"])

        # setup the 12 users and ensure they are correct
        for user in self.users:
            (result, out, err) = user["createUserFn"](user)

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            if 'unix' in user["name"]:
                self.assertIn("Modified User '%s' successfully" % user["name"],
                              out)
            else:
                self.assertIn("User '%s' added successfully" % user["name"],
                              out)

            user["checkUserFn"](user)

    def tearDown(self):
        super().tearDown()
        # clean up all the left over users, just in case
        for user in self.users:
            if self._find_user(user["name"]):
                self.runsubcmd("user", "delete", user["name"])
        lp = env_loadparm()
        # second run of this test
        # the cache is still there and '--cache-ldb-initialize'
        # will fail
        cachedb = lp.private_path("user-syncpasswords-cache.ldb")
        if os.path.exists(cachedb):
            os.remove(cachedb)
        lp.set('template homedir', self.template_homedir)

    def test_newuser(self):
        # try to add all the users again, this should fail
        for user in self.users:
            (result, out, err) = self._create_user(user)
            self.assertCmdFail(result, "Ensure that create user fails")
            self.assertIn("LDAP error 68 LDAP_ENTRY_ALREADY_EXISTS", err)

        # try to delete all the 4 users we just added
        for user in self.users:
            (result, out, err) = self.runsubcmd("user", "delete", user["name"])
            self.assertCmdSuccess(result, out, err, "Can we delete users")
            found = self._find_user(user["name"])
            self.assertIsNone(found)

        # test adding users with --use-username-as-cn
        for user in self.users:
            (result, out, err) = self.runsubcmd("user", "create", user["name"], user["password"],
                                                "--use-username-as-cn",
                                                "--surname=%s" % user["surname"],
                                                "--given-name=%s" % user["given-name"],
                                                "--job-title=%s" % user["job-title"],
                                                "--department=%s" % user["department"],
                                                "--description=%s" % user["description"],
                                                "--company=%s" % user["company"],
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn("User '%s' added successfully" % user["name"], out)

            found = self._find_user(user["name"])

            self.assertEqual("%s" % found.get("cn"), "%(name)s" % user)
            self.assertEqual("%s" % found.get("name"), "%(name)s" % user)

    def test_newuser_weak_password(self):
        # Ensure that when we try to create a user over LDAP (thus no
        # transactions) and the password is too weak, we do not get a
        # half-created account.

        def cleanup_user(username):
            try:
                self.samdb.deleteuser(username)
            except Exception as err:
                estr = err.args[0]
                if 'Unable to find user' not in estr:
                    raise

        server = os.environ['DC_SERVER']
        dc_username = os.environ['DC_USERNAME']
        dc_password = os.environ['DC_PASSWORD']

        username = self.randomName()
        password = 'a'

        self.addCleanup(cleanup_user, username)

        # Try to add the user and ensure it fails.
        result, out, err = self.runsubcmd('user', 'add',
                                          username, password,
                                          '-H', f'ldap://{server}',
                                          f'-U{dc_username}%{dc_password}')
        self.assertCmdFail(result)
        self.assertIn('Failed to add user', err)
        self.assertIn('LDAP_CONSTRAINT_VIOLATION', err)
        self.assertIn(f'{werror.WERR_PASSWORD_RESTRICTION:08X}', err)

        # Now search for the user, and make sure we don't find anything.
        res = self.samdb.search(self.samdb.domain_dn(),
                                expression=f'(sAMAccountName={username})',
                                scope=ldb.SCOPE_SUBTREE)
        self.assertEqual(0, len(res), 'expected not to find the user')

    def _verify_supplementalCredentials(self, ldif,
                                        min_packages=3,
                                        max_packages=6):
        msgs = self.samdb.parse_ldif(ldif)
        (changetype, obj) = next(msgs)

        self.assertIn("supplementalCredentials", obj, "supplementalCredentials attribute required")
        sc_blob = obj["supplementalCredentials"][0]
        sc = ndr_unpack(drsblobs.supplementalCredentialsBlob, sc_blob)

        self.assertGreaterEqual(sc.sub.num_packages,
                                min_packages, "min_packages check")
        self.assertLessEqual(sc.sub.num_packages,
                             max_packages, "max_packages check")

        if max_packages == 0:
            return

        def find_package(packages, name, start_idx=0):
            for i in range(start_idx, len(packages)):
                if packages[i].name == name:
                    return (i, packages[i])
            return (None, None)

        # The ordering is this
        #
        # Primary:Kerberos-Newer-Keys (optional)
        # Primary:Kerberos
        # Primary:WDigest
        # Primary:CLEARTEXT (optional)
        # Primary:SambaGPG (optional)
        #
        # And the 'Packages' package is insert before the last
        # other package.

        nidx = 0
        (pidx, pp) = find_package(sc.sub.packages, "Packages", start_idx=nidx)
        self.assertIsNotNone(pp, "Packages required")
        self.assertEqual(pidx + 1, sc.sub.num_packages - 1,
                         "Packages needs to be at num_packages - 1")

        (knidx, knp) = find_package(sc.sub.packages, "Primary:Kerberos-Newer-Keys",
                                    start_idx=nidx)
        if knidx is not None:
            self.assertEqual(knidx, nidx, "Primary:Kerberos-Newer-Keys at wrong position")
            nidx = nidx + 1
            if nidx == pidx:
                nidx = nidx + 1

        (kidx, kp) = find_package(sc.sub.packages, "Primary:Kerberos",
                                  start_idx=nidx)
        self.assertIsNotNone(pp, "Primary:Kerberos required")
        self.assertEqual(kidx, nidx, "Primary:Kerberos at wrong position")
        nidx = nidx + 1
        if nidx == pidx:
            nidx = nidx + 1

        (widx, wp) = find_package(sc.sub.packages, "Primary:WDigest",
                                  start_idx=nidx)
        self.assertIsNotNone(pp, "Primary:WDigest required")
        self.assertEqual(widx, nidx, "Primary:WDigest at wrong position")
        nidx = nidx + 1
        if nidx == pidx:
            nidx = nidx + 1

        (cidx, cp) = find_package(sc.sub.packages, "Primary:CLEARTEXT",
                                  start_idx=nidx)
        if cidx is not None:
            self.assertEqual(cidx, nidx, "Primary:CLEARTEXT at wrong position")
            nidx = nidx + 1
            if nidx == pidx:
                nidx = nidx + 1

        (gidx, gp) = find_package(sc.sub.packages, "Primary:SambaGPG",
                                  start_idx=nidx)
        if gidx is not None:
            self.assertEqual(gidx, nidx, "Primary:SambaGPG at wrong position")
            nidx = nidx + 1
            if nidx == pidx:
                nidx = nidx + 1

        self.assertEqual(nidx, sc.sub.num_packages, "Unknown packages found")

    def test_setpassword(self):
        expect_nt_hash = bool(int(os.environ.get("EXPECT_NT_HASH", "1")))

        for user in self.users:
            newpasswd = self.random_password(16)
            (result, out, err) = self.runsubcmd("user", "setpassword",
                                                user["name"],
                                                "--newpassword=%s" % newpasswd,
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, out, err, "Ensure setpassword runs")
            self.assertEqual(err, "", "setpassword with url")
            self.assertMatch(out, "Changed password OK", "setpassword with url")

        attributes = "sAMAccountName,unicodePwd,supplementalCredentials,virtualClearTextUTF8,virtualClearTextUTF16,virtualSSHA,virtualSambaGPG"
        (result, out, err) = self.runsubcmd("user", "syncpasswords",
                                            "--cache-ldb-initialize",
                                            "--attributes=%s" % attributes,
                                            "--decrypt-samba-gpg")
        self.assertCmdSuccess(result, out, err, "Ensure syncpasswords --cache-ldb-initialize runs")
        self.assertEqual(err, "", "getpassword without url")
        cache_attrs = {
            "objectClass": {"value": "userSyncPasswords"},
            "samdbUrl": {},
            "dirsyncFilter": {},
            "dirsyncAttribute": {},
            "dirsyncControl": {"value": "dirsync:1:0:0"},
            "passwordAttribute": {},
            "decryptSambaGPG": {},
            "currentTime": {},
        }
        for a in cache_attrs.keys():
            v = cache_attrs[a].get("value", "")
            self.assertMatch(out, "%s: %s" % (a, v),
                             "syncpasswords --cache-ldb-initialize: %s: %s out[%s]" % (a, v, out))

        (result, out, err) = self.runsubcmd("user", "syncpasswords", "--no-wait")
        self.assertCmdSuccess(result, out, err, "Ensure syncpasswords --no-wait runs")
        self.assertEqual(err, "", "syncpasswords --no-wait")
        self.assertMatch(out, "dirsync_loop(): results 0",
                         "syncpasswords --no-wait: 'dirsync_loop(): results 0': out[%s]" % (out))
        for user in self.users:
            self.assertMatch(out, "sAMAccountName: %s" % (user["name"]),
                             "syncpasswords --no-wait: 'sAMAccountName': %s out[%s]" % (user["name"], out))

        for user in self.users:
            newpasswd = self.random_password(16)
            creds = credentials.Credentials()
            creds.set_anonymous()
            creds.set_password(newpasswd)
            unicodePwd = base64.b64encode(creds.get_nt_hash()).decode('utf8')
            virtualClearTextUTF8 = base64.b64encode(get_bytes(newpasswd)).decode('utf8')
            virtualClearTextUTF16 = base64.b64encode(get_string(newpasswd).encode('utf-16-le')).decode('utf8')

            (result, out, err) = self.runsubcmd("user", "setpassword",
                                                user["name"],
                                                "--newpassword=%s" % newpasswd)
            self.assertCmdSuccess(result, out, err, "Ensure setpassword runs")
            self.assertEqual(err, "", "setpassword without url")
            self.assertMatch(out, "Changed password OK", "setpassword without url")

            (result, out, err) = self.runsubcmd("user", "syncpasswords", "--no-wait")
            self.assertCmdSuccess(result, out, err, "Ensure syncpasswords --no-wait runs")
            self.assertEqual(err, "", "syncpasswords --no-wait")
            self.assertMatch(out, "dirsync_loop(): results 0",
                             "syncpasswords --no-wait: 'dirsync_loop(): results 0': out[%s]" % (out))
            self.assertMatch(out, "sAMAccountName: %s" % (user["name"]),
                             "syncpasswords --no-wait: 'sAMAccountName': %s out[%s]" % (user["name"], out))
            self.assertMatch(out, "# unicodePwd::: REDACTED SECRET ATTRIBUTE",
                             "getpassword '# unicodePwd::: REDACTED SECRET ATTRIBUTE': out[%s]" % out)
            if expect_nt_hash or "virtualSambaGPG:: " in out:
                self.assertMatch(out, "unicodePwd:: %s" % unicodePwd,
                                 "getpassword unicodePwd: out[%s]" % out)
            else:
                self.assertNotIn("unicodePwd:: %s" % unicodePwd, out)
            self.assertMatch(out, "# supplementalCredentials::: REDACTED SECRET ATTRIBUTE",
                             "getpassword '# supplementalCredentials::: REDACTED SECRET ATTRIBUTE': out[%s]" % out)
            self.assertMatch(out, "supplementalCredentials:: ",
                             "getpassword supplementalCredentials: out[%s]" % out)
            if "virtualSambaGPG:: " in out:
                self.assertMatch(out, "virtualClearTextUTF8:: %s" % virtualClearTextUTF8,
                                 "getpassword virtualClearTextUTF8: out[%s]" % out)
                self.assertMatch(out, "virtualClearTextUTF16:: %s" % virtualClearTextUTF16,
                                 "getpassword virtualClearTextUTF16: out[%s]" % out)
                self.assertMatch(out, "virtualSSHA: ",
                                 "getpassword virtualSSHA: out[%s]" % out)

            (result, out, err) = self.runsubcmd("user", "getpassword",
                                                user["name"],
                                                "--attributes=%s" % attributes,
                                                "--decrypt-samba-gpg")
            self.assertCmdSuccess(result, out, err, "Ensure getpassword runs")
            self.assertEqual(err, "Any available password returned OK\n", "getpassword without url")
            self.assertMatch(out, "sAMAccountName: %s" % (user["name"]),
                             "getpassword: 'sAMAccountName': %s out[%s]" % (user["name"], out))
            if expect_nt_hash or "virtualSambaGPG:: " in out:
                self.assertMatch(out, "unicodePwd:: %s" % unicodePwd,
                                 "getpassword unicodePwd: out[%s]" % out)
            else:
                self.assertNotIn("unicodePwd:: %s" % unicodePwd, out)
            self.assertMatch(out, "supplementalCredentials:: ",
                             "getpassword supplementalCredentials: out[%s]" % out)
            self._verify_supplementalCredentials(out)
            if "virtualSambaGPG:: " in out:
                self.assertMatch(out, "virtualClearTextUTF8:: %s" % virtualClearTextUTF8,
                                 "getpassword virtualClearTextUTF8: out[%s]" % out)
                self.assertMatch(out, "virtualClearTextUTF16:: %s" % virtualClearTextUTF16,
                                 "getpassword virtualClearTextUTF16: out[%s]" % out)
                self.assertMatch(out, "virtualSSHA: ",
                                 "getpassword virtualSSHA: out[%s]" % out)

        for user in self.users:
            newpasswd = self.random_password(16)
            (result, out, err) = self.runsubcmd("user", "setpassword",
                                                user["name"],
                                                "--newpassword=%s" % newpasswd,
                                                "--must-change-at-next-login",
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, out, err, "Ensure setpassword runs")
            self.assertEqual(err, "", "setpassword with forced change")
            self.assertMatch(out, "Changed password OK", "setpassword with forced change")

    def test_setexpiry(self):
        for user in self.users:
            twodays = time.time() + (2 * 24 * 60 * 60)

            (result, out, err) = self.runsubcmd("user", "setexpiry", user["name"],
                                                "--days=2",
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, out, err, "Can we run setexpiry with names")
            self.assertIn("Expiry for user '%s' set to 2 days." % user["name"], out)

            found = self._find_user(user["name"])

            expires = nttime2unix(int("%s" % found.get("accountExpires")))
            self.assertWithin(expires, twodays, 5, "Ensure account expires is within 5 seconds of the expected time")

        # TODO: re-enable this after the filter case is sorted out
        if "filters are broken, bail now":
            return

        # now run the expiration based on a filter
        fourdays = time.time() + (4 * 24 * 60 * 60)
        (result, out, err) = self.runsubcmd("user", "setexpiry",
                                            "--filter", "(&(objectClass=user)(company=comp2))",
                                            "--days=4",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Can we run setexpiry with a filter")

        for user in self.users:
            found = self._find_user(user["name"])
            if ("%s" % found.get("company")) == "comp2":
                expires = nttime2unix(int("%s" % found.get("accountExpires")))
                self.assertWithin(expires, fourdays, 5, "Ensure account expires is within 5 seconds of the expected time")
            else:
                expires = nttime2unix(int("%s" % found.get("accountExpires")))
                self.assertWithin(expires, twodays, 5, "Ensure account expires is within 5 seconds of the expected time")

    def test_list(self):
        (result, out, err) = self.runsubcmd("user", "list",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(&(objectClass=user)(userAccountControl:%s:=%u))" %
                         (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT))

        userlist = self.samdb.search(base=self.samdb.domain_dn(),
                                     scope=ldb.SCOPE_SUBTREE,
                                     expression=search_filter,
                                     attrs=["samaccountname"])

        self.assertTrue(len(userlist) > 0, "no users found in samdb")

        for userobj in userlist:
            name = str(userobj.get("samaccountname", idx=0))
            self.assertMatch(out, name,
                             "user '%s' not found" % name)

    # Test: samba-tool user list --locked-only
    # This test does not verify that the command lists the locked user, it just
    # tests that it does not list unlocked users. The funcional test, which
    # lists locked users, is located in the 'samba4.ldap.password_lockout' test
    # in source8/dsdb/tests/python/password_lockout.py
    def test_list_locked(self):
        (result, out, err) = self.runsubcmd("user", "list",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]),
                                            "--locked-only")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(&(objectClass=user)(userAccountControl:%s:=%u))" %
                         (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT))

        userlist = self.samdb.search(base=self.samdb.domain_dn(),
                                     scope=ldb.SCOPE_SUBTREE,
                                     expression=search_filter,
                                     attrs=["samaccountname"])

        for userobj in userlist:
            name = str(userobj.get("samaccountname", idx=0))
            self.assertNotIn(name, out,
                             "user '%s' is incorrectly listed as locked" % name)

    def test_list_base_dn(self):
        base_dn = "CN=Users"
        (result, out, err) = self.runsubcmd("user", "list", "-b", base_dn,
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(&(objectClass=user)(userAccountControl:%s:=%u))" %
                         (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT))

        userlist = self.samdb.search(base=self.samdb.normalize_dn_in_domain(base_dn),
                                     scope=ldb.SCOPE_SUBTREE,
                                     expression=search_filter,
                                     attrs=["samaccountname"])

        self.assertTrue(len(userlist) > 0, "no users found in samdb")

        for userobj in userlist:
            name = str(userobj.get("samaccountname", idx=0))
            self.assertMatch(out, name,
                             "user '%s' not found" % name)

    def test_list_full_dn(self):
        (result, out, err) = self.runsubcmd("user", "list", "--full-dn",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = ("(&(objectClass=user)(userAccountControl:%s:=%u))" %
                         (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT))

        userlist = self.samdb.search(base=self.samdb.domain_dn(),
                                     scope=ldb.SCOPE_SUBTREE,
                                     expression=search_filter,
                                     attrs=["dn"])

        self.assertTrue(len(userlist) > 0, "no users found in samdb")

        for userobj in userlist:
            name = str(userobj.get("dn", idx=0))
            self.assertMatch(out, name,
                             "user '%s' not found" % name)

    def test_list_hide_expired(self):
        expire_username = "expireUser"
        expire_user = self._randomUser({"name": expire_username})
        self._create_user(expire_user)

        (result, out, err) = self.runsubcmd(
            "user",
            "list",
            "--hide-expired",
            "-H",
            "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")
        self.assertTrue(expire_username in out,
                        "user '%s' not found" % expire_username)

        # user will be expired one second ago
        self.samdb.setexpiry(
            "(sAMAccountname=%s)" % expire_username,
            -1,
            False)

        (result, out, err) = self.runsubcmd(
            "user",
            "list",
            "--hide-expired",
            "-H",
            "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")
        self.assertFalse(expire_username in out,
                         "user '%s' found" % expire_username)

        self.samdb.deleteuser(expire_username)

    def test_list_hide_disabled(self):
        disable_username = "disableUser"
        disable_user = self._randomUser({"name": disable_username})
        self._create_user(disable_user)

        (result, out, err) = self.runsubcmd(
            "user",
            "list",
            "--hide-disabled",
            "-H",
            "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")
        self.assertTrue(disable_username in out,
                        "user '%s' not found" % disable_username)

        self.samdb.disable_account("(sAMAccountname=%s)" % disable_username)

        (result, out, err) = self.runsubcmd(
            "user",
            "list",
            "--hide-disabled",
            "-H",
            "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running list")
        self.assertFalse(disable_username in out,
                         "user '%s' found" % disable_username)

        self.samdb.deleteuser(disable_username)

    def test_show(self):
        for user in self.users:
            (result, out, err) = self.runsubcmd(
                "user", "show", user["name"],
                "--attributes=sAMAccountName,company",
                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                "-U%s%%%s" % (os.environ["DC_USERNAME"],
                              os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, out, err, "Error running show")

            expected_out = """dn: CN=%s %s,CN=Users,%s
company: %s
sAMAccountName: %s

""" % (user["given-name"], user["surname"], self.samdb.domain_dn(),
                user["company"], user["name"])

            self.assertEqual(out, expected_out,
                             "Unexpected show output for user '%s'" %
                             user["name"])

            time_attrs = [
                "name", # test that invalid values are just ignored
                "whenCreated",
                "whenChanged",
                "accountExpires",
                "badPasswordTime",
                "lastLogoff",
                "lastLogon",
                "lastLogonTimestamp",
                "lockoutTime",
                "msDS-UserPasswordExpiryTimeComputed",
                "pwdLastSet",
                ]

            attrs = []
            for ta in time_attrs:
                attrs.append(ta)
                for fm in ["GeneralizedTime", "UnixTime", "TimeSpec"]:
                    attrs.append("%s;format=%s" % (ta, fm))

            (result, out, err) = self.runsubcmd(
                "user", "show", user["name"],
                "--attributes=%s" % ",".join(attrs),
                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                "-U%s%%%s" % (os.environ["DC_USERNAME"],
                              os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, out, err,
                                  "Error running show --attributes=%s"
                                  % ",".join(attrs))

            self.assertIn(";format=GeneralizedTime", out)
            self.assertIn(";format=UnixTime", out)
            self.assertIn(";format=TimeSpec", out)

            self.assertIn("name: ", out)
            self.assertNotIn("name;format=GeneralizedTime: ", out)
            self.assertNotIn("name;format=UnixTime: ", out)
            self.assertNotIn("name;format=TimeSpec: ", out)

            self.assertIn("whenCreated: 20", out)
            self.assertIn("whenCreated;format=GeneralizedTime: 20", out)
            self.assertIn("whenCreated;format=UnixTime: 1", out)
            self.assertIn("whenCreated;format=TimeSpec: 1", out)

            self.assertIn("whenChanged: 20", out)
            self.assertIn("whenChanged;format=GeneralizedTime: 20", out)
            self.assertIn("whenChanged;format=UnixTime: 1", out)
            self.assertIn("whenChanged;format=TimeSpec: 1", out)

            self.assertIn("accountExpires: 9223372036854775807", out)
            self.assertNotIn("accountExpires;format=GeneralizedTime: ", out)
            self.assertNotIn("accountExpires;format=UnixTime: ", out)
            self.assertNotIn("accountExpires;format=TimeSpec: ", out)

            self.assertIn("badPasswordTime: 0", out)
            self.assertNotIn("badPasswordTime;format=GeneralizedTime: ", out)
            self.assertNotIn("badPasswordTime;format=UnixTime: ", out)
            self.assertNotIn("badPasswordTime;format=TimeSpec: ", out)

            self.assertIn("lastLogoff: 0", out)
            self.assertNotIn("lastLogoff;format=GeneralizedTime: ", out)
            self.assertNotIn("lastLogoff;format=UnixTime: ", out)
            self.assertNotIn("lastLogoff;format=TimeSpec: ", out)

            self.assertIn("lastLogon: 0", out)
            self.assertNotIn("lastLogon;format=GeneralizedTime: ", out)
            self.assertNotIn("lastLogon;format=UnixTime: ", out)
            self.assertNotIn("lastLogon;format=TimeSpec: ", out)

            # If a specified attribute is not available on a user object
            # it's silently omitted.
            self.assertNotIn("lastLogonTimestamp:", out)
            self.assertNotIn("lockoutTime:", out)

            self.assertIn("msDS-UserPasswordExpiryTimeComputed: 1", out)
            self.assertIn("msDS-UserPasswordExpiryTimeComputed;format=GeneralizedTime: 20", out)
            self.assertIn("msDS-UserPasswordExpiryTimeComputed;format=UnixTime: 1", out)
            self.assertIn("msDS-UserPasswordExpiryTimeComputed;format=TimeSpec: 1", out)

            self.assertIn("pwdLastSet: 1", out)
            self.assertIn("pwdLastSet;format=GeneralizedTime: 20", out)
            self.assertIn("pwdLastSet;format=UnixTime: 1", out)
            self.assertIn("pwdLastSet;format=TimeSpec: 1", out)

            out_msgs = self.samdb.parse_ldif(out)
            out_msg = next(out_msgs)[1]

            self.assertIn("whenCreated", out_msg)
            when_created_str = str(out_msg["whenCreated"][0])
            self.assertIn("whenCreated;format=GeneralizedTime", out_msg)
            self.assertEqual(str(out_msg["whenCreated;format=GeneralizedTime"][0]), when_created_str)
            when_created_time = ldb.string_to_time(when_created_str)
            self.assertIn("whenCreated;format=UnixTime", out_msg)
            self.assertEqual(str(out_msg["whenCreated;format=UnixTime"][0]), str(when_created_time))
            self.assertIn("whenCreated;format=TimeSpec", out_msg)
            self.assertEqual(str(out_msg["whenCreated;format=TimeSpec"][0]),
                             "%d.000000000" % (when_created_time))

            self.assertIn("whenChanged", out_msg)
            when_changed_str = str(out_msg["whenChanged"][0])
            self.assertIn("whenChanged;format=GeneralizedTime", out_msg)
            self.assertEqual(str(out_msg["whenChanged;format=GeneralizedTime"][0]), when_changed_str)
            when_changed_time = ldb.string_to_time(when_changed_str)
            self.assertIn("whenChanged;format=UnixTime", out_msg)
            self.assertEqual(str(out_msg["whenChanged;format=UnixTime"][0]), str(when_changed_time))
            self.assertIn("whenChanged;format=TimeSpec", out_msg)
            self.assertEqual(str(out_msg["whenChanged;format=TimeSpec"][0]),
                             "%d.000000000" % (when_changed_time))

            self.assertIn("pwdLastSet;format=GeneralizedTime", out_msg)
            pwd_last_set_str = str(out_msg["pwdLastSet;format=GeneralizedTime"][0])
            pwd_last_set_time = ldb.string_to_time(pwd_last_set_str)
            self.assertIn("pwdLastSet;format=UnixTime", out_msg)
            self.assertEqual(str(out_msg["pwdLastSet;format=UnixTime"][0]), str(pwd_last_set_time))
            self.assertIn("pwdLastSet;format=TimeSpec", out_msg)
            self.assertIn("%d." % pwd_last_set_time, str(out_msg["pwdLastSet;format=TimeSpec"][0]))
            self.assertNotIn(".000000000", str(out_msg["pwdLastSet;format=TimeSpec"][0]))

            # assert that the pwd has been set in the minute after user creation
            self.assertGreaterEqual(pwd_last_set_time, when_created_time)
            self.assertLess(pwd_last_set_time, when_created_time + 60)

            self.assertIn("msDS-UserPasswordExpiryTimeComputed;format=GeneralizedTime", out_msg)
            pwd_expires_str = str(out_msg["msDS-UserPasswordExpiryTimeComputed;format=GeneralizedTime"][0])
            pwd_expires_time = ldb.string_to_time(pwd_expires_str)
            self.assertIn("msDS-UserPasswordExpiryTimeComputed;format=UnixTime", out_msg)
            self.assertEqual(str(out_msg["msDS-UserPasswordExpiryTimeComputed;format=UnixTime"][0]), str(pwd_expires_time))
            self.assertIn("msDS-UserPasswordExpiryTimeComputed;format=TimeSpec", out_msg)
            self.assertIn("%d." % pwd_expires_time, str(out_msg["msDS-UserPasswordExpiryTimeComputed;format=TimeSpec"][0]))
            self.assertNotIn(".000000000", str(out_msg["msDS-UserPasswordExpiryTimeComputed;format=TimeSpec"][0]))

            # assert that the pwd expires after it was set
            self.assertGreater(pwd_expires_time, pwd_last_set_time)

    def test_move(self):
        full_ou_dn = str(self.samdb.normalize_dn_in_domain("OU=movetest_usr"))
        self.addCleanup(self.samdb.delete, full_ou_dn, ["tree_delete:1"])

        (result, out, err) = self.runsubcmd("ou", "add", full_ou_dn)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "There shouldn't be any error message")
        self.assertIn('Added ou "%s"' % full_ou_dn, out)

        for user in self.users:
            (result, out, err) = self.runsubcmd(
                "user", "move", user["name"], full_ou_dn)
            self.assertCmdSuccess(result, out, err, "Error running move")
            self.assertIn('Moved user "%s" into "%s"' %
                          (user["name"], full_ou_dn), out)

        # Should fail as users objects are in OU
        (result, out, err) = self.runsubcmd("ou", "delete", full_ou_dn)
        self.assertCmdFail(result)
        self.assertIn(("subtree_delete: Unable to delete a non-leaf node "
                       "(it has %d children)!") % len(self.users), err)

        for user in self.users:
            new_dn = "CN=Users,%s" % self.samdb.domain_dn()
            (result, out, err) = self.runsubcmd(
                "user", "move", user["name"], new_dn)
            self.assertCmdSuccess(result, out, err, "Error running move")
            self.assertIn('Moved user "%s" into "%s"' %
                          (user["name"], new_dn), out)

    def test_rename_surname_initials_givenname(self):
        """rename the existing surname and given name and add missing
        initials, then remove them, for all users"""
        for user in self.users:
            new_givenname = "new_given_name_of_" + user["name"]
            new_initials = "A"
            new_surname = "new_surname_of_" + user["name"]
            found = self._find_user(user["name"])
            old_cn = str(found.get("cn"))

            # rename given name, initials and surname
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--surname=%s" % new_surname,
                                                "--initials=%s" % new_initials,
                                                "--given-name=%s" % new_givenname)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual("%s" % found.get("givenName"), new_givenname)
            self.assertEqual("%s" % found.get("initials"), new_initials)
            self.assertEqual("%s" % found.get("sn"), new_surname)
            self.assertEqual("%s" % found.get("name"),
                             "%s %s. %s" % (new_givenname, new_initials, new_surname))
            self.assertEqual("%s" % found.get("cn"),
                             "%s %s. %s" % (new_givenname, new_initials, new_surname))

            # remove given name, initials and surname
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--surname=",
                                                "--initials=",
                                                "--given-name=")
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual(found.get("givenName"), None)
            self.assertEqual(found.get("initials"), None)
            self.assertEqual(found.get("sn"), None)
            self.assertEqual("%s" % found.get("cn"), user["name"])

            # reset changes (initials are removed)
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--surname=%(surname)s" % user,
                                                "--given-name=%(given-name)s" % user)
            self.assertCmdSuccess(result, out, err)

            if old_cn:
                (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--force-new-cn=%s" % old_cn)

    def test_rename_cn_samaccountname(self):
        """rename and try to remove the cn and the samaccount of all users"""
        for user in self.users:
            new_cn = "new_cn_of_" + user["name"]
            new_samaccountname = "new_samaccount_of_" + user["name"]
            new_surname = "new_surname_of_" + user["name"]

            # rename cn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--samaccountname=%s"
                                                 % new_samaccountname,
                                                "--force-new-cn=%s" % new_cn)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(new_samaccountname)
            self.assertEqual("%s" % found.get("cn"), new_cn)
            self.assertEqual("%s" % found.get("sAMAccountName"),
                             new_samaccountname)

            # changing the surname has no effect to the cn
            (result, out, err) = self.runsubcmd("user", "rename", new_samaccountname,
                                                "--surname=%s" % new_surname)
            self.assertCmdSuccess(result, out, err)

            found = self._find_user(new_samaccountname)
            self.assertEqual("%s" % found.get("cn"), new_cn)

            # trying to remove cn (throws an error)
            (result, out, err) = self.runsubcmd("user", "rename",
                                                new_samaccountname,
                                                "--force-new-cn=")
            self.assertCmdFail(result)
            self.assertIn('Failed to rename user', err)
            self.assertIn("delete protected attribute", err)

            # trying to remove the samccountname (throws an error)
            (result, out, err) = self.runsubcmd("user", "rename",
                                                new_samaccountname,
                                                "--samaccountname=")
            self.assertCmdFail(result)
            self.assertIn('Failed to rename user', err)
            self.assertIn('delete protected attribute', err)

            # reset changes (cn must be the name)
            (result, out, err) = self.runsubcmd("user", "rename", new_samaccountname,
                                                "--samaccountname=%(name)s"
                                                  % user,
                                                "--force-new-cn=%(name)s" % user)
            self.assertCmdSuccess(result, out, err)

    def test_rename_standard_cn(self):
        """reset the cn of all users to the standard"""
        for user in self.users:
            new_cn = "new_cn_of_" + user["name"]
            new_givenname = "new_given_name_of_" + user["name"]
            new_initials = "A"
            new_surname = "new_surname_of_" + user["name"]

            # set different cn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--force-new-cn=%s" % new_cn)
            self.assertCmdSuccess(result, out, err)

            # remove given name, initials and surname
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--surname=",
                                                "--initials=",
                                                "--given-name=")
            self.assertCmdSuccess(result, out, err)

            # reset the CN (no given name, initials or surname --> samaccountname)
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--reset-cn")

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual("%s" % found.get("cn"), user["name"])

            # set given name, initials and surname and set different cn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--force-new-cn=%s" % new_cn,
                                                "--surname=%s" % new_surname,
                                                "--initials=%s" % new_initials,
                                                "--given-name=%s" % new_givenname)
            self.assertCmdSuccess(result, out, err)

            # reset the CN (given name, initials or surname are given --> given name)
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--reset-cn")

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual("%s" % found.get("cn"),
                             "%s %s. %s" % (new_givenname, new_initials, new_surname))

            # reset changes
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--reset-cn",
                                                "--initials=",
                                                "--surname=%(surname)s" % user,
                                                "--given-name=%(given-name)s" % user)
            self.assertCmdSuccess(result, out, err)

    def test_rename_mailaddress_displayname(self):
        for user in self.users:
            new_mail = "new_mailaddress_of_" + user["name"]
            new_displayname = "new displayname of " + user["name"]

            # change mail and displayname
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--mail-address=%s"
                                                  % new_mail,
                                                "--display-name=%s"
                                                  % new_displayname)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual("%s" % found.get("mail"), new_mail)
            self.assertEqual("%s" % found.get("displayName"), new_displayname)

            # remove mail and displayname
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--mail-address=",
                                                "--display-name=")
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual(found.get("mail"), None)
            self.assertEqual(found.get("displayName"), None)

    def test_rename_upn(self):
        """rename upn of all users"""
        for user in self.users:
            found = self._find_user(user["name"])
            old_upn = "%s" % found.get("userPrincipalName")
            valid_suffix = old_upn.split('@')[1]   # samba.example.com

            valid_new_upn = "new_%s@%s" % (user["name"], valid_suffix)
            invalid_new_upn = "%s@invalid.suffix" + user["name"]

            # trying to set invalid upn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--upn=%s"
                                                  % invalid_new_upn)
            self.assertCmdFail(result)
            self.assertIn('is not a valid upn', err)

            # set valid upn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--upn=%s"
                                                  % valid_new_upn)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_user(user["name"])
            self.assertEqual("%s" % found.get("userPrincipalName"), valid_new_upn)

            # trying to remove upn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--upn=%s")
            self.assertCmdFail(result)
            self.assertIn('is not a valid upn', err)

            # reset upn
            (result, out, err) = self.runsubcmd("user", "rename", user["name"],
                                                "--upn=%s" % old_upn)
            self.assertCmdSuccess(result, out, err)

    def test_getpwent(self):
        try:
            import pwd
        except ImportError:
            self.skipTest("Skipping getpwent test, no 'pwd' module available")
            return

        # get the current user's data for the test
        uid = os.geteuid()
        try:
            u = pwd.getpwuid(uid)
        except KeyError:
            self.skipTest("Skipping getpwent test, current EUID not found in NSS")
            return


# samba-tool user create command didn't support users with empty gecos if none is
# specified on the command line and the user hasn't one in the passwd file it
# will fail, so let's add some contents

        gecos = u[4]
        if (gecos is None or len(gecos) == 0):
            gecos = "Foo GECOS"
        user = self._randomPosixUser({
                        "name": u[0],
                        "uid": u[0],
                        "uidNumber": u[2],
                        "gidNumber": u[3],
                        "gecos": gecos,
                        "loginShell": u[6],
                        })

        # Remove user if it already exists
        if self._find_user(u[0]):
            self.runsubcmd("user", "delete", u[0])
        # check if --rfc2307-from-nss sets the same values as we got from pwd.getpwuid()
        (result, out, err) = self.runsubcmd("user", "create", user["name"], user["password"],
                                            "--surname=%s" % user["surname"],
                                            "--given-name=%s" % user["given-name"],
                                            "--job-title=%s" % user["job-title"],
                                            "--department=%s" % user["department"],
                                            "--description=%s" % user["description"],
                                            "--company=%s" % user["company"],
                                            "--gecos=%s" % user["gecos"],
                                            "--rfc2307-from-nss",
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("User '%s' added successfully" % user["name"], out)

        self._check_posix_user(user)
        self.runsubcmd("user", "delete", user["name"])

        # Check if overriding the attributes from NSS with explicit values works
        #
        # get a user with all random posix attributes
        user = self._randomPosixUser({"name": u[0]})

        # Remove user if it already exists
        if self._find_user(u[0]):
            self.runsubcmd("user", "delete", u[0])
        # create a user with posix attributes from nss but override all of them with the
        # random ones just obtained
        (result, out, err) = self.runsubcmd("user", "create", user["name"], user["password"],
                                            "--surname=%s" % user["surname"],
                                            "--given-name=%s" % user["given-name"],
                                            "--job-title=%s" % user["job-title"],
                                            "--department=%s" % user["department"],
                                            "--description=%s" % user["description"],
                                            "--company=%s" % user["company"],
                                            "--rfc2307-from-nss",
                                            "--gecos=%s" % user["gecos"],
                                            "--login-shell=%s" % user["loginShell"],
                                            "--uid=%s" % user["uid"],
                                            "--uid-number=%s" % user["uidNumber"],
                                            "--gid-number=%s" % user["gidNumber"],
                                            "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                            "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")
        self.assertIn("User '%s' added successfully" % user["name"], out)

        self._check_posix_user(user)
        self.runsubcmd("user", "delete", user["name"])

    # Test: samba-tool user unlock
    # This test does not verify that the command unlocks the user, it just
    # tests the command itself. The unlock test, which unlocks locked users,
    # is located in the 'samba4.ldap.password_lockout' test in
    # source4/dsdb/tests/python/password_lockout.py
    def test_unlock(self):

        # try to unlock a nonexistent user, this should fail
        nonexistentusername = "userdoesnotexist"
        (result, out, err) = self.runsubcmd(
            "user", "unlock", nonexistentusername)
        self.assertCmdFail(result, "Ensure that unlock nonexistent user fails")
        self.assertIn("Failed to unlock user '%s'" % nonexistentusername, err)
        self.assertIn("Unable to find user", err)

        # try to unlock with insufficient permissions, this should fail
        unprivileged_username = "unprivilegedunlockuser"
        unlocktest_username = "usertounlock"

        self.runsubcmd("user", "add", unprivileged_username, "Passw0rd")
        self.runsubcmd("user", "add", unlocktest_username, "Passw0rd")

        (result, out, err) = self.runsubcmd(
            "user", "unlock", unlocktest_username,
            "-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (unprivileged_username,
                          "Passw0rd"))
        self.assertCmdFail(result, "Fail with LDAP_INSUFFICIENT_ACCESS_RIGHTS")
        self.assertIn("Failed to unlock user '%s'" % unlocktest_username, err)
        self.assertIn("LDAP error 50 LDAP_INSUFFICIENT_ACCESS_RIGHTS", err)

        self.runsubcmd("user", "delete", unprivileged_username)
        self.runsubcmd("user", "delete", unlocktest_username)

        # run unlock against test users
        for user in self.users:
            (result, out, err) = self.runsubcmd(
                "user", "unlock", user["name"])
            self.assertCmdSuccess(result, out, err, "Error running user unlock")
            self.assertEqual(err, "", "Shouldn't be any error messages")

    def test_disable_remove_supplemental_groups(self):
        """disable user and remove supplemental groups"""
        username = "userRemoveGroups"
        user = self._randomUser({"name": username})
        self._create_user(user)

        usergroups = self._get_groups(username)
        self.assertTrue(len(usergroups) == 1, "exactly one membership expected")
        self.assertEqual(usergroups[0],
                         "Domain Users",
                         "Unexpected groupmembership")

        self._add_groupmember("Domain Admins", username)
        self._add_groupmember("Print Operators", username)

        usergroups = self._get_groups(username)
        self.assertTrue(len(usergroups) == 3, "exactly 3 memberships expected")

        (result, out, err) = self.runsubcmd(
            "user", "disable", username,
            "--remove-supplemental-groups",
            "-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
            os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(
            result, out, err,
            "Error running user disable --remove-supplemental-groups")
        self.assertEqual(err, "",
                         "Shouldn't be any error messages from user disable")

        usergroups = self._get_groups(username)
        self.assertTrue(len(usergroups) == 1, "exactly one membership expected")
        self.assertEqual(usergroups[0], "Domain Users",
                         "Unexpected groupmembership")

    def _randomUser(self, base=None):
        """create a user with random attribute values, you can specify base attributes"""
        if base is None:
            base = {}
        user = {
            "name": self.randomName(),
            "password": self.random_password(16),
            "surname": self.randomName(),
            "given-name": self.randomName(),
            "job-title": self.randomName(),
            "department": self.randomName(),
            "company": self.randomName(),
            "description": self.randomName(count=100),
            "createUserFn": self._create_user,
            "checkUserFn": self._check_user,
        }
        user.update(base)
        return user

    def _randomPosixUser(self, base=None):
        """create a user with random attribute values and additional RFC2307
        attributes, you can specify base attributes"""
        if base is None:
            base = {}
        user = self._randomUser({})
        user.update(base)
        posixAttributes = {
            "uid": self.randomName(),
            "loginShell": self.randomName(),
            "gecos": self.randomName(),
            "uidNumber": self.randomXid(),
            "gidNumber": self.randomXid(),
            "createUserFn": self._create_posix_user,
            "checkUserFn": self._check_posix_user,
        }
        user.update(posixAttributes)
        user.update(base)
        return user

    def _randomUnixUser(self, base=None):
        """create a user with random attribute values and additional RFC2307
        attributes, you can specify base attributes"""
        if base is None:
            base = {}
        user = self._randomUser({})
        user.update(base)
        posixAttributes = {
            "uidNumber": self.randomXid(),
            "gidNumber": self.randomXid(),
            "uid": self.randomName(),
            "loginShell": self.randomName(),
            "gecos": self.randomName(),
            "createUserFn": self._create_unix_user,
            "checkUserFn": self._check_unix_user,
        }
        user.update(posixAttributes)
        user.update(base)
        return user

    def _check_user(self, user):
        """ check if a user from SamDB has the same attributes as its template """
        found = self._find_user(user["name"])

        self.assertEqual("%s" % found.get("name"), "%(given-name)s %(surname)s" % user)
        self.assertEqual("%s" % found.get("title"), user["job-title"])
        self.assertEqual("%s" % found.get("company"), user["company"])
        self.assertEqual("%s" % found.get("description"), user["description"])
        self.assertEqual("%s" % found.get("department"), user["department"])

    def _check_posix_user(self, user):
        """ check if a posix_user from SamDB has the same attributes as its template """
        found = self._find_user(user["name"])

        self.assertEqual("%s" % found.get("loginShell"), user["loginShell"])
        self.assertEqual("%s" % found.get("gecos"), user["gecos"])
        self.assertEqual("%s" % found.get("uidNumber"), "%s" % user["uidNumber"])
        self.assertEqual("%s" % found.get("gidNumber"), "%s" % user["gidNumber"])
        self.assertEqual("%s" % found.get("uid"), user["uid"])
        self._check_user(user)

    def _check_unix_user(self, user):
        """ check if a unix_user from SamDB has the same attributes as its
template """
        found = self._find_user(user["name"])

        self.assertEqual("%s" % found.get("loginShell"), user["loginShell"])
        self.assertEqual("%s" % found.get("gecos"), user["gecos"])
        self.assertEqual("%s" % found.get("uidNumber"), "%s" %
                          user["uidNumber"])
        self.assertEqual("%s" % found.get("gidNumber"), "%s" %
                          user["gidNumber"])
        self.assertEqual("%s" % found.get("uid"), user["uid"])
        self.assertIn('/home/test/', "%s" % found.get("unixHomeDirectory"))
        self._check_user(user)

    def _create_user(self, user):
        return self.runsubcmd("user", "add", user["name"], user["password"],
                              "--surname=%s" % user["surname"],
                              "--given-name=%s" % user["given-name"],
                              "--job-title=%s" % user["job-title"],
                              "--department=%s" % user["department"],
                              "--description=%s" % user["description"],
                              "--company=%s" % user["company"],
                              "-H", "ldap://%s" % os.environ["DC_SERVER"],
                              "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

    def _create_posix_user(self, user):
        """ create a new user with RFC2307 attributes """
        return self.runsubcmd("user", "create", user["name"], user["password"],
                              "--surname=%s" % user["surname"],
                              "--given-name=%s" % user["given-name"],
                              "--job-title=%s" % user["job-title"],
                              "--department=%s" % user["department"],
                              "--description=%s" % user["description"],
                              "--company=%s" % user["company"],
                              "--gecos=%s" % user["gecos"],
                              "--login-shell=%s" % user["loginShell"],
                              "--uid=%s" % user["uid"],
                              "--uid-number=%s" % user["uidNumber"],
                              "--gid-number=%s" % user["gidNumber"],
                              "-H", "ldap://%s" % os.environ["DC_SERVER"],
                              "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

    def _create_unix_user(self, user):
        """ Add RFC2307 attributes to a user"""
        self._create_user(user)
        return self.runsubcmd("user", "addunixattrs", user["name"],
                              "%s" % user["uidNumber"],
                              "--gid-number=%s" % user["gidNumber"],
                              "--gecos=%s" % user["gecos"],
                              "--login-shell=%s" % user["loginShell"],
                              "--uid=%s" % user["uid"],
                              "-H", "ldap://%s" % os.environ["DC_SERVER"],
                              "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                            os.environ["DC_PASSWORD"]))

    def _find_user(self, name):
        search_filter = "(&(sAMAccountName=%s)(objectCategory=%s,%s))" % (ldb.binary_encode(name), "CN=Person,CN=Schema,CN=Configuration", self.samdb.domain_dn())
        userlist = self.samdb.search(base=self.samdb.domain_dn(),
                                     scope=ldb.SCOPE_SUBTREE,
                                     expression=search_filter)
        if userlist:
            return userlist[0]
        else:
            return None

    def _add_groupmember(self, group, user):
        (result, out, err) =  self.runsubcmd(
            "group", "addmembers", group, user,
            "-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(
            result, out, err, "Error running group addmembers")
        self.assertEqual(
            err,
            "",
            "Shouldn't be any error messages from group addmembers")

        return out.rstrip().split("\n")

    def _remove_groupmember(self, group, user):
        (result, out, err) = self.runsubcmd(
            "group", "removemembers", group, user,
            "-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
                          os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(
            result, out, err, "Error running group removemembers")
        self.assertEqual(
            err,
            "",
            "Shouldn't be any error messages from group removemembers")

        return out.rstrip().split("\n")

    def _get_groups(self, user):
        (result, out, err) = self.runsubcmd(
            "user", "getgroups", user,
            "-H", "ldap://%s" % os.environ["DC_SERVER"],
            "-U%s%%%s" % (os.environ["DC_USERNAME"],
            os.environ["DC_PASSWORD"]))
        self.assertCmdSuccess(result, out, err, "Error running user getgroups")
        self.assertEqual(err,
                         "",
                         "Shouldn't be any error messages from user getgroups")

        return out.rstrip().split("\n")
