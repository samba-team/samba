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
        dsdb
        )
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba.compat import get_bytes
from samba.compat import get_string
from samba.tests import env_loadparm


class UserCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool user subcommands"""
    users = []
    samdb = None

    def setUp(self):
        super(UserCmdTestCase, self).setUp()
        self.samdb = self.getSamDB("-H", "ldap://%s" % os.environ["DC_SERVER"],
                                   "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
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

        # setup the 12 users and ensure they are correct
        for user in self.users:
            (result, out, err) = user["createUserFn"](user)

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            if 'unix' in user["name"]:
                self.assertIn("Modified User '%s' successfully" % user["name"],
                              out)
            else:
                self.assertIn("User '%s' created successfully" % user["name"],
                              out)

            user["checkUserFn"](user)

    def tearDown(self):
        super(UserCmdTestCase, self).tearDown()
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
            self.assertIn("User '%s' created successfully" % user["name"], out)

            found = self._find_user(user["name"])

            self.assertEqual("%s" % found.get("cn"), "%(name)s" % user)
            self.assertEqual("%s" % found.get("name"), "%(name)s" % user)

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
            nthash = creds.get_nt_hash()
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
            self.assertMatch(out, "unicodePwd:: %s" % unicodePwd,
                             "getpassword unicodePwd: out[%s]" % out)
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
            self.assertEqual(err, "", "getpassword without url")
            self.assertMatch(out, "Got password OK", "getpassword without url")
            self.assertMatch(out, "sAMAccountName: %s" % (user["name"]),
                             "getpassword: 'sAMAccountName': %s out[%s]" % (user["name"], out))
            self.assertMatch(out, "unicodePwd:: %s" % unicodePwd,
                             "getpassword unicodePwd: out[%s]" % out)
            self.assertMatch(out, "supplementalCredentials:: ",
                             "getpassword supplementalCredentials: out[%s]" % out)
            self._verify_supplementalCredentials(out.replace("\nGot password OK\n", ""))
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

        # TODO: renable this after the filter case is sorted out
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
            found = self.assertMatch(out, name,
                                     "user '%s' not found" % name)


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
            found = self.assertMatch(out, name,
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
            found = self.assertMatch(out, name,
                                     "user '%s' not found" % name)

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

    def test_move(self):
        full_ou_dn = str(self.samdb.normalize_dn_in_domain("OU=movetest"))
        (result, out, err) = self.runsubcmd("ou", "create", full_ou_dn)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "There shouldn't be any error message")
        self.assertIn('Created ou "%s"' % full_ou_dn, out)

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

        (result, out, err) = self.runsubcmd("ou", "delete", full_ou_dn)
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % full_ou_dn)

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
        self.assertIn("User '%s' created successfully" % user["name"], out)

        self._check_posix_user(user)
        self.runsubcmd("user", "delete", user["name"])

        # Check if overriding the attributes from NSS with explicit values works
        #
        # get a user with all random posix attributes
        user = self._randomPosixUser({"name": u[0]})
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
        self.assertIn("User '%s' created successfully" % user["name"], out)

        self._check_posix_user(user)
        self.runsubcmd("user", "delete", user["name"])

    def _randomUser(self, base={}):
        """create a user with random attribute values, you can specify base attributes"""
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

    def _randomPosixUser(self, base={}):
        """create a user with random attribute values and additional RFC2307
        attributes, you can specify base attributes"""
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

    def _randomUnixUser(self, base={}):
        """create a user with random attribute values and additional RFC2307
        attributes, you can specify base attributes"""
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
        self._check_user(user)

    def _create_user(self, user):
        return self.runsubcmd("user", "create", user["name"], user["password"],
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
