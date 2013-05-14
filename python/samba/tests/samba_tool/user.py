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
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import (
        nttime2unix,
        dsdb
        )

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

        # setup the 8 users and ensure they are correct
        for user in self.users:
            (result, out, err) = user["createUserFn"](user)

            self.assertCmdSuccess(result)
            self.assertEquals(err,"","Shouldn't be any error messages")
            self.assertIn("User '%s' created successfully" % user["name"], out)

            user["checkUserFn"](user)


    def tearDown(self):
        super(UserCmdTestCase, self).tearDown()
        # clean up all the left over users, just in case
        for user in self.users:
            if self._find_user(user["name"]):
                self.runsubcmd("user", "delete", user["name"])


    def test_newuser(self):
        # try to add all the users again, this should fail
        for user in self.users:
            (result, out, err) = self._create_user(user)
            self.assertCmdFail(result, "Ensure that create user fails")
            self.assertIn("LDAP error 68 LDAP_ENTRY_ALREADY_EXISTS", err)

        # try to delete all the 4 users we just added
        for user in self.users:
            (result, out, err) = self.runsubcmd("user", "delete", user["name"])
            self.assertCmdSuccess(result, "Can we delete users")
            found = self._find_user(user["name"])
            self.assertIsNone(found)

        # test adding users with --use-username-as-cn
        for user in self.users:
            (result, out, err) =  self.runsubcmd("user", "add", user["name"], user["password"],
                                                 "--use-username-as-cn",
                                                 "--surname=%s" % user["surname"],
                                                 "--given-name=%s" % user["given-name"],
                                                 "--job-title=%s" % user["job-title"],
                                                 "--department=%s" % user["department"],
                                                 "--description=%s" % user["description"],
                                                 "--company=%s" % user["company"],
                                                 "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                 "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))

            self.assertCmdSuccess(result)
            self.assertEquals(err,"","Shouldn't be any error messages")
            self.assertIn("User '%s' created successfully" % user["name"], out)

            found = self._find_user(user["name"])

            self.assertEquals("%s" % found.get("cn"), "%(name)s" % user)
            self.assertEquals("%s" % found.get("name"), "%(name)s" % user)



    def test_setpassword(self):
        for user in self.users:
            newpasswd = self.randomPass()
            (result, out, err) = self.runsubcmd("user", "setpassword",
                                                user["name"],
                                                "--newpassword=%s" % newpasswd,
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
            # self.assertCmdSuccess(result, "Ensure setpassword runs")
            self.assertEquals(err,"","setpassword with url")
            self.assertMatch(out, "Changed password OK", "setpassword with url")

        for user in self.users:
            newpasswd = self.randomPass()
            (result, out, err) = self.runsubcmd("user", "setpassword",
                                                user["name"],
                                                "--newpassword=%s" % newpasswd)
            # self.assertCmdSuccess(result, "Ensure setpassword runs")
            self.assertEquals(err,"","setpassword without url")
            self.assertMatch(out, "Changed password OK", "setpassword without url")

        for user in self.users:
            newpasswd = self.randomPass()
            (result, out, err) = self.runsubcmd("user", "setpassword",
                                                user["name"],
                                                "--newpassword=%s" % newpasswd,
                                                "--must-change-at-next-login",
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
            # self.assertCmdSuccess(result, "Ensure setpassword runs")
            self.assertEquals(err,"","setpassword with forced change")
            self.assertMatch(out, "Changed password OK", "setpassword with forced change")




    def test_setexpiry(self):
        twodays = time.time() + (2 * 24 * 60 * 60)

        for user in self.users:
            (result, out, err) = self.runsubcmd("user", "setexpiry", user["name"],
                                                "--days=2",
                                                "-H", "ldap://%s" % os.environ["DC_SERVER"],
                                                "-U%s%%%s" % (os.environ["DC_USERNAME"], os.environ["DC_PASSWORD"]))
            self.assertCmdSuccess(result, "Can we run setexpiry with names")
            self.assertIn("Expiry for user '%s' set to 2 days." % user["name"], out)

        for user in self.users:
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
        self.assertCmdSuccess(result, "Can we run setexpiry with a filter")

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
        self.assertCmdSuccess(result, "Error running list")

        search_filter = ("(&(objectClass=user)(userAccountControl:%s:=%u))" %
                         (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT))

        userlist = self.samdb.search(base=self.samdb.domain_dn(),
                                     scope=ldb.SCOPE_SUBTREE,
                                     expression=search_filter,
                                     attrs=["samaccountname"])

        self.assertTrue(len(userlist) > 0, "no users found in samdb")

        for userobj in userlist:
            name = userobj.get("samaccountname", idx=0)
            found = self.assertMatch(out, name,
                                     "user '%s' not found" % name)
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


# samba-tool user add command didn't support users with empty gecos if none is
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
        (result, out, err) = self.runsubcmd("user", "add", user["name"], user["password"],
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

        msg = "command should return %s" % err
        self.assertCmdSuccess(result, msg)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertIn("User '%s' created successfully" % user["name"], out)

        self._check_posix_user(user)
        self.runsubcmd("user", "delete", user["name"])

        # Check if overriding the attributes from NSS with explicit values works
        #
        # get a user with all random posix attributes
        user = self._randomPosixUser({"name": u[0]})
        # create a user with posix attributes from nss but override all of them with the
        # random ones just obtained
        (result, out, err) = self.runsubcmd("user", "add", user["name"], user["password"],
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

        msg = "command should return %s" % err
        self.assertCmdSuccess(result, msg)
        self.assertEquals(err,"","Shouldn't be any error messages")
        self.assertIn("User '%s' created successfully" % user["name"], out)

        self._check_posix_user(user)
        self.runsubcmd("user", "delete", user["name"])

    def _randomUser(self, base={}):
        """create a user with random attribute values, you can specify base attributes"""
        user = {
            "name": self.randomName(),
            "password": self.randomPass(),
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

    def _check_user(self, user):
        """ check if a user from SamDB has the same attributes as its template """
        found = self._find_user(user["name"])

        self.assertEquals("%s" % found.get("name"), "%(given-name)s %(surname)s" % user)
        self.assertEquals("%s" % found.get("title"), user["job-title"])
        self.assertEquals("%s" % found.get("company"), user["company"])
        self.assertEquals("%s" % found.get("description"), user["description"])
        self.assertEquals("%s" % found.get("department"), user["department"])

    def _check_posix_user(self, user):
        """ check if a posix_user from SamDB has the same attributes as its template """
        found = self._find_user(user["name"])

        self.assertEquals("%s" % found.get("loginShell"), user["loginShell"])
        self.assertEquals("%s" % found.get("gecos"), user["gecos"])
        self.assertEquals("%s" % found.get("uidNumber"), "%s" % user["uidNumber"])
        self.assertEquals("%s" % found.get("gidNumber"), "%s" % user["gidNumber"])
        self.assertEquals("%s" % found.get("uid"), user["uid"])
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

    def _find_user(self, name):
        search_filter = "(&(sAMAccountName=%s)(objectCategory=%s,%s))" % (ldb.binary_encode(name), "CN=Person,CN=Schema,CN=Configuration", self.samdb.domain_dn())
        userlist = self.samdb.search(base=self.samdb.domain_dn(),
                                  scope=ldb.SCOPE_SUBTREE,
                                  expression=search_filter, attrs=[])
        if userlist:
            return userlist[0]
        else:
            return None
