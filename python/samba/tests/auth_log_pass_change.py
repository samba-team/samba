# Unix SMB/CIFS implementation.
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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
"""Tests for the Auth and AuthZ logging of password changes.
"""

import samba.tests
from samba.samdb import SamDB
from samba.auth import system_session
import os
import samba.tests.auth_log_base
from samba.tests import delete_force
from samba.net import Net
import samba
from subprocess import call
from ldb import LdbError
from samba.tests.password_test import PasswordCommon
from samba.dcerpc.windows_event_ids import (
    EVT_ID_SUCCESSFUL_LOGON,
    EVT_ID_UNSUCCESSFUL_LOGON,
    EVT_LOGON_NETWORK
)

USER_NAME = "authlogtestuser"
USER_PASS = samba.generate_random_password(32, 32)


class AuthLogPassChangeTests(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogPassChangeTests, self).setUp()

        self.server_ip = os.environ["SERVER_IP"]

        host = "ldap://%s" % os.environ["SERVER"]
        self.ldb = SamDB(url=host,
                         session_info=system_session(),
                         credentials=self.get_credentials(),
                         lp=self.get_loadparm())

        print("ldb %s" % type(self.ldb))
        # Gets back the basedn
        base_dn = self.ldb.domain_dn()
        print("base_dn %s" % base_dn)

        # permit password changes during this test
        PasswordCommon.allow_password_changes(self, self.ldb)

        self.base_dn = self.ldb.domain_dn()

        # (Re)adds the test user USER_NAME with password USER_PASS
        delete_force(self.ldb, "cn=" + USER_NAME + ",cn=users," + self.base_dn)
        self.ldb.add({
            "dn": "cn=" + USER_NAME + ",cn=users," + self.base_dn,
            "objectclass": "user",
            "sAMAccountName": USER_NAME,
            "userPassword": USER_PASS
        })

        # discard any auth log messages for the password setup
        self.discardMessages()

    def tearDown(self):
        super(AuthLogPassChangeTests, self).tearDown()

    def test_admin_change_password(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["status"] == "NT_STATUS_OK") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "SAMR Password Change") and
                    (msg["Authentication"]["authDescription"] ==
                        "samr_ChangePasswordUser3") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_SUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword!!42"

        net.change_password(newpassword=password,
                            username=USER_NAME,
                            oldpassword=USER_PASS)
        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    def test_admin_change_password_new_password_fails_restriction(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["status"] ==
                        "NT_STATUS_PASSWORD_RESTRICTION") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "SAMR Password Change") and
                    (msg["Authentication"]["authDescription"] ==
                        "samr_ChangePasswordUser3") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_UNSUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword"

        exception_thrown = False
        try:
            net.change_password(newpassword=password,
                                oldpassword=USER_PASS,
                                username=USER_NAME)
        except Exception:
            exception_thrown = True
        self.assertEqual(True, exception_thrown,
                          "Expected exception not thrown")
        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    def test_admin_change_password_unknown_user(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["status"] ==
                        "NT_STATUS_NO_SUCH_USER") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "SAMR Password Change") and
                    (msg["Authentication"]["authDescription"] ==
                        "samr_ChangePasswordUser3") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_UNSUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword!!42"

        exception_thrown = False
        try:
            net.change_password(newpassword=password,
                                oldpassword=USER_PASS,
                                username="badUser")
        except Exception:
            exception_thrown = True
        self.assertEqual(True, exception_thrown,
                          "Expected exception not thrown")

        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    def test_admin_change_password_bad_original_password(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["status"] ==
                        "NT_STATUS_WRONG_PASSWORD") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "SAMR Password Change") and
                    (msg["Authentication"]["authDescription"] ==
                        "samr_ChangePasswordUser3") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_UNSUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword!!42"

        exception_thrown = False
        try:
            net.change_password(newpassword=password,
                                oldpassword="badPassword",
                                username=USER_NAME)
        except Exception:
            exception_thrown = True
        self.assertEqual(True, exception_thrown,
                          "Expected exception not thrown")

        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    # net rap password changes are broken, but they trigger enough of the
    # server side behaviour to exercise the code paths of interest.
    # if we used the real password it would be too long and does not hash
    # correctly, so we just check it triggers the wrong password path.
    def test_rap_change_password(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "SAMR Password Change") and
                    (msg["Authentication"]["status"] ==
                        "NT_STATUS_WRONG_PASSWORD") and
                    (msg["Authentication"]["authDescription"] ==
                        "OemChangePasswordUser2") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_UNSUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        username = os.environ["USERNAME"]
        server = os.environ["SERVER"]
        password = os.environ["PASSWORD"]
        server_param = "--server=%s" % server
        creds = "-U%s%%%s" % (username, password)
        call(["bin/net", "rap", server_param,
              "password", USER_NAME, "notMyPassword", "notGoingToBeMyPassword",
              server, creds, "--option=client ipc max protocol=nt1"])
        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    def test_ldap_change_password(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["status"] == "NT_STATUS_OK") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "LDAP Password Change") and
                    (msg["Authentication"]["authDescription"] ==
                        "LDAP Modify") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_SUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        new_password = samba.generate_random_password(32, 32)
        self.ldb.modify_ldif(
            "dn: cn=" + USER_NAME + ",cn=users," + self.base_dn + "\n" +
            "changetype: modify\n" +
            "delete: userPassword\n" +
            "userPassword: " + USER_PASS + "\n" +
            "add: userPassword\n" +
            "userPassword: " + new_password + "\n")

        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    #
    # Currently this does not get logged, so we expect to only see the log
    # entries for the underlying ldap bind.
    #
    def test_ldap_change_password_bad_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"] == "LDAP" and
                    msg["Authorization"]["authType"] == "krb5")

        new_password = samba.generate_random_password(32, 32)
        try:
            self.ldb.modify_ldif(
                "dn: cn=" + "badUser" + ",cn=users," + self.base_dn + "\n" +
                "changetype: modify\n" +
                "delete: userPassword\n" +
                "userPassword: " + USER_PASS + "\n" +
                "add: userPassword\n" +
                "userPassword: " + new_password + "\n")
            self.fail()
        except LdbError as e:
            (num, msg) = e.args
            pass

        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")

    def test_ldap_change_password_bad_original_password(self):
        def isLastExpectedMessage(msg):
            return ((msg["type"] == "Authentication") and
                    (msg["Authentication"]["status"] ==
                        "NT_STATUS_WRONG_PASSWORD") and
                    (msg["Authentication"]["serviceDescription"] ==
                        "LDAP Password Change") and
                    (msg["Authentication"]["authDescription"] ==
                        "LDAP Modify") and
                    (msg["Authentication"]["eventId"] ==
                        EVT_ID_UNSUCCESSFUL_LOGON) and
                    (msg["Authentication"]["logonType"] ==
                        EVT_LOGON_NETWORK))

        new_password = samba.generate_random_password(32, 32)
        try:
            self.ldb.modify_ldif(
                "dn: cn=" + USER_NAME + ",cn=users," + self.base_dn + "\n" +
                "changetype: modify\n" +
                "delete: userPassword\n" +
                "userPassword: " + "badPassword" + "\n" +
                "add: userPassword\n" +
                "userPassword: " + new_password + "\n")
            self.fail()
        except LdbError as e1:
            (num, msg) = e1.args
            pass

        self.assertTrue(self.waitForMessages(isLastExpectedMessage),
                        "Did not receive the expected message")
