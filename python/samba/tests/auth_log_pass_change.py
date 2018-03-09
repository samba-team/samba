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

from samba import auth
import samba.tests
from samba.messaging import Messaging
from samba.samdb import SamDB
from samba.auth import system_session
import json
import os
import samba.tests.auth_log_base
from samba.tests import delete_force
from samba.net import Net
from samba import ntstatus
import samba
from subprocess import call
from ldb import LdbError

USER_NAME = "authlogtestuser"
USER_PASS = samba.generate_random_password(32,32)

class AuthLogPassChangeTests(samba.tests.auth_log_base.AuthLogTestBase):

    def setUp(self):
        super(AuthLogPassChangeTests, self).setUp()

        self.remoteAddress = os.environ["CLIENT_IP"]
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

        # Gets back the configuration basedn
        configuration_dn = self.ldb.get_config_basedn().get_linearized()

        # Get the old "dSHeuristics" if it was set
        dsheuristics = self.ldb.get_dsheuristics()

        # Set the "dSHeuristics" to activate the correct "userPassword"
        # behaviour
        self.ldb.set_dsheuristics("000000001")

        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb.set_dsheuristics, dsheuristics)

        # Get the old "minPwdAge"
        minPwdAge = self.ldb.get_minPwdAge()

        # Set it temporarily to "0"
        self.ldb.set_minPwdAge("0")
        self.base_dn = self.ldb.domain_dn()

        # Reset the "minPwdAge" as it was before
        self.addCleanup(self.ldb.set_minPwdAge, minPwdAge)

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
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_OK" and
                    msg["Authentication"]["serviceDescription"]
                        == "SAMR Password Change" and
                    msg["Authentication"]["authDescription"]
                        == "samr_ChangePasswordUser3")

        creds = self.insta_creds(template = self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword!!42"

        net.change_password(newpassword=password.encode('utf-8'),
                            username=USER_NAME,
                            oldpassword=USER_PASS)


        messages = self.waitForMessages(isLastExpectedMessage)
        print("Received %d messages" % len(messages))
        self.assertEquals(8,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_admin_change_password_new_password_fails_restriction(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_PASSWORD_RESTRICTION" and
                    msg["Authentication"]["serviceDescription"]
                        == "SAMR Password Change" and
                    msg["Authentication"]["authDescription"]
                        == "samr_ChangePasswordUser3")

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword"

        exception_thrown = False
        try:
            net.change_password(newpassword=password.encode('utf-8'),
                                oldpassword=USER_PASS,
                                username=USER_NAME)
        except Exception as msg:
            exception_thrown = True
        self.assertEquals(True, exception_thrown,
                          "Expected exception not thrown")

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(8,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_admin_change_password_unknown_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_NO_SUCH_USER" and
                    msg["Authentication"]["serviceDescription"]
                        == "SAMR Password Change" and
                    msg["Authentication"]["authDescription"]
                        == "samr_ChangePasswordUser3")

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword!!42"

        exception_thrown = False
        try:
            net.change_password(newpassword=password.encode('utf-8'),
                                oldpassword=USER_PASS,
                                username="badUser")
        except Exception as msg:
            exception_thrown = True
        self.assertEquals(True, exception_thrown,
                          "Expected exception not thrown")

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(8,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_admin_change_password_bad_original_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["serviceDescription"]
                        == "SAMR Password Change" and
                    msg["Authentication"]["authDescription"]
                        == "samr_ChangePasswordUser3")

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server_ip)
        password = "newPassword!!42"

        exception_thrown = False
        try:
            net.change_password(newpassword=password.encode('utf-8'),
                                oldpassword="badPassword",
                                username=USER_NAME)
        except Exception as msg:
            exception_thrown = True
        self.assertEquals(True, exception_thrown,
                          "Expected exception not thrown")

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(8,
                          len(messages),
                          "Did not receive the expected number of messages")

    # net rap password changes are broken, but they trigger enough of the
    # server side behaviour to exercise the code paths of interest.
    # if we used the real password it would be too long and does not hash
    # correctly, so we just check it triggers the wrong password path.
    def test_rap_change_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["serviceDescription"]
                        == "SAMR Password Change" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["authDescription"]
                        == "OemChangePasswordUser2")

        username = os.environ["USERNAME"]
        server = os.environ["SERVER"]
        password = os.environ["PASSWORD"]
        server_param = "--server=%s" % server
        creds = "-U%s%%%s" % (username,password)
        call(["bin/net", "rap", server_param,
              "password", USER_NAME, "notMyPassword", "notGoingToBeMyPassword",
              server, creds, "--option=client ipc max protocol=nt1"])

        messages = self.waitForMessages(isLastExpectedMessage)
        self.assertEquals(7,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_ldap_change_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_OK" and
                    msg["Authentication"]["serviceDescription"]
                        == "LDAP Password Change" and
                    msg["Authentication"]["authDescription"]
                        == "LDAP Modify")

        new_password = samba.generate_random_password(32,32)
        self.ldb.modify_ldif(
            "dn: cn=" + USER_NAME + ",cn=users," + self.base_dn + "\n" +
            "changetype: modify\n" +
            "delete: userPassword\n" +
            "userPassword: " + USER_PASS + "\n" +
            "add: userPassword\n" +
            "userPassword: " + new_password + "\n"
        )

        messages = self.waitForMessages(isLastExpectedMessage)
        print("Received %d messages" % len(messages))
        self.assertEquals(4,
                          len(messages),
                          "Did not receive the expected number of messages")

    #
    # Currently this does not get logged, so we expect to only see the log
    # entries for the underlying ldap bind.
    #
    def test_ldap_change_password_bad_user(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authorization" and
                    msg["Authorization"]["serviceDescription"]
                        == "LDAP" and
                    msg["Authorization"]["authType"] == "krb5")

        new_password = samba.generate_random_password(32,32)
        try:
            self.ldb.modify_ldif(
                "dn: cn=" + "badUser" + ",cn=users," + self.base_dn + "\n" +
                "changetype: modify\n" +
                "delete: userPassword\n" +
                "userPassword: " + USER_PASS + "\n" +
                "add: userPassword\n" +
                "userPassword: " + new_password + "\n"
            )
            self.fail()
        except LdbError as e:
            (num, msg) = e.args
            pass

        messages = self.waitForMessages(isLastExpectedMessage)
        print("Received %d messages" % len(messages))
        self.assertEquals(3,
                          len(messages),
                          "Did not receive the expected number of messages")

    def test_ldap_change_password_bad_original_password(self):
        def isLastExpectedMessage(msg):
            return (msg["type"] == "Authentication" and
                    msg["Authentication"]["status"]
                        == "NT_STATUS_WRONG_PASSWORD" and
                    msg["Authentication"]["serviceDescription"]
                        == "LDAP Password Change" and
                    msg["Authentication"]["authDescription"]
                        == "LDAP Modify")

        new_password = samba.generate_random_password(32,32)
        try:
            self.ldb.modify_ldif(
                "dn: cn=" + USER_NAME + ",cn=users," + self.base_dn + "\n" +
                "changetype: modify\n" +
                "delete: userPassword\n" +
                "userPassword: " + "badPassword" + "\n" +
                "add: userPassword\n" +
                "userPassword: " + new_password + "\n"
            )
            self.fail()
        except LdbError as e1:
            (num, msg) = e1.args
            pass

        messages = self.waitForMessages(isLastExpectedMessage)
        print("Received %d messages" % len(messages))
        self.assertEquals(4,
                          len(messages),
                          "Did not receive the expected number of messages")
