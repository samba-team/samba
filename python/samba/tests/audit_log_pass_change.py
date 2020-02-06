# Tests for SamDb password change audit logging.
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

from __future__ import print_function
"""Tests for the SamDb logging of password changes.
"""

import samba.tests
from samba.dcerpc.messaging import MSG_DSDB_PWD_LOG, DSDB_PWD_EVENT_NAME
from samba.samdb import SamDB
from samba.auth import system_session
import os
from samba.tests.audit_log_base import AuditLogTestBase
from samba.tests import delete_force
from samba.net import Net
from ldb import ERR_INSUFFICIENT_ACCESS_RIGHTS
from samba.dcerpc.windows_event_ids import (
    EVT_ID_PASSWORD_CHANGE,
    EVT_ID_PASSWORD_RESET
)


USER_NAME = "auditlogtestuser"
USER_PASS = samba.generate_random_password(32, 32)

SECOND_USER_NAME = "auditlogtestuser02"
SECOND_USER_PASS = samba.generate_random_password(32, 32)


class AuditLogPassChangeTests(AuditLogTestBase):

    def setUp(self):
        self.message_type = MSG_DSDB_PWD_LOG
        self.event_type = DSDB_PWD_EVENT_NAME
        super(AuditLogPassChangeTests, self).setUp()

        self.server_ip = os.environ["SERVER_IP"]

        host = "ldap://%s" % os.environ["SERVER"]
        self.ldb = SamDB(url=host,
                         session_info=system_session(),
                         credentials=self.get_credentials(),
                         lp=self.get_loadparm())
        self.server = os.environ["SERVER"]

        # Gets back the basedn
        self.base_dn = self.ldb.domain_dn()

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
        delete_force(
            self.ldb,
            "cn=" + SECOND_USER_NAME + ",cn=users," + self.base_dn)
        self.ldb.add({
            "dn": "cn=" + USER_NAME + ",cn=users," + self.base_dn,
            "objectclass": "user",
            "sAMAccountName": USER_NAME,
            "userPassword": USER_PASS
        })

    #
    # Discard the messages from the setup code
    #
    def discardSetupMessages(self, dn):
        self.waitForMessages(1, dn=dn)
        self.discardMessages()

    def tearDown(self):
        super(AuditLogPassChangeTests, self).tearDown()

    def test_net_change_password(self):

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        self.discardSetupMessages(dn)

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server)
        password = "newPassword!!42"

        net.change_password(newpassword=password,
                            username=USER_NAME,
                            oldpassword=USER_PASS)

        messages = self.waitForMessages(1, net, dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_CHANGE, audit["eventId"])
        self.assertEqual("Change", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "DCE/RPC")
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_net_set_password_user_without_permission(self):

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        self.discardSetupMessages(dn)

        self.ldb.newuser(SECOND_USER_NAME, SECOND_USER_PASS)

        #
        # Get the password reset from the user add
        #
        dn = "CN=" + SECOND_USER_NAME + ",CN=Users," + self.base_dn
        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["transactionId"]))
        self.assertEqual(0, audit["statusCode"])
        self.assertEqual("Success", audit["status"])
        self.discardMessages()

        creds = self.insta_creds(
            template=self.get_credentials(),
            username=SECOND_USER_NAME,
            userpass=SECOND_USER_PASS,
            kerberos_state=None)

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server)
        password = "newPassword!!42"
        domain = lp.get("workgroup")

        try:
            net.set_password(newpassword=password,
                             account_name=USER_NAME,
                             domain_name=domain)
            self.fail("Expected exception not thrown")
        except Exception:
            pass

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        messages = self.waitForMessages(1, net, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "DCE/RPC")
        self.assertTrue(self.is_guid(audit["transactionId"]))
        self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, audit["statusCode"])
        self.assertEqual("insufficient access rights", audit["status"])

    def test_net_set_password(self):

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        self.discardSetupMessages(dn)

        creds = self.insta_creds(template=self.get_credentials())

        lp = self.get_loadparm()
        net = Net(creds, lp, server=self.server)
        password = "newPassword!!42"
        domain = lp.get("workgroup")

        net.set_password(newpassword=password,
                         account_name=USER_NAME,
                         domain_name=domain)

        dn = "CN=" + USER_NAME + ",CN=Users," + self.base_dn
        messages = self.waitForMessages(1, net, dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "DCE/RPC")
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_ldap_change_password(self):

        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        self.discardSetupMessages(dn)

        new_password = samba.generate_random_password(32, 32)
        self.ldb.modify_ldif(
            "dn: " + dn + "\n" +
            "changetype: modify\n" +
            "delete: userPassword\n" +
            "userPassword: " + USER_PASS + "\n" +
            "add: userPassword\n" +
            "userPassword: " + new_password + "\n")

        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_CHANGE, audit["eventId"])
        self.assertEqual("Change", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_ldap_replace_password(self):

        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        self.discardSetupMessages(dn)

        new_password = samba.generate_random_password(32, 32)
        self.ldb.modify_ldif(
            "dn: " + dn + "\n" +
            "changetype: modify\n" +
            "replace: userPassword\n" +
            "userPassword: " + new_password + "\n")

        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["transactionId"]))

    def test_ldap_add_user(self):

        # The setup code adds a user, so we check for the password event
        # generated by it.
        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        messages = self.waitForMessages(1, dn=dn)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")

        #
        # The first message should be the reset from the Setup code.
        #
        audit = messages[0]["passwordChange"]
        self.assertEqual(EVT_ID_PASSWORD_RESET, audit["eventId"])
        self.assertEqual("Reset", audit["action"])
        self.assertEqual(dn, audit["dn"])
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertTrue(self.is_guid(audit["sessionId"]))
        self.assertTrue(self.is_guid(audit["transactionId"]))
