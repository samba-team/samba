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
from samba.dcerpc.messaging import MSG_GROUP_LOG, DSDB_GROUP_EVENT_NAME
from samba.dcerpc.windows_event_ids import (
    EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
    EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP
)
from samba.samdb import SamDB
from samba.auth import system_session
import os
from samba.tests.audit_log_base import AuditLogTestBase
from samba.tests import delete_force
import ldb
from ldb import FLAG_MOD_REPLACE

USER_NAME = "grpadttstuser01"
USER_PASS = samba.generate_random_password(32, 32)

SECOND_USER_NAME = "grpadttstuser02"
SECOND_USER_PASS = samba.generate_random_password(32, 32)

GROUP_NAME_01 = "group-audit-01"
GROUP_NAME_02 = "group-audit-02"


class GroupAuditTests(AuditLogTestBase):

    def setUp(self):
        self.message_type = MSG_GROUP_LOG
        self.event_type = DSDB_GROUP_EVENT_NAME
        super(GroupAuditTests, self).setUp()

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
        self.ldb.add({
            "dn": "cn=" + USER_NAME + ",cn=users," + self.base_dn,
            "objectclass": "user",
            "sAMAccountName": USER_NAME,
            "userPassword": USER_PASS
        })
        self.ldb.newgroup(GROUP_NAME_01)
        self.ldb.newgroup(GROUP_NAME_02)

    def tearDown(self):
        super(GroupAuditTests, self).tearDown()
        delete_force(self.ldb, "cn=" + USER_NAME + ",cn=users," + self.base_dn)
        self.ldb.deletegroup(GROUP_NAME_01)
        self.ldb.deletegroup(GROUP_NAME_02)

    def test_add_and_remove_users_from_group(self):

        #
        # Wait for the primary group change for the created user.
        #
        messages = self.waitForMessages(2)
        print("Received %d messages" % len(messages))
        self.assertEqual(2,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["groupChange"]

        self.assertEqual("PrimaryGroup", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=domain users,cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

        # Check the Add message for the new users primary group
        audit = messages[1]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=domain users,cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        self.assertEqual(EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
                          audit["eventId"])
        #
        # Add the user to a group
        #
        self.discardMessages()

        self.ldb.add_remove_group_members(GROUP_NAME_01, [USER_NAME])
        messages = self.waitForMessages(1)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

        #
        # Add the user to another group
        #
        self.discardMessages()
        self.ldb.add_remove_group_members(GROUP_NAME_02, [USER_NAME])

        messages = self.waitForMessages(1)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_02 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

        #
        # Remove the user from a group
        #
        self.discardMessages()
        self.ldb.add_remove_group_members(
            GROUP_NAME_01,
            [USER_NAME],
            add_members_operation=False)
        messages = self.waitForMessages(1)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["groupChange"]

        self.assertEqual("Removed", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

        #
        # Re-add the user to a group
        #
        self.discardMessages()
        self.ldb.add_remove_group_members(GROUP_NAME_01, [USER_NAME])

        messages = self.waitForMessages(1)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

    def test_change_primary_group(self):

        #
        # Wait for the primary group change for the created user.
        #
        messages = self.waitForMessages(2)
        print("Received %d messages" % len(messages))
        self.assertEqual(2,
                          len(messages),
                          "Did not receive the expected number of messages")

        # Check the PrimaryGroup message
        audit = messages[0]["groupChange"]

        self.assertEqual("PrimaryGroup", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=domain users,cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")

        # Check the Add message for the new users primary group
        audit = messages[1]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=domain users,cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        self.assertEqual(EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
                          audit["eventId"])

        #
        # Add the user to a group, the user needs to be a member of a group
        # before there primary group can be set to that group.
        #
        self.discardMessages()

        self.ldb.add_remove_group_members(GROUP_NAME_01, [USER_NAME])
        messages = self.waitForMessages(1)
        print("Received %d messages" % len(messages))
        self.assertEqual(1,
                          len(messages),
                          "Did not receive the expected number of messages")
        audit = messages[0]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertEqual(EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
                          audit["eventId"])

        #
        # Change the primary group of a user
        #
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        # get the primaryGroupToken of the group
        res = self.ldb.search(base=group_dn, attrs=["primaryGroupToken"],
                              scope=ldb.SCOPE_BASE)
        group_id = res[0]["primaryGroupToken"]

        # set primaryGroupID attribute of the user to that group
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, user_dn)
        m["primaryGroupID"] = ldb.MessageElement(
            group_id,
            FLAG_MOD_REPLACE,
            "primaryGroupID")
        self.discardMessages()
        self.ldb.modify(m)

        #
        # Wait for the primary group change.
        # Will see the user removed from the new group
        #          the user added to their old primary group
        #          and a new primary group event.
        #
        messages = self.waitForMessages(3)
        print("Received %d messages" % len(messages))
        self.assertEqual(3,
                          len(messages),
                          "Did not receive the expected number of messages")

        audit = messages[0]["groupChange"]
        self.assertEqual("Removed", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertEqual(EVT_ID_USER_REMOVED_FROM_GLOBAL_SEC_GROUP,
                          audit["eventId"])

        audit = messages[1]["groupChange"]

        self.assertEqual("Added", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=domain users,cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
        self.assertEqual(EVT_ID_USER_ADDED_TO_GLOBAL_SEC_GROUP,
                          audit["eventId"])

        audit = messages[2]["groupChange"]

        self.assertEqual("PrimaryGroup", audit["action"])
        user_dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        group_dn = "cn=" + GROUP_NAME_01 + ",cn=users," + self.base_dn
        self.assertTrue(user_dn.lower(), audit["user"].lower())
        self.assertTrue(group_dn.lower(), audit["group"].lower())
        self.assertRegexpMatches(audit["remoteAddress"],
                                 self.remoteAddress)
        self.assertTrue(self.is_guid(audit["sessionId"]))
        session_id = self.get_session()
        self.assertEqual(session_id, audit["sessionId"])
        service_description = self.get_service_description()
        self.assertEqual(service_description, "LDAP")
