#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This is a port of the original in testprogs/ejs/ldap.js

from __future__ import print_function
import optparse
import sys
import os
import time

sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.auth import system_session
from samba.compat import get_string
from samba.compat import text_type
from ldb import SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT, ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_ENTRY_ALREADY_EXISTS, ERR_UNWILLING_TO_PERFORM
from ldb import ERR_OTHER, ERR_NO_SUCH_ATTRIBUTE
from ldb import ERR_OBJECT_CLASS_VIOLATION
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import ERR_UNDEFINED_ATTRIBUTE_TYPE
from ldb import ERR_INSUFFICIENT_ACCESS_RIGHTS
from ldb import ERR_INVALID_CREDENTIALS
from ldb import ERR_STRONG_AUTH_REQUIRED
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba.samdb import SamDB
from samba.dsdb import (UF_NORMAL_ACCOUNT, UF_ACCOUNTDISABLE,
                        UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT,
                        UF_PARTIAL_SECRETS_ACCOUNT, UF_TEMP_DUPLICATE_ACCOUNT,
                        UF_INTERDOMAIN_TRUST_ACCOUNT, UF_SMARTCARD_REQUIRED,
                        UF_PASSWD_NOTREQD, UF_LOCKOUT, UF_PASSWORD_EXPIRED, ATYPE_NORMAL_ACCOUNT,
                        GTYPE_SECURITY_BUILTIN_LOCAL_GROUP, GTYPE_SECURITY_DOMAIN_LOCAL_GROUP,
                        GTYPE_SECURITY_GLOBAL_GROUP, GTYPE_SECURITY_UNIVERSAL_GROUP,
                        GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP, GTYPE_DISTRIBUTION_GLOBAL_GROUP,
                        GTYPE_DISTRIBUTION_UNIVERSAL_GROUP,
                        ATYPE_SECURITY_GLOBAL_GROUP, ATYPE_SECURITY_UNIVERSAL_GROUP,
                        ATYPE_SECURITY_LOCAL_GROUP, ATYPE_DISTRIBUTION_GLOBAL_GROUP,
                        ATYPE_DISTRIBUTION_UNIVERSAL_GROUP, ATYPE_DISTRIBUTION_LOCAL_GROUP,
                        ATYPE_WORKSTATION_TRUST)
from samba.dcerpc.security import (DOMAIN_RID_USERS, DOMAIN_RID_ADMINS,
                                   DOMAIN_RID_DOMAIN_MEMBERS, DOMAIN_RID_DCS, DOMAIN_RID_READONLY_DCS)

from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba.dcerpc import drsuapi
from samba.dcerpc import security
from samba.tests import delete_force
from samba import gensec
from samba import werror

parser = optparse.OptionParser("sam.py [options] <host>")
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

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)


class SamTests(samba.tests.TestCase):

    def setUp(self):
        super(SamTests, self).setUp()
        self.ldb = ldb
        self.base_dn = ldb.domain_dn()

        print("baseDN: %s\n" % self.base_dn)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptest\,specialuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)

    def test_users_groups(self):
        """This tests the SAM users and groups behaviour"""
        print("Testing users and groups behaviour\n")

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        ldb.add({
            "dn": "cn=ldaptestgroup2,cn=users," + self.base_dn,
            "objectclass": "group"})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["objectSID"])
        self.assertTrue(len(res1) == 1)
        obj_sid = get_string(ldb.schema_format_value("objectSID",
                                                     res1[0]["objectSID"][0]))
        group_rid_1 = security.dom_sid(obj_sid).split()[1]

        res1 = ldb.search("cn=ldaptestgroup2,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["objectSID"])
        self.assertTrue(len(res1) == 1)
        obj_sid = get_string(ldb.schema_format_value("objectSID",
                                                     res1[0]["objectSID"][0]))
        group_rid_2 = security.dom_sid(obj_sid).split()[1]

        # Try to create a user with an invalid account name
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "sAMAccountName": "administrator"})
            self.fail()
        except LdbError as e9:
            (num, _) = e9.args
            self.assertEqual(num, ERR_ENTRY_ALREADY_EXISTS)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Try to create a user with an invalid account name
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "sAMAccountName": []})
            self.fail()
        except LdbError as e10:
            (num, _) = e10.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Try to create a user with an invalid primary group
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "primaryGroupID": "0"})
            self.fail()
        except LdbError as e11:
            (num, _) = e11.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Try to Create a user with a valid primary group
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "primaryGroupID": str(group_rid_1)})
            self.fail()
        except LdbError as e12:
            (num, _) = e12.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Test to see how we should behave when the user account doesn't
        # exist
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("0", FLAG_MOD_REPLACE,
                                             "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e13:
            (num, _) = e13.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        # Test to see how we should behave when the account isn't a user
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("0", FLAG_MOD_REPLACE,
                                             "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e14:
            (num, _) = e14.args
            self.assertEqual(num, ERR_OBJECT_CLASS_VIOLATION)

        # Test default primary groups on add operations

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_USERS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD)})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_USERS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # unfortunately the INTERDOMAIN_TRUST_ACCOUNT case cannot be tested
        # since such accounts aren't directly creatable (ACCESS_DENIED)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT |
                                      UF_PASSWD_NOTREQD)})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]),
                          DOMAIN_RID_DOMAIN_MEMBERS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT |
                                      UF_PASSWD_NOTREQD)})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_DCS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Read-only DC accounts are only creatable by
        # UF_WORKSTATION_TRUST_ACCOUNT and work only on DCs >= 2008 (therefore
        # we have a fallback in the assertion)
        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_PARTIAL_SECRETS_ACCOUNT |
                                      UF_WORKSTATION_TRUST_ACCOUNT |
                                      UF_PASSWD_NOTREQD)})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(int(res1[0]["primaryGroupID"][0]) == DOMAIN_RID_READONLY_DCS or
                        int(res1[0]["primaryGroupID"][0]) == DOMAIN_RID_DOMAIN_MEMBERS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Test default primary groups on modify operations

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_NORMAL_ACCOUNT |
                                                     UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_REPLACE,
                                                 "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_USERS)

        # unfortunately the INTERDOMAIN_TRUST_ACCOUNT case cannot be tested
        # since such accounts aren't directly creatable (ACCESS_DENIED)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "computer"})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_USERS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_WORKSTATION_TRUST_ACCOUNT |
                                                     UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_REPLACE,
                                                 "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_DOMAIN_MEMBERS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_SERVER_TRUST_ACCOUNT |
                                                     UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_REPLACE,
                                                 "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_DCS)

        # Read-only DC accounts are only creatable by
        # UF_WORKSTATION_TRUST_ACCOUNT and work only on DCs >= 2008 (therefore
        # we have a fallback in the assertion)
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_PARTIAL_SECRETS_ACCOUNT |
                                                     UF_WORKSTATION_TRUST_ACCOUNT |
                                                     UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_REPLACE,
                                                 "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(int(res1[0]["primaryGroupID"][0]) == DOMAIN_RID_READONLY_DCS or
                        int(res1[0]["primaryGroupID"][0]) == DOMAIN_RID_DOMAIN_MEMBERS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Recreate account for further tests

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        # Try to set an invalid account name
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement("administrator", FLAG_MOD_REPLACE,
                                             "sAMAccountName")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e15:
            (num, _) = e15.args
            self.assertEqual(num, ERR_ENTRY_ALREADY_EXISTS)

        # But to reset the actual "sAMAccountName" should still be possible
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountName"])
        self.assertTrue(len(res1) == 1)
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement(res1[0]["sAMAccountName"][0], FLAG_MOD_REPLACE,
                                             "sAMAccountName")
        ldb.modify(m)

        # And another (free) name should be possible as well
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement("xxx_ldaptestuser_xxx", FLAG_MOD_REPLACE,
                                             "sAMAccountName")
        ldb.modify(m)

        # We should be able to reset our actual primary group
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(DOMAIN_RID_USERS), FLAG_MOD_REPLACE,
                                             "primaryGroupID")
        ldb.modify(m)

        # Try to add invalid primary group
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("0", FLAG_MOD_REPLACE,
                                             "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e16:
            (num, _) = e16.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Try to make group 1 primary - should be denied since it is not yet
        # secondary
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(group_rid_1),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e17:
            (num, _) = e17.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Make group 1 secondary
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_REPLACE, "member")
        ldb.modify(m)

        # Make group 1 primary
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(group_rid_1),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        ldb.modify(m)

        # Try to delete group 1 - should be denied
        try:
            ldb.delete("cn=ldaptestgroup,cn=users," + self.base_dn)
            self.fail()
        except LdbError as e18:
            (num, _) = e18.args
            self.assertEqual(num, ERR_ENTRY_ALREADY_EXISTS)

        # Try to add group 1 also as secondary - should be denied
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e19:
            (num, _) = e19.args
            self.assertEqual(num, ERR_ENTRY_ALREADY_EXISTS)

        # Try to add invalid member to group 1 - should be denied
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement(
            "cn=ldaptestuser3,cn=users," + self.base_dn,
            FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e20:
            (num, _) = e20.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        # Make group 2 secondary
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

        # Swap the groups
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(group_rid_2),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        ldb.modify(m)

        # Swap the groups (does not really make sense but does the same)
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(group_rid_1),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        m["primaryGroupID"] = MessageElement(str(group_rid_2),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        ldb.modify(m)

        # Old primary group should contain a "member" attribute for the user,
        # the new shouldn't contain anymore one
        res1 = ldb.search("cn=ldaptestgroup, cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["member"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(len(res1[0]["member"]) == 1)
        self.assertEqual(str(res1[0]["member"][0]).lower(),
                          ("cn=ldaptestuser,cn=users," + self.base_dn).lower())

        res1 = ldb.search("cn=ldaptestgroup2, cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["member"])
        self.assertTrue(len(res1) == 1)
        self.assertFalse("member" in res1[0])

        # Primary group member
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_DELETE, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e21:
            (num, _) = e21.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Delete invalid group member
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser1,cn=users," + self.base_dn,
                                     FLAG_MOD_DELETE, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e22:
            (num, _) = e22.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Also this should be denied
        try:
            ldb.add({
                "dn": "cn=ldaptestuser2,cn=users," + self.base_dn,
                "objectclass": "user",
                "primaryGroupID": "0"})
            self.fail()
        except LdbError as e23:
            (num, _) = e23.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Recreate user accounts

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        ldb.add({
            "dn": "cn=ldaptestuser2,cn=users," + self.base_dn,
            "objectclass": "user"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

        # Already added
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e24:
            (num, _) = e24.args
            self.assertEqual(num, ERR_ENTRY_ALREADY_EXISTS)

        # Already added, but as <SID=...>
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["objectSid"])
        self.assertTrue(len(res1) == 1)
        sid_bin = res1[0]["objectSid"][0]
        sid_str = ("<SID=" + get_string(ldb.schema_format_value("objectSid", sid_bin)) + ">").upper()

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement(sid_str, FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e25:
            (num, _) = e25.args
            self.assertEqual(num, ERR_ENTRY_ALREADY_EXISTS)

        # Invalid member
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser1,cn=users," + self.base_dn,
                                     FLAG_MOD_REPLACE, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e26:
            (num, _) = e26.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        # Invalid member
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement(["cn=ldaptestuser,cn=users," + self.base_dn,
                                      "cn=ldaptestuser1,cn=users," + self.base_dn],
                                     FLAG_MOD_REPLACE, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e27:
            (num, _) = e27.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        # Invalid member
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_REPLACE, "member")
        m["member"] = MessageElement("cn=ldaptestuser1,cn=users," + self.base_dn,
                                     FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e28:
            (num, _) = e28.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        m["member"] = MessageElement(["cn=ldaptestuser,cn=users," + self.base_dn,
                                      "cn=ldaptestuser2,cn=users," + self.base_dn],
                                     FLAG_MOD_REPLACE, "member")
        ldb.modify(m)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)

        # Make also a small test for accounts with special DNs ("," in this case)
        ldb.add({
            "dn": "cn=ldaptest\,specialuser,cn=users," + self.base_dn,
            "objectclass": "user"})
        delete_force(self.ldb, "cn=ldaptest\,specialuser,cn=users," + self.base_dn)

    def test_sam_attributes(self):
        """Test the behaviour of special attributes of SAM objects"""
        print("Testing the behaviour of special attributes of SAM objects\n")

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})
        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(str(GTYPE_SECURITY_GLOBAL_GROUP), FLAG_MOD_ADD,
                                        "groupType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e29:
            (num, _) = e29.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        # Delete protection tests

        for attr in ["nTSecurityDescriptor", "objectSid", "sAMAccountType",
                     "sAMAccountName", "groupType"]:

            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m[attr] = MessageElement([], FLAG_MOD_REPLACE, attr)
            try:
                ldb.modify(m)
                self.fail()
            except LdbError as e:
                (num, _) = e.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m[attr] = MessageElement([], FLAG_MOD_DELETE, attr)
            try:
                ldb.modify(m)
                self.fail()
            except LdbError as e1:
                (num, _) = e1.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("513", FLAG_MOD_ADD,
                                             "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e30:
            (num, _) = e30.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_NORMAL_ACCOUNT |
                                                     UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_ADD,
                                                 "userAccountControl")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e31:
            (num, _) = e31.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectSid"] = MessageElement("xxxxxxxxxxxxxxxx", FLAG_MOD_ADD,
                                        "objectSid")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e32:
            (num, _) = e32.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountType"] = MessageElement("0", FLAG_MOD_ADD,
                                             "sAMAccountType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e33:
            (num, _) = e33.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement("test", FLAG_MOD_ADD,
                                             "sAMAccountName")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e34:
            (num, _) = e34.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        # Delete protection tests

        for attr in ["nTSecurityDescriptor", "objectSid", "sAMAccountType",
                     "sAMAccountName", "primaryGroupID", "userAccountControl",
                     "accountExpires", "badPasswordTime", "badPwdCount",
                     "codePage", "countryCode", "lastLogoff", "lastLogon",
                     "logonCount", "pwdLastSet"]:

            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m[attr] = MessageElement([], FLAG_MOD_REPLACE, attr)
            try:
                ldb.modify(m)
                self.fail()
            except LdbError as e2:
                (num, _) = e2.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m[attr] = MessageElement([], FLAG_MOD_DELETE, attr)
            try:
                ldb.modify(m)
                self.fail()
            except LdbError as e3:
                (num, _) = e3.args
                self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_primary_group_token_constructed(self):
        """Test the primary group token behaviour (hidden-generated-readonly attribute on groups) and some other constructed attributes"""
        print("Testing primary group token behaviour and other constructed attributes\n")

        try:
            ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "primaryGroupToken": "100"})
            self.fail()
        except LdbError as e35:
            (num, _) = e35.args
            self.assertEqual(num, ERR_UNDEFINED_ATTRIBUTE_TYPE)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        # Testing for one invalid, and one valid operational attribute, but also the things they are built from
        res1 = ldb.search(self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupToken", "canonicalName", "objectClass", "objectSid"])
        self.assertTrue(len(res1) == 1)
        self.assertFalse("primaryGroupToken" in res1[0])
        self.assertTrue("canonicalName" in res1[0])
        self.assertTrue("objectClass" in res1[0])
        self.assertTrue("objectSid" in res1[0])

        res1 = ldb.search(self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupToken", "canonicalName"])
        self.assertTrue(len(res1) == 1)
        self.assertFalse("primaryGroupToken" in res1[0])
        self.assertFalse("objectSid" in res1[0])
        self.assertFalse("objectClass" in res1[0])
        self.assertTrue("canonicalName" in res1[0])

        res1 = ldb.search("cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupToken"])
        self.assertTrue(len(res1) == 1)
        self.assertFalse("primaryGroupToken" in res1[0])

        res1 = ldb.search("cn=ldaptestuser, cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupToken"])
        self.assertTrue(len(res1) == 1)
        self.assertFalse("primaryGroupToken" in res1[0])

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE)
        self.assertTrue(len(res1) == 1)
        self.assertFalse("primaryGroupToken" in res1[0])

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupToken", "objectSID"])
        self.assertTrue(len(res1) == 1)
        primary_group_token = int(res1[0]["primaryGroupToken"][0])

        obj_sid = get_string(ldb.schema_format_value("objectSID", res1[0]["objectSID"][0]))
        rid = security.dom_sid(obj_sid).split()[1]
        self.assertEqual(primary_group_token, rid)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["primaryGroupToken"] = "100"
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e36:
            (num, _) = e36.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_tokenGroups(self):
        """Test the tokenGroups behaviour (hidden-generated-readonly attribute on SAM objects)"""
        print("Testing tokenGroups behaviour\n")

        # The domain object shouldn't contain any "tokenGroups" entry
        res = ldb.search(self.base_dn, scope=SCOPE_BASE, attrs=["tokenGroups"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("tokenGroups" in res[0])

        # The domain administrator should contain "tokenGroups" entries
        # (the exact number depends on the domain/forest function level and the
        # DC software versions)
        res = ldb.search("cn=Administrator,cn=Users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["tokenGroups"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("tokenGroups" in res[0])

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        # This testuser should contain at least two "tokenGroups" entries
        # (exactly two on an unmodified "Domain Users" and "Users" group)
        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["tokenGroups"])
        self.assertTrue(len(res) == 1)
        self.assertTrue(len(res[0]["tokenGroups"]) >= 2)

        # one entry which we need to find should point to domains "Domain Users"
        # group and another entry should point to the builtin "Users"group
        domain_users_group_found = False
        users_group_found = False
        for sid in res[0]["tokenGroups"]:
            obj_sid = get_string(ldb.schema_format_value("objectSID", sid))
            rid = security.dom_sid(obj_sid).split()[1]
            if rid == 513:
                domain_users_group_found = True
            if rid == 545:
                users_group_found = True

        self.assertTrue(domain_users_group_found)
        self.assertTrue(users_group_found)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

    def test_groupType(self):
        """Test the groupType behaviour"""
        print("Testing groupType behaviour\n")

        # You can never create or change to a
        # "GTYPE_SECURITY_BUILTIN_LOCAL_GROUP"

        # Add operation

        # Invalid attribute
        try:
            ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "groupType": "0"})
            self.fail()
        except LdbError as e37:
            (num, _) = e37.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "groupType": str(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP)})
            self.fail()
        except LdbError as e38:
            (num, _) = e38.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "groupType": str(GTYPE_SECURITY_GLOBAL_GROUP)})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "groupType": str(GTYPE_SECURITY_UNIVERSAL_GROUP)})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_UNIVERSAL_GROUP)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "groupType": str(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP)})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_LOCAL_GROUP)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "groupType": str(GTYPE_DISTRIBUTION_GLOBAL_GROUP)})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_GLOBAL_GROUP)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "groupType": str(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP)})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_UNIVERSAL_GROUP)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "groupType": str(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_LOCAL_GROUP)
        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        # Modify operation

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        # We can change in this direction: global <-> universal <-> local
        # On each step also the group type itself (security/distribution) is
        # variable.

        # After creation we should have a "security global group"
        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        # Invalid attribute
        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement("0",
                                            FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e39:
            (num, _) = e39.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Security groups

        # Default is "global group"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        # Change to "local" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e40:
            (num, _) = e40.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_UNIVERSAL_GROUP)

        # Change back to "global"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        # Change back to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_UNIVERSAL_GROUP)

        # Change to "local"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_LOCAL_GROUP)

        # Change to "global" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_SECURITY_GLOBAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e41:
            (num, _) = e41.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change to "builtin local" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e42:
            (num, _) = e42.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        # Change back to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_UNIVERSAL_GROUP)

        # Change to "builtin local" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e43:
            (num, _) = e43.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change back to "global"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        # Change to "builtin local" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e44:
            (num, _) = e44.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Distribution groups

        # Default is "global group"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_GLOBAL_GROUP)

        # Change to local (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e45:
            (num, _) = e45.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_UNIVERSAL_GROUP)

        # Change back to "global"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_GLOBAL_GROUP)

        # Change back to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_UNIVERSAL_GROUP)

        # Change to "local"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_LOCAL_GROUP)

        # Change to "global" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_DISTRIBUTION_GLOBAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e46:
            (num, _) = e46.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change back to "universal"

        # Try to add invalid member to group 1 - should be denied
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement(
            "cn=ldaptestuser3,cn=users," + self.base_dn,
            FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e47:
            (num, _) = e47.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        # Make group 2 secondary
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_UNIVERSAL_GROUP)

        # Change back to "global"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_GLOBAL_GROUP)

        # Both group types: this performs only random checks - all possibilities
        # would require too much code.

        # Default is "global group"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        # Change to "local" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e48:
            (num, _) = e48.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_UNIVERSAL_GROUP)

        # Change back to "global"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        # Change back to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_UNIVERSAL_GROUP)

        # Change to "local"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_DISTRIBUTION_LOCAL_GROUP)

        # Change to "global" (shouldn't work)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
            m["groupType"] = MessageElement(
                str(GTYPE_DISTRIBUTION_GLOBAL_GROUP),
                FLAG_MOD_REPLACE, "groupType")
            ldb.modify(m)
            self.fail()
        except LdbError as e49:
            (num, _) = e49.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Change back to "universal"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_UNIVERSAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_UNIVERSAL_GROUP)

        # Change back to "global"

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement(
            str(GTYPE_SECURITY_GLOBAL_GROUP),
            FLAG_MOD_REPLACE, "groupType")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_SECURITY_GLOBAL_GROUP)

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_pwdLastSet(self):
        """Test the pwdLastSet behaviour"""
        print("Testing pwdLastSet behaviour\n")

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "pwdLastSet": "0"})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        self.assertEqual(int(res1[0]["pwdLastSet"][0]), 0)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "pwdLastSet": "-1"})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        self.assertNotEqual(int(res1[0]["pwdLastSet"][0]), 0)
        lastset = int(res1[0]["pwdLastSet"][0])
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "pwdLastSet": str(1)})
            self.fail()
        except LdbError as e50:
            (num, msg) = e50.args
            self.assertEqual(num, ERR_OTHER)
            self.assertTrue('00000057' in msg)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "pwdLastSet": str(lastset)})
            self.fail()
        except LdbError as e51:
            (num, msg) = e51.args
            self.assertEqual(num, ERR_OTHER)
            self.assertTrue('00000057' in msg)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        self.assertEqual(int(res1[0]["pwdLastSet"][0]), 0)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["pls1"] = MessageElement(str(0),
                                   FLAG_MOD_REPLACE,
                                   "pwdLastSet")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["pls1"] = MessageElement(str(0),
                                   FLAG_MOD_DELETE,
                                   "pwdLastSet")
        m["pls2"] = MessageElement(str(0),
                                   FLAG_MOD_ADD,
                                   "pwdLastSet")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["pls1"] = MessageElement(str(-1),
                                   FLAG_MOD_REPLACE,
                                   "pwdLastSet")
        ldb.modify(m)
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        self.assertGreater(int(res1[0]["pwdLastSet"][0]), lastset)
        lastset = int(res1[0]["pwdLastSet"][0])

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["pls1"] = MessageElement(str(0),
                                       FLAG_MOD_DELETE,
                                       "pwdLastSet")
            m["pls2"] = MessageElement(str(0),
                                       FLAG_MOD_ADD,
                                       "pwdLastSet")
            ldb.modify(m)
            self.fail()
        except LdbError as e52:
            (num, msg) = e52.args
            self.assertEqual(num, ERR_NO_SUCH_ATTRIBUTE)
            self.assertTrue('00002085' in msg)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["pls1"] = MessageElement(str(-1),
                                       FLAG_MOD_DELETE,
                                       "pwdLastSet")
            m["pls2"] = MessageElement(str(0),
                                       FLAG_MOD_ADD,
                                       "pwdLastSet")
            ldb.modify(m)
            self.fail()
        except LdbError as e53:
            (num, msg) = e53.args
            self.assertEqual(num, ERR_NO_SUCH_ATTRIBUTE)
            self.assertTrue('00002085' in msg)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["pls1"] = MessageElement(str(lastset),
                                   FLAG_MOD_DELETE,
                                   "pwdLastSet")
        m["pls2"] = MessageElement(str(-1),
                                   FLAG_MOD_ADD,
                                   "pwdLastSet")
        time.sleep(0.2)
        ldb.modify(m)
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        self.assertEqual(int(res1[0]["pwdLastSet"][0]), lastset)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["pls1"] = MessageElement(str(lastset),
                                       FLAG_MOD_DELETE,
                                       "pwdLastSet")
            m["pls2"] = MessageElement(str(lastset),
                                       FLAG_MOD_ADD,
                                       "pwdLastSet")
            ldb.modify(m)
            self.fail()
        except LdbError as e54:
            (num, msg) = e54.args
            self.assertEqual(num, ERR_OTHER)
            self.assertTrue('00000057' in msg)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["pls1"] = MessageElement(str(lastset),
                                   FLAG_MOD_DELETE,
                                   "pwdLastSet")
        m["pls2"] = MessageElement(str(0),
                                   FLAG_MOD_ADD,
                                   "pwdLastSet")
        ldb.modify(m)
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        uac = int(res1[0]["userAccountControl"][0])
        self.assertEqual(int(res1[0]["pwdLastSet"][0]), 0)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["uac1"] = MessageElement(str(uac |UF_PASSWORD_EXPIRED),
                                   FLAG_MOD_REPLACE,
                                   "userAccountControl")
        ldb.modify(m)
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD)
        self.assertEqual(int(res1[0]["pwdLastSet"][0]), 0)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

    def test_ldap_bind_must_change_pwd(self):
        """Test the error messages for failing LDAP binds"""
        print("Test the error messages for failing LDAP binds\n")

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        def format_error_msg(hresult_v, dsid_v, werror_v):
            #
            # There are 4 lower case hex digits following 'v' at the end,
            # but different Windows Versions return different values:
            #
            # Windows 2008R2 uses 'v1db1'
            # Windows 2012R2 uses 'v2580'
            #
            return "%08X: LdapErr: DSID-%08X, comment: AcceptSecurityContext error, data %x, v" % (
                    hresult_v, dsid_v, werror_v)

        HRES_SEC_E_LOGON_DENIED = 0x8009030C
        HRES_SEC_E_INVALID_TOKEN = 0x80090308

        sasl_bind_dsid = 0x0C0904DC
        simple_bind_dsid = 0x0C0903A9

        error_msg_sasl_wrong_pw = format_error_msg(
                                HRES_SEC_E_LOGON_DENIED,
                                sasl_bind_dsid,
                                werror.WERR_LOGON_FAILURE)
        error_msg_sasl_must_change = format_error_msg(
                                HRES_SEC_E_LOGON_DENIED,
                                sasl_bind_dsid,
                                werror.WERR_PASSWORD_MUST_CHANGE)
        error_msg_simple_wrong_pw = format_error_msg(
                                HRES_SEC_E_INVALID_TOKEN,
                                simple_bind_dsid,
                                werror.WERR_LOGON_FAILURE)
        error_msg_simple_must_change = format_error_msg(
                                HRES_SEC_E_INVALID_TOKEN,
                                simple_bind_dsid,
                                werror.WERR_PASSWORD_MUST_CHANGE)

        username = "ldaptestuser"
        password = "thatsAcomplPASS2"
        utf16pw = text_type('"' + password + '"').encode('utf-16-le')

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "sAMAccountName": username,
            "userAccountControl": str(UF_NORMAL_ACCOUNT),
            "unicodePwd": utf16pw,
        })

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountName", "sAMAccountType", "userAccountControl", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["sAMAccountName"][0]), username)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]), ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res1[0]["userAccountControl"][0]), UF_NORMAL_ACCOUNT)
        self.assertNotEqual(int(res1[0]["pwdLastSet"][0]), 0)

        # Open a second LDB connection with the user credentials. Use the
        # command line credentials for information like the domain, the realm
        # and the workstation.
        sasl_creds = Credentials()
        sasl_creds.set_username(username)
        sasl_creds.set_password(password)
        sasl_creds.set_domain(creds.get_domain())
        sasl_creds.set_workstation(creds.get_workstation())
        sasl_creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
        sasl_creds.set_kerberos_state(DONT_USE_KERBEROS)

        sasl_wrong_creds = Credentials()
        sasl_wrong_creds.set_username(username)
        sasl_wrong_creds.set_password("wrong")
        sasl_wrong_creds.set_domain(creds.get_domain())
        sasl_wrong_creds.set_workstation(creds.get_workstation())
        sasl_wrong_creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
        sasl_wrong_creds.set_kerberos_state(DONT_USE_KERBEROS)

        simple_creds = Credentials()
        simple_creds.set_bind_dn("cn=ldaptestuser,cn=users," + self.base_dn)
        simple_creds.set_username(username)
        simple_creds.set_password(password)
        simple_creds.set_domain(creds.get_domain())
        simple_creds.set_workstation(creds.get_workstation())
        simple_creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
        simple_creds.set_kerberos_state(DONT_USE_KERBEROS)

        simple_wrong_creds = Credentials()
        simple_wrong_creds.set_bind_dn("cn=ldaptestuser,cn=users," + self.base_dn)
        simple_wrong_creds.set_username(username)
        simple_wrong_creds.set_password("wrong")
        simple_wrong_creds.set_domain(creds.get_domain())
        simple_wrong_creds.set_workstation(creds.get_workstation())
        simple_wrong_creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)
        simple_wrong_creds.set_kerberos_state(DONT_USE_KERBEROS)

        sasl_ldb = SamDB(url=host, credentials=sasl_creds, lp=lp)
        self.assertIsNotNone(sasl_ldb)
        sasl_ldb = None

        requires_strong_auth = False
        try:
            simple_ldb = SamDB(url=host, credentials=simple_creds, lp=lp)
            self.assertIsNotNone(simple_ldb)
            simple_ldb = None
        except LdbError as e55:
            (num, msg) = e55.args
            if num != ERR_STRONG_AUTH_REQUIRED:
                raise
            requires_strong_auth = True

        def assertLDAPErrorMsg(msg, expected_msg):
            self.assertTrue(expected_msg in msg,
                            "msg[%s] does not contain expected[%s]" % (
                                msg, expected_msg))

        try:
            ldb_fail = SamDB(url=host, credentials=sasl_wrong_creds, lp=lp)
            self.fail()
        except LdbError as e56:
            (num, msg) = e56.args
            self.assertEqual(num, ERR_INVALID_CREDENTIALS)
            self.assertTrue(error_msg_sasl_wrong_pw in msg)

        if not requires_strong_auth:
            try:
                ldb_fail = SamDB(url=host, credentials=simple_wrong_creds, lp=lp)
                self.fail()
            except LdbError as e4:
                (num, msg) = e4.args
                self.assertEqual(num, ERR_INVALID_CREDENTIALS)
                assertLDAPErrorMsg(msg, error_msg_simple_wrong_pw)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["pls1"] = MessageElement(str(0),
                                   FLAG_MOD_REPLACE,
                                   "pwdLastSet")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["pwdLastSet"])
        self.assertEqual(int(res1[0]["pwdLastSet"][0]), 0)

        try:
            ldb_fail = SamDB(url=host, credentials=sasl_wrong_creds, lp=lp)
            self.fail()
        except LdbError as e57:
            (num, msg) = e57.args
            self.assertEqual(num, ERR_INVALID_CREDENTIALS)
            assertLDAPErrorMsg(msg, error_msg_sasl_wrong_pw)

        try:
            ldb_fail = SamDB(url=host, credentials=sasl_creds, lp=lp)
            self.fail()
        except LdbError as e58:
            (num, msg) = e58.args
            self.assertEqual(num, ERR_INVALID_CREDENTIALS)
            assertLDAPErrorMsg(msg, error_msg_sasl_must_change)

        if not requires_strong_auth:
            try:
                ldb_fail = SamDB(url=host, credentials=simple_wrong_creds, lp=lp)
                self.fail()
            except LdbError as e5:
                (num, msg) = e5.args
                self.assertEqual(num, ERR_INVALID_CREDENTIALS)
                assertLDAPErrorMsg(msg, error_msg_simple_wrong_pw)

            try:
                ldb_fail = SamDB(url=host, credentials=simple_creds, lp=lp)
                self.fail()
            except LdbError as e6:
                (num, msg) = e6.args
                self.assertEqual(num, ERR_INVALID_CREDENTIALS)
                assertLDAPErrorMsg(msg, error_msg_simple_must_change)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

    def test_userAccountControl(self):
        """Test the userAccountControl behaviour"""
        print("Testing userAccountControl behaviour\n")

        # With a user object

        # Add operation

        # As user you can only set a normal account.
        # The UF_PASSWD_NOTREQD flag is needed since we haven't requested a
        # password yet.
        # With SYSTEM rights you can set a interdomain trust account.

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": "0"})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_PASSWD_NOTREQD == 0)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT)})
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD)})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT |
                                      UF_PASSWD_NOTREQD |
                                      UF_LOCKOUT |
                                      UF_PASSWORD_EXPIRED)})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "lockoutTime", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & (UF_LOCKOUT | UF_PASSWORD_EXPIRED) == 0)
        self.assertFalse("lockoutTime" in res1[0])
        self.assertTrue(int(res1[0]["pwdLastSet"][0]) == 0)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "userAccountControl": str(UF_TEMP_DUPLICATE_ACCOUNT)})
            self.fail()
        except LdbError as e59:
            (num, _) = e59.args
            self.assertEqual(num, ERR_OTHER)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT)})
            self.fail()
        except LdbError as e60:
            (num, _) = e60.args
            self.assertEqual(num, ERR_OBJECT_CLASS_VIOLATION)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT)})
        except LdbError as e61:
            (num, _) = e61.args
            self.assertEqual(num, ERR_OBJECT_CLASS_VIOLATION)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)})
        except LdbError as e62:
            (num, _) = e62.args
            self.assertEqual(num, ERR_OBJECT_CLASS_VIOLATION)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": "user",
                "userAccountControl": str(UF_INTERDOMAIN_TRUST_ACCOUNT)})
            self.fail()
        except LdbError as e63:
            (num, _) = e63.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Modify operation

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user"})

        # After creation we should have a normal account
        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE != 0)

        # As user you can only switch from a normal account to a workstation
        # trust account and back.
        # The UF_PASSWD_NOTREQD flag is needed since we haven't requested a
        # password yet.
        # With SYSTEM rights you can switch to a interdomain trust account.

        # Invalid attribute
        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["userAccountControl"] = MessageElement("0",
                                                     FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
        except LdbError as e64:
            (num, _) = e64.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_NORMAL_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
        except LdbError as e65:
            (num, _) = e65.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_ACCOUNTDISABLE),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_NORMAL_ACCOUNT != 0)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE != 0)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["lockoutTime"] = MessageElement(str(samba.unix2nttime(0)), FLAG_MOD_REPLACE, "lockoutTime")
        m["pwdLastSet"] = MessageElement(str(samba.unix2nttime(0)), FLAG_MOD_REPLACE, "pwdLastSet")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_LOCKOUT | UF_PASSWORD_EXPIRED),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "lockoutTime", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_NORMAL_ACCOUNT != 0)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & (UF_LOCKOUT | UF_PASSWORD_EXPIRED) == 0)
        self.assertTrue(int(res1[0]["lockoutTime"][0]) == 0)
        self.assertTrue(int(res1[0]["pwdLastSet"][0]) == 0)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_TEMP_DUPLICATE_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
            self.fail()
        except LdbError as e66:
            (num, _) = e66.args
            self.assertEqual(num, ERR_OTHER)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_SERVER_TRUST_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
            self.fail()
        except LdbError as e67:
            (num, _) = e67.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_WORKSTATION_TRUST_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
            self.fail()
        except LdbError as e68:
            (num, _) = e68.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_WORKSTATION_TRUST)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_INTERDOMAIN_TRUST_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
            self.fail()
        except LdbError as e69:
            (num, _) = e69.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        # With a computer object

        # Add operation

        # As computer you can set a normal account and a server trust account.
        # The UF_PASSWD_NOTREQD flag is needed since we haven't requested a
        # password yet.
        # With SYSTEM rights you can set a interdomain trust account.

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": "0"})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_PASSWD_NOTREQD == 0)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_NORMAL_ACCOUNT)})
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD)})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_NORMAL_ACCOUNT |
                                      UF_PASSWD_NOTREQD |
                                      UF_LOCKOUT |
                                      UF_PASSWORD_EXPIRED)})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "lockoutTime", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & (UF_LOCKOUT | UF_PASSWORD_EXPIRED) == 0)
        self.assertFalse("lockoutTime" in res1[0])
        self.assertTrue(int(res1[0]["pwdLastSet"][0]) == 0)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
                "objectclass": "computer",
                "userAccountControl": str(UF_TEMP_DUPLICATE_ACCOUNT)})
            self.fail()
        except LdbError as e70:
            (num, _) = e70.args
            self.assertEqual(num, ERR_OTHER)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT)})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_WORKSTATION_TRUST)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
                "objectclass": "computer",
                "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT)})
        except LdbError as e71:
            (num, _) = e71.args
            self.assertEqual(num, ERR_OBJECT_CLASS_VIOLATION)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        try:
            ldb.add({
                "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
                "objectclass": "computer",
                "userAccountControl": str(UF_INTERDOMAIN_TRUST_ACCOUNT)})
            self.fail()
        except LdbError as e72:
            (num, _) = e72.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        # Modify operation

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer"})

        # After creation we should have a normal account
        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE != 0)

        # As computer you can switch from a normal account to a workstation
        # or server trust account and back (also swapping between trust
        # accounts is allowed).
        # The UF_PASSWD_NOTREQD flag is needed since we haven't requested a
        # password yet.
        # With SYSTEM rights you can switch to a interdomain trust account.

        # Invalid attribute
        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
            m["userAccountControl"] = MessageElement("0",
                                                     FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
        except LdbError as e73:
            (num, _) = e73.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_NORMAL_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
        except LdbError as e74:
            (num, _) = e74.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_ACCOUNTDISABLE),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_NORMAL_ACCOUNT != 0)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE != 0)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["lockoutTime"] = MessageElement(str(samba.unix2nttime(0)), FLAG_MOD_REPLACE, "lockoutTime")
        m["pwdLastSet"] = MessageElement(str(samba.unix2nttime(0)), FLAG_MOD_REPLACE, "pwdLastSet")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_LOCKOUT | UF_PASSWORD_EXPIRED),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["sAMAccountType", "userAccountControl", "lockoutTime", "pwdLastSet"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_NORMAL_ACCOUNT != 0)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & (UF_LOCKOUT | UF_PASSWORD_EXPIRED) == 0)
        self.assertTrue(int(res1[0]["lockoutTime"][0]) == 0)
        self.assertTrue(int(res1[0]["pwdLastSet"][0]) == 0)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_TEMP_DUPLICATE_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
            self.fail()
        except LdbError as e75:
            (num, _) = e75.args
            self.assertEqual(num, ERR_OTHER)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_SERVER_TRUST_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_WORKSTATION_TRUST)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_WORKSTATION_TRUST_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_WORKSTATION_TRUST)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_NORMAL_ACCOUNT)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_SERVER_TRUST_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_WORKSTATION_TRUST)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_WORKSTATION_TRUST_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["sAMAccountType"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["sAMAccountType"][0]),
                          ATYPE_WORKSTATION_TRUST)

        try:
            m = Message()
            m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
            m["userAccountControl"] = MessageElement(
                str(UF_INTERDOMAIN_TRUST_ACCOUNT),
                FLAG_MOD_REPLACE, "userAccountControl")
            ldb.modify(m)
            self.fail()
        except LdbError as e76:
            (num, _) = e76.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        # "primaryGroupID" does not change if account type remains the same

        # For a user account

        ldb.add({
            "dn": "cn=ldaptestuser2,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT |
                                      UF_PASSWD_NOTREQD |
                                      UF_ACCOUNTDISABLE)})

        res1 = ldb.search("cn=ldaptestuser2,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["userAccountControl"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["userAccountControl"][0]),
                          UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE)

        m = Message()
        m.dn = Dn(ldb, "<SID=" + ldb.get_domain_sid() + "-" + str(DOMAIN_RID_ADMINS) + ">")
        m["member"] = MessageElement(
            "cn=ldaptestuser2,cn=users," + self.base_dn, FLAG_MOD_ADD, "member")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(DOMAIN_RID_ADMINS),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser2,cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["userAccountControl", "primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(int(res1[0]["userAccountControl"][0]) & UF_ACCOUNTDISABLE == 0)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_ADMINS)

        # For a workstation account

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_DOMAIN_MEMBERS)

        m = Message()
        m.dn = Dn(ldb, "<SID=" + ldb.get_domain_sid() + "-" + str(DOMAIN_RID_USERS) + ">")
        m["member"] = MessageElement(
            "cn=ldaptestcomputer,cn=computers," + self.base_dn, FLAG_MOD_ADD, "member")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(DOMAIN_RID_USERS),
                                             FLAG_MOD_REPLACE, "primaryGroupID")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_WORKSTATION_TRUST_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(int(res1[0]["primaryGroupID"][0]), DOMAIN_RID_USERS)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

    def find_repl_meta_data(self, rpmd, attid):
        for i in range(0, rpmd.ctr.count):
            m = rpmd.ctr.array[i]
            if m.attid == attid:
                return m
        return None

    def test_smartcard_required1(self):
        """Test the UF_SMARTCARD_REQUIRED behaviour"""
        print("Testing UF_SMARTCARD_REQUIRED behaviour\n")

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT),
            "unicodePwd": "\"thatsAcomplPASS2\"".encode('utf-16-le')
        })

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT)
        self.assertNotEqual(int(res[0]["pwdLastSet"][0]), 0)
        lastset = int(res[0]["pwdLastSet"][0])
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 1)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 1)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 1)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 1)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 1)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNotNone(spcbmd)
        self.assertEqual(spcbmd.version, 1)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED)
        self.assertEqual(int(res[0]["pwdLastSet"][0]), lastset)
        lastset1 = int(res[0]["pwdLastSet"][0])
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 2)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 2)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 2)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 2)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 2)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNotNone(spcbmd)
        self.assertEqual(spcbmd.version, 2)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

    def test_smartcard_required2(self):
        """Test the UF_SMARTCARD_REQUIRED behaviour"""
        print("Testing UF_SMARTCARD_REQUIRED behaviour\n")

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT |UF_ACCOUNTDISABLE),
        })

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT |UF_ACCOUNTDISABLE)
        self.assertEqual(int(res[0]["pwdLastSet"][0]), 0)
        self.assertTrue("msDS-KeyVersionNumber" in res[0])
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 1)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 1)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 1)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 1)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 1)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNone(spcbmd)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT |UF_ACCOUNTDISABLE |UF_SMARTCARD_REQUIRED),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT |UF_ACCOUNTDISABLE |UF_SMARTCARD_REQUIRED)
        self.assertEqual(int(res[0]["pwdLastSet"][0]), 0)
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 2)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 2)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 2)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 2)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 2)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNotNone(spcbmd)
        self.assertEqual(spcbmd.version, 1)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED)
        self.assertEqual(int(res[0]["pwdLastSet"][0]), 0)
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 2)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 2)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 2)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 2)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 2)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNotNone(spcbmd)
        self.assertEqual(spcbmd.version, 1)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

    def test_smartcard_required3(self):
        """Test the UF_SMARTCARD_REQUIRED behaviour"""
        print("Testing UF_SMARTCARD_REQUIRED behaviour\n")

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": "user",
            "userAccountControl": str(UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED |UF_ACCOUNTDISABLE),
        })

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED |UF_ACCOUNTDISABLE)
        self.assertEqual(int(res[0]["pwdLastSet"][0]), 0)
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 1)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 1)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 1)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 1)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 1)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNotNone(spcbmd)
        self.assertEqual(spcbmd.version, 1)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE,
                         attrs=["sAMAccountType", "userAccountControl",
                                "pwdLastSet", "msDS-KeyVersionNumber",
                                "replPropertyMetaData"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(int(res[0]["sAMAccountType"][0]),
                         ATYPE_NORMAL_ACCOUNT)
        self.assertEqual(int(res[0]["userAccountControl"][0]),
                         UF_NORMAL_ACCOUNT |UF_SMARTCARD_REQUIRED)
        self.assertEqual(int(res[0]["pwdLastSet"][0]), 0)
        self.assertEqual(int(res[0]["msDS-KeyVersionNumber"][0]), 1)
        self.assertTrue(len(res[0]["replPropertyMetaData"]) == 1)
        rpmd = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          res[0]["replPropertyMetaData"][0])
        lastsetmd = self.find_repl_meta_data(rpmd,
                                             drsuapi.DRSUAPI_ATTID_pwdLastSet)
        self.assertIsNotNone(lastsetmd)
        self.assertEqual(lastsetmd.version, 1)
        nthashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_unicodePwd)
        self.assertIsNotNone(nthashmd)
        self.assertEqual(nthashmd.version, 1)
        nthistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_ntPwdHistory)
        self.assertIsNotNone(nthistmd)
        self.assertEqual(nthistmd.version, 1)
        lmhashmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_dBCSPwd)
        self.assertIsNotNone(lmhashmd)
        self.assertEqual(lmhashmd.version, 1)
        lmhistmd = self.find_repl_meta_data(rpmd,
                                            drsuapi.DRSUAPI_ATTID_lmPwdHistory)
        self.assertIsNotNone(lmhistmd)
        self.assertEqual(lmhistmd.version, 1)
        spcbmd = self.find_repl_meta_data(rpmd,
                                          drsuapi.DRSUAPI_ATTID_supplementalCredentials)
        self.assertIsNotNone(spcbmd)
        self.assertEqual(spcbmd.version, 1)

        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

    def test_isCriticalSystemObject(self):
        """Test the isCriticalSystemObject behaviour"""
        print("Testing isCriticalSystemObject behaviour\n")

        # Add tests

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer"})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue("isCriticalSystemObject" not in res1[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT)})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "FALSE")

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT)})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "TRUE")

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT)})

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "TRUE")

        # Modification tests

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "TRUE")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_WORKSTATION_TRUST_ACCOUNT),
                                                 FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "FALSE")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(
            str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT),
            FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "TRUE")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD),
                                                 FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "TRUE")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_SERVER_TRUST_ACCOUNT),
                                                 FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "TRUE")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_WORKSTATION_TRUST_ACCOUNT),
                                                 FLAG_MOD_REPLACE, "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["isCriticalSystemObject"])
        self.assertTrue(len(res1) == 1)
        self.assertEqual(str(res1[0]["isCriticalSystemObject"][0]), "FALSE")

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

    def test_service_principal_name_updates(self):
        """Test the servicePrincipalNames update behaviour"""
        print("Testing servicePrincipalNames update behaviour\n")

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "dNSHostName": "testname.testdom"})

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("servicePrincipalName" in res[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "servicePrincipalName": "HOST/testname.testdom"})

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["dNSHostName"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("dNSHostName" in res[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "dNSHostName": "testname2.testdom",
            "servicePrincipalName": "HOST/testname.testdom"})

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["dNSHostName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["dNSHostName"][0]), "testname2.testdom")

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname.testdom")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname.testdoM",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname.testdom")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname2.testdom2",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname2.testdom2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement([],
                                          FLAG_MOD_DELETE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname2.testdom2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname.testdom3",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname2.testdom2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname2.testdom2",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname3.testdom3",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        m["servicePrincipalName"] = MessageElement("HOST/testname2.testdom2",
                                                   FLAG_MOD_REPLACE,
                                                   "servicePrincipalName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname3.testdom3")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["servicePrincipalName"] = MessageElement("HOST/testname2.testdom2",
                                                   FLAG_MOD_REPLACE,
                                                   "servicePrincipalName")
        m["dNSHostName"] = MessageElement("testname4.testdom4",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname2.testdom2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["servicePrincipalName"] = MessageElement([],
                                                   FLAG_MOD_DELETE,
                                                   "servicePrincipalName")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname2.testdom2",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("servicePrincipalName" in res[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "sAMAccountName": "testname$"})

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("servicePrincipalName" in res[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "servicePrincipalName": "HOST/testname"})

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["sAMAccountName"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("sAMAccountName" in res[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "sAMAccountName": "testname$",
            "servicePrincipalName": "HOST/testname"})

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["sAMAccountName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["sAMAccountName"][0]), "testname$")

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testnamE$",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testname",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("test$name$",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/test$name")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testname2",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testname3",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        m["servicePrincipalName"] = MessageElement("HOST/testname2",
                                                   FLAG_MOD_REPLACE,
                                                   "servicePrincipalName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname3")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["servicePrincipalName"] = MessageElement("HOST/testname2",
                                                   FLAG_MOD_REPLACE,
                                                   "servicePrincipalName")
        m["sAMAccountName"] = MessageElement("testname4",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["servicePrincipalName"][0]),
                          "HOST/testname2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["servicePrincipalName"] = MessageElement([],
                                                   FLAG_MOD_DELETE,
                                                   "servicePrincipalName")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testname2",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("servicePrincipalName" in res[0])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "dNSHostName": "testname.testdom",
            "sAMAccountName": "testname$",
            "servicePrincipalName": ["HOST/testname.testdom", "HOST/testname"]
        })

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname2.testdom",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        m["sAMAccountName"] = MessageElement("testname2$",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["dNSHostName", "sAMAccountName", "servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["dNSHostName"][0]), "testname2.testdom")
        self.assertEqual(str(res[0]["sAMAccountName"][0]), "testname2$")
        self.assertTrue(str(res[0]["servicePrincipalName"][0]) == "HOST/testname2" or
                        str(res[0]["servicePrincipalName"][1]) == "HOST/testname2")
        self.assertTrue(str(res[0]["servicePrincipalName"][0]) == "HOST/testname2.testdom" or
                        str(res[0]["servicePrincipalName"][1]) == "HOST/testname2.testdom")

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "dNSHostName": "testname.testdom",
            "sAMAccountName": "testname$",
            "servicePrincipalName": ["HOST/testname.testdom", "HOST/testname"]
        })

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testname2$",
                                             FLAG_MOD_REPLACE, "sAMAccountName")
        m["dNSHostName"] = MessageElement("testname2.testdom",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["dNSHostName", "sAMAccountName", "servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["dNSHostName"][0]), "testname2.testdom")
        self.assertEqual(str(res[0]["sAMAccountName"][0]), "testname2$")
        self.assertTrue(len(res[0]["servicePrincipalName"]) == 2)
        self.assertTrue("HOST/testname2" in [str(x) for x in res[0]["servicePrincipalName"]])
        self.assertTrue("HOST/testname2.testdom" in [str(x) for x in res[0]["servicePrincipalName"]])

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["servicePrincipalName"] = MessageElement("HOST/testname2.testdom",
                                                   FLAG_MOD_ADD, "servicePrincipalName")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e77:
            (num, _) = e77.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["servicePrincipalName"] = MessageElement("HOST/testname3",
                                                   FLAG_MOD_ADD, "servicePrincipalName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["dNSHostName", "sAMAccountName", "servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["dNSHostName"][0]), "testname2.testdom")
        self.assertEqual(str(res[0]["sAMAccountName"][0]), "testname2$")
        self.assertTrue(len(res[0]["servicePrincipalName"]) == 3)
        self.assertTrue("HOST/testname2" in [str(x) for x in res[0]["servicePrincipalName"]])
        self.assertTrue("HOST/testname3" in [str(x) for x in res[0]["servicePrincipalName"]])
        self.assertTrue("HOST/testname2.testdom" in [str(x) for x in res[0]["servicePrincipalName"]])

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        m["dNSHostName"] = MessageElement("testname3.testdom",
                                          FLAG_MOD_REPLACE, "dNSHostName")
        m["servicePrincipalName"] = MessageElement("HOST/testname3.testdom",
                                                   FLAG_MOD_ADD, "servicePrincipalName")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestcomputer,cn=computers," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["dNSHostName", "sAMAccountName", "servicePrincipalName"])
        self.assertTrue(len(res) == 1)
        self.assertEqual(str(res[0]["dNSHostName"][0]), "testname3.testdom")
        self.assertEqual(str(res[0]["sAMAccountName"][0]), "testname2$")
        self.assertTrue(len(res[0]["servicePrincipalName"]) == 3)
        self.assertTrue("HOST/testname2" in [str(x) for x in res[0]["servicePrincipalName"]])
        self.assertTrue("HOST/testname3" in [str(x) for x in res[0]["servicePrincipalName"]])
        self.assertTrue("HOST/testname3.testdom" in [str(x) for x in res[0]["servicePrincipalName"]])

        delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)

    def test_sam_description_attribute(self):
        """Test SAM description attribute"""
        print("Test SAM description attribute")

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "description": "desc1"
        })

        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("description" in res[0])
        self.assertTrue(len(res[0]["description"]) == 1)
        self.assertEqual(str(res[0]["description"][0]), "desc1")

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "description": ["desc1", "desc2"]})

        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("description" in res[0])
        self.assertTrue(len(res[0]["description"]) == 2)
        self.assertTrue(str(res[0]["description"][0]) == "desc1" or
                        str(res[0]["description"][1]) == "desc1")
        self.assertTrue(str(res[0]["description"][0]) == "desc2" or
                        str(res[0]["description"][1]) == "desc2")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement(["desc1", "desc2"], FLAG_MOD_REPLACE,
                                          "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e78:
            (num, _) = e78.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement(["desc1", "desc2"], FLAG_MOD_DELETE,
                                          "description")
        ldb.modify(m)

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc1", FLAG_MOD_REPLACE,
                                          "description")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("description" in res[0])
        self.assertTrue(len(res[0]["description"]) == 1)
        self.assertEqual(str(res[0]["description"][0]), "desc1")

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "description": ["desc1", "desc2"]})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc1", FLAG_MOD_REPLACE,
                                          "description")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("description" in res[0])
        self.assertTrue(len(res[0]["description"]) == 1)
        self.assertEqual(str(res[0]["description"][0]), "desc1")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc3", FLAG_MOD_ADD,
                                          "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e79:
            (num, _) = e79.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement(["desc1", "desc2"], FLAG_MOD_DELETE,
                                          "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e80:
            (num, _) = e80.args
            self.assertEqual(num, ERR_NO_SUCH_ATTRIBUTE)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc1", FLAG_MOD_DELETE,
                                          "description")
        ldb.modify(m)
        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("description" in res[0])

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement(["desc1", "desc2"], FLAG_MOD_REPLACE,
                                          "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e81:
            (num, _) = e81.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement(["desc3", "desc4"], FLAG_MOD_ADD,
                                          "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e82:
            (num, _) = e82.args
            self.assertEqual(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc1", FLAG_MOD_ADD,
                                          "description")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("description" in res[0])
        self.assertTrue(len(res[0]["description"]) == 1)
        self.assertEqual(str(res[0]["description"][0]), "desc1")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m.add(MessageElement("desc1", FLAG_MOD_DELETE, "description"))
        m.add(MessageElement("desc2", FLAG_MOD_ADD, "description"))
        ldb.modify(m)

        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["description"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("description" in res[0])
        self.assertTrue(len(res[0]["description"]) == 1)
        self.assertEqual(str(res[0]["description"][0]), "desc2")

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_fSMORoleOwner_attribute(self):
        """Test fSMORoleOwner attribute"""
        print("Test fSMORoleOwner attribute")

        ds_service_name = self.ldb.get_dsServiceName()

        # The "fSMORoleOwner" attribute can only be set to "nTDSDSA" entries,
        # invalid DNs return ERR_UNWILLING_TO_PERFORM

        try:
            self.ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "fSMORoleOwner": self.base_dn})
            self.fail()
        except LdbError as e83:
            (num, _) = e83.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "fSMORoleOwner": []})
            self.fail()
        except LdbError as e84:
            (num, _) = e84.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)

        # We are able to set it to a valid "nTDSDSA" entry if the server is
        # capable of handling the role

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "fSMORoleOwner": ds_service_name})

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m.add(MessageElement(self.base_dn, FLAG_MOD_REPLACE, "fSMORoleOwner"))
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e85:
            (num, _) = e85.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m.add(MessageElement([], FLAG_MOD_REPLACE, "fSMORoleOwner"))
        try:
            ldb.modify(m)
            self.fail()
        except LdbError as e86:
            (num, _) = e86.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # We are able to set it to a valid "nTDSDSA" entry if the server is
        # capable of handling the role

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m.add(MessageElement(ds_service_name, FLAG_MOD_REPLACE, "fSMORoleOwner"))
        ldb.modify(m)

        # A clean-out works on plain entries, not master (schema, PDC...) DNs

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m.add(MessageElement([], FLAG_MOD_DELETE, "fSMORoleOwner"))
        ldb.modify(m)

        delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_protected_sid_objects(self):
        """Test deletion of objects with RID < 1000"""
        # a list of some well-known sids
        # objects in Builtin are aready covered by objectclass
        protected_list = [
            ["CN=Domain Admins", "CN=Users,"],
            ["CN=Schema Admins", "CN=Users,"],
            ["CN=Enterprise Admins", "CN=Users,"],
            ["CN=Administrator", "CN=Users,"],
            ["CN=Domain Controllers", "CN=Users,"],
        ]

        for pr_object in protected_list:
            try:
                self.ldb.delete(pr_object[0] + "," + pr_object[1] + self.base_dn)
            except LdbError as e7:
                (num, _) = e7.args
                self.assertEqual(num, ERR_OTHER)
            else:
                self.fail("Deleted " + pr_object[0])

            try:
                self.ldb.rename(pr_object[0] + "," + pr_object[1] + self.base_dn,
                                pr_object[0] + "2," + pr_object[1] + self.base_dn)
            except LdbError as e8:
                (num, _) = e8.args
                self.fail("Could not rename " + pr_object[0])

            self.ldb.rename(pr_object[0] + "2," + pr_object[1] + self.base_dn,
                            pr_object[0] + "," + pr_object[1] + self.base_dn)

    def test_new_user_default_attributes(self):
        """Test default attributes for new user objects"""
        print("Test default attributes for new User objects\n")

        user_name = "ldaptestuser"
        user_dn = "CN=%s,CN=Users,%s" % (user_name, self.base_dn)
        ldb.add({
            "dn": user_dn,
            "objectclass": "user",
            "sAMAccountName": user_name})

        res = ldb.search(user_dn, scope=SCOPE_BASE)
        self.assertTrue(len(res) == 1)
        user_obj = res[0]

        expected_attrs = {"primaryGroupID": MessageElement(["513"]),
                          "logonCount": MessageElement(["0"]),
                          "cn": MessageElement([user_name]),
                          "countryCode": MessageElement(["0"]),
                          "objectClass": MessageElement(["top", "person", "organizationalPerson", "user"]),
                          "instanceType": MessageElement(["4"]),
                          "distinguishedName": MessageElement([user_dn]),
                          "sAMAccountType": MessageElement(["805306368"]),
                          "objectSid": "**SKIP**",
                          "whenCreated": "**SKIP**",
                          "uSNCreated": "**SKIP**",
                          "badPasswordTime": MessageElement(["0"]),
                          "dn": Dn(ldb, user_dn),
                          "pwdLastSet": MessageElement(["0"]),
                          "sAMAccountName": MessageElement([user_name]),
                          "objectCategory": MessageElement(["CN=Person,%s" % ldb.get_schema_basedn().get_linearized()]),
                          "objectGUID": "**SKIP**",
                          "whenChanged": "**SKIP**",
                          "badPwdCount": MessageElement(["0"]),
                          "accountExpires": MessageElement(["9223372036854775807"]),
                          "name": MessageElement([user_name]),
                          "codePage": MessageElement(["0"]),
                          "userAccountControl": MessageElement(["546"]),
                          "lastLogon": MessageElement(["0"]),
                          "uSNChanged": "**SKIP**",
                          "lastLogoff": MessageElement(["0"])}
        # assert we have expected attribute names
        actual_names = set(user_obj.keys())
        # Samba does not use 'dSCorePropagationData', so skip it
        actual_names -= set(['dSCorePropagationData'])
        self.assertEqual(set(expected_attrs.keys()), actual_names, "Actual object does not have expected attributes")
        # check attribute values
        for name in expected_attrs.keys():
            actual_val = user_obj.get(name)
            self.assertFalse(actual_val is None, "No value for attribute '%s'" % name)
            expected_val = expected_attrs[name]
            if expected_val == "**SKIP**":
                # "**ANY**" values means "any"
                continue
            self.assertEqual(expected_val, actual_val,
                             "Unexpected value[%r] for '%s' expected[%r]" %
                             (actual_val, name, expected_val))
        # clean up
        delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)

TestProgram(module=__name__, opts=subunitopts)
