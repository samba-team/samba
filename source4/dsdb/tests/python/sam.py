#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This is a port of the original in testprogs/ejs/ldap.js

import optparse
import sys
import time
import base64
import os

sys.path.append("bin/python")
import samba
samba.ensure_external_module("subunit", "subunit/python")
samba.ensure_external_module("testtools", "testtools")

import samba.getopt as options

from samba.auth import system_session
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT, ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_ENTRY_ALREADY_EXISTS, ERR_UNWILLING_TO_PERFORM
from ldb import ERR_NOT_ALLOWED_ON_NON_LEAF, ERR_OTHER, ERR_INVALID_DN_SYNTAX
from ldb import ERR_NO_SUCH_ATTRIBUTE
from ldb import ERR_OBJECT_CLASS_VIOLATION, ERR_NOT_ALLOWED_ON_RDN
from ldb import ERR_NAMING_VIOLATION, ERR_CONSTRAINT_VIOLATION
from ldb import ERR_UNDEFINED_ATTRIBUTE_TYPE
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from samba import Ldb
from samba.dsdb import (UF_NORMAL_ACCOUNT, UF_INTERDOMAIN_TRUST_ACCOUNT,
    UF_WORKSTATION_TRUST_ACCOUNT, UF_SERVER_TRUST_ACCOUNT,
    UF_PARTIAL_SECRETS_ACCOUNT,
    UF_PASSWD_NOTREQD, UF_ACCOUNTDISABLE, ATYPE_NORMAL_ACCOUNT,
    ATYPE_WORKSTATION_TRUST, SYSTEM_FLAG_DOMAIN_DISALLOW_MOVE,
    SYSTEM_FLAG_CONFIG_ALLOW_RENAME, SYSTEM_FLAG_CONFIG_ALLOW_MOVE,
    SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE)
from samba.dcerpc.security import (DOMAIN_RID_USERS, DOMAIN_RID_DOMAIN_MEMBERS,
    DOMAIN_RID_DCS, DOMAIN_RID_READONLY_DCS)

from subunit.run import SubunitTestRunner
import unittest

from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

parser = optparse.OptionParser("sam.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

class SamTests(unittest.TestCase):

    def delete_force(self, ldb, dn):
        try:
            ldb.delete(dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

    def find_basedn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["defaultNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["defaultNamingContext"][0]

    def find_domain_sid(self):
        res = self.ldb.search(base=self.base_dn, expression="(objectClass=*)", scope=SCOPE_BASE)
        return ndr_unpack( security.dom_sid,res[0]["objectSid"][0])

    def setUp(self):
        super(SamTests, self).setUp()
        self.ldb = ldb
        self.gc_ldb = gc_ldb
        self.base_dn = self.find_basedn(ldb)
        self.domain_sid = self.find_domain_sid()

        print "baseDN: %s\n" % self.base_dn

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)

    def test_users_groups(self):
        """This tests the SAM users and groups behaviour"""
        print "Testing users and groups behaviour\n"

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        ldb.add({
            "dn": "cn=ldaptestgroup2,cn=users," + self.base_dn,
            "objectclass": "group"})

        res1 = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["objectSID"])
        self.assertTrue(len(res1) == 1)
        group_rid_1 = security.dom_sid(ldb.schema_format_value("objectSID",
          res1[0]["objectSID"][0])).split()[1]

        res1 = ldb.search("cn=ldaptestgroup2,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["objectSID"])
        self.assertTrue(len(res1) == 1)
        group_rid_2 = security.dom_sid(ldb.schema_format_value("objectSID",
          res1[0]["objectSID"][0])).split()[1]

        # Try to create a user with an invalid primary group
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": ["user", "person"],
                "primaryGroupID": "0"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)
        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Try to Create a user with a valid primary group
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": ["user", "person"],
                "primaryGroupID": str(group_rid_1)})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)
        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Test to see how we should behave when the user account doesn't
        # exist
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("0", FLAG_MOD_REPLACE,
          "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        # Test to see how we should behave when the account isn't a user
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("0", FLAG_MOD_REPLACE,
          "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # Test default primary groups on add operations

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_USERS))

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"],
            "userAccountControl": str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD) })

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_USERS))

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # unfortunately the INTERDOMAIN_TRUST_ACCOUNT case cannot be tested
        # since such accounts aren't directly creatable (ACCESS_DENIED)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["computer"],
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD) })

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_DOMAIN_MEMBERS))

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["computer"],
            "userAccountControl": str(UF_SERVER_TRUST_ACCOUNT | UF_PASSWD_NOTREQD) })

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_DCS))

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Read-only DC accounts are only creatable by
        # UF_WORKSTATION_TRUST_ACCOUNT and work only on DCs >= 2008 (therefore
        # we have a fallback in the assertion)
        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["computer"],
            "userAccountControl": str(UF_PARTIAL_SECRETS_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD) })

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(res1[0]["primaryGroupID"][0] == str(DOMAIN_RID_READONLY_DCS) or
                        res1[0]["primaryGroupID"][0] == str(DOMAIN_RID_DOMAIN_MEMBERS))

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Test default primary groups on modify operations

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD), FLAG_MOD_REPLACE,
          "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_USERS))

        # unfortunately the INTERDOMAIN_TRUST_ACCOUNT case cannot be tested
        # since such accounts aren't directly creatable (ACCESS_DENIED)

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["computer"]})

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_USERS))

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD), FLAG_MOD_REPLACE,
          "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_DOMAIN_MEMBERS))

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_SERVER_TRUST_ACCOUNT | UF_PASSWD_NOTREQD), FLAG_MOD_REPLACE,
          "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertEquals(res1[0]["primaryGroupID"][0], str(DOMAIN_RID_DCS))

        # Read-only DC accounts are only creatable by
        # UF_WORKSTATION_TRUST_ACCOUNT and work only on DCs >= 2008 (therefore
        # we have a fallback in the assertion)
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(UF_PARTIAL_SECRETS_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD), FLAG_MOD_REPLACE,
          "userAccountControl")
        ldb.modify(m)

        res1 = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["primaryGroupID"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(res1[0]["primaryGroupID"][0] == str(DOMAIN_RID_READONLY_DCS) or
                        res1[0]["primaryGroupID"][0] == str(DOMAIN_RID_DOMAIN_MEMBERS))

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Recreate account for further tests

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})

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
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        # Try to make group 1 primary - should be denied since it is not yet
        # secondary
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement(str(group_rid_1),
          FLAG_MOD_REPLACE, "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

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
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ENTRY_ALREADY_EXISTS)

        # Try to add group 1 also as secondary - should be denied
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
                                     FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ENTRY_ALREADY_EXISTS)

        # Try to add invalid member to group 1 - should be denied
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement(
          "cn=ldaptestuser3,cn=users," + self.base_dn,
          FLAG_MOD_ADD, "member")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

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

        # Old primary group should contain a "member" attribute for the user,
        # the new shouldn't contain anymore one
        res1 = ldb.search("cn=ldaptestgroup, cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["member"])
        self.assertTrue(len(res1) == 1)
        self.assertTrue(len(res1[0]["member"]) == 1)
        self.assertEquals(res1[0]["member"][0].lower(),
          ("cn=ldaptestuser,cn=users," + self.base_dn).lower())

        res1 = ldb.search("cn=ldaptestgroup2, cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["member"])
        self.assertTrue(len(res1) == 1)
        self.assertFalse("member" in res1[0])

        # Also this should be denied
        try:
            ldb.add({
              "dn": "cn=ldaptestuser1,cn=users," + self.base_dn,
              "objectclass": ["user", "person"],
              "primaryGroupID": "0"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)

    def test_sam_attributes(self):
        """Test the behaviour of special attributes of SAM objects"""
        print "Testing the behaviour of special attributes of SAM objects\n"""

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})
        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement("0", FLAG_MOD_ADD,
          "groupType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["groupType"] = MessageElement([], FLAG_MOD_DELETE,
          "groupType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("0", FLAG_MOD_ADD,
          "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement([], FLAG_MOD_DELETE,
          "primaryGroupID")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement("0", FLAG_MOD_ADD,
          "userAccountControl")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement([], FLAG_MOD_DELETE,
          "userAccountControl")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountType"] = MessageElement("0", FLAG_MOD_ADD,
          "sAMAccountType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountType"] = MessageElement([], FLAG_MOD_REPLACE,
          "sAMAccountType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["sAMAccountType"] = MessageElement([], FLAG_MOD_DELETE,
          "sAMAccountType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_primary_group_token_constructed(self):
        """Test the primary group token behaviour (hidden-generated-readonly attribute on groups) and some other constructed attributes"""
        print "Testing primary group token behaviour and other constructed attributes\n"

        try:
            ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "primaryGroupToken": "100"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNDEFINED_ATTRIBUTE_TYPE)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})

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

        res1 = ldb.search("cn=users,"+self.base_dn,
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

        rid = security.dom_sid(ldb.schema_format_value("objectSID", res1[0]["objectSID"][0])).split()[1]
        self.assertEquals(primary_group_token, rid)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["primaryGroupToken"] = "100"
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_tokenGroups(self):
        """Test the tokenGroups behaviour (hidden-generated-readonly attribute on SAM objects)"""
        print "Testing tokenGroups behaviour\n"

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
            "objectclass": ["user", "person"]})

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
            rid = security.dom_sid(ldb.schema_format_value("objectSID", sid)).split()[1]
            if rid == 513:
                domain_users_group_found = True
            if rid == 545:
                users_group_found = True

        self.assertTrue(domain_users_group_found)
        self.assertTrue(users_group_found)

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = Ldb(host, credentials=creds, session_info=system_session(), lp=lp)
if not "tdb://" in host:
    gc_ldb = Ldb("%s:3268" % host, credentials=creds,
                 session_info=system_session(), lp=lp)
else:
    gc_ldb = None

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(SamTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
