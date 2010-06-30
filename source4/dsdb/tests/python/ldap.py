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
from samba.dsdb import (UF_NORMAL_ACCOUNT, UF_WORKSTATION_TRUST_ACCOUNT, 
    UF_PASSWD_NOTREQD, UF_ACCOUNTDISABLE, ATYPE_NORMAL_ACCOUNT,
    ATYPE_WORKSTATION_TRUST)

from subunit.run import SubunitTestRunner
import unittest

from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

parser = optparse.OptionParser("ldap [options] <host>")
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

class BasicTests(unittest.TestCase):

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

    def find_configurationdn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["configurationNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["configurationNamingContext"][0]

    def find_schemadn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE, attrs=["schemaNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["schemaNamingContext"][0]

    def find_domain_sid(self):
        res = self.ldb.search(base=self.base_dn, expression="(objectClass=*)", scope=SCOPE_BASE)
        return ndr_unpack( security.dom_sid,res[0]["objectSid"][0])

    def setUp(self):
        super(BasicTests, self).setUp()
        self.ldb = ldb
        self.gc_ldb = gc_ldb
        self.base_dn = self.find_basedn(ldb)
        self.configuration_dn = self.find_configurationdn(ldb)
        self.schema_dn = self.find_schemadn(ldb)
        self.domain_sid = self.find_domain_sid()

        print "baseDN: %s\n" % self.base_dn

        self.delete_force(self.ldb, "cn=posixuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser3,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser4,cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser4,cn=ldaptestcontainer2," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser5,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptest2computer,cn=computers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcomputer3,cn=computers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestutf8user èùéìòà,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestutf8user2  èùéìòà,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=entry1,cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=entry2,cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcontainer2," + self.base_dn)
        self.delete_force(self.ldb, "cn=parentguidtest,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=parentguidtest,cn=testotherusers," + self.base_dn)
        self.delete_force(self.ldb, "cn=testotherusers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestobject," + self.base_dn)
        self.delete_force(self.ldb, "description=xyz,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "ou=testou,cn=users," + self.base_dn)

    def test_objectclasses(self):
        """Test objectClass behaviour"""
        print "Test objectClass behaviour"""

        # Invalid objectclass specified
        try:
            self.ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectClass": "X" })
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        # We cannot instanciate from an abstract objectclass
        try:
            self.ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectClass": "connectionPoint" })
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.ldb.add({
             "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
             "objectClass": "person" })

        # We can remove derivation classes of the structural objectclass
        # but they're going to be readded afterwards
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("top", FLAG_MOD_DELETE,
          "objectClass")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["objectClass"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("top" in res[0]["objectClass"])

        # The top-most structural class cannot be deleted since there are
        # attributes of it in use
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("person", FLAG_MOD_DELETE,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # We cannot delete classes which weren't specified
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("computer", FLAG_MOD_DELETE,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        # An invalid class cannot be added
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("X", FLAG_MOD_ADD,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        # The top-most structural class cannot be changed by adding another
        # structural one
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("user", FLAG_MOD_ADD,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # An already specified objectclass cannot be added another time
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("person", FLAG_MOD_ADD,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        # Auxiliary classes can always be added
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("bootableDevice", FLAG_MOD_ADD,
          "objectClass")
        ldb.modify(m)

        # It's only possible to replace with the same objectclass combination.
        # So the replace action on "objectClass" attributes is really useless.
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement(["top", "person", "bootableDevice"],
          FLAG_MOD_REPLACE, "objectClass")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement(["person", "bootableDevice"],
          FLAG_MOD_REPLACE, "objectClass")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement(["top", "person", "bootableDevice",
          "connectionPoint"], FLAG_MOD_REPLACE, "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement(["top", "computer"], FLAG_MOD_REPLACE,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # Classes can be removed unless attributes of them are used.
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("bootableDevice", FLAG_MOD_DELETE,
          "objectClass")
        ldb.modify(m)

        res = ldb.search("cn=ldaptestuser,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["objectClass"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("bootableDevice" in res[0]["objectClass"])

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("bootableDevice", FLAG_MOD_ADD,
          "objectClass")
        ldb.modify(m)

        # Add an attribute specific to the "bootableDevice" class
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["bootParameter"] = MessageElement("test", FLAG_MOD_ADD,
          "bootParameter")
        ldb.modify(m)

        # Classes can be removed unless attributes of them are used. Now there
        # exist such attributes on the entry.
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("bootableDevice", FLAG_MOD_DELETE,
          "objectClass")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # Remove the previously specified attribute
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["bootParameter"] = MessageElement("test", FLAG_MOD_DELETE,
          "bootParameter")
        ldb.modify(m)

        # Classes can be removed unless attributes of them are used.
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("bootableDevice", FLAG_MOD_DELETE,
          "objectClass")
        ldb.modify(m)

        self.delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)

    def test_system_only(self):
        """Test systemOnly objects"""
        print "Test systemOnly objects"""

        try:
            self.ldb.add({
                "dn": "cn=ldaptestobject," + self.base_dn,
                "objectclass": "configuration"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.delete_force(self.ldb, "cn=ldaptestobject," + self.base_dn)

    def test_invalid_parent(self):
        """Test adding an object with invalid parent"""
        print "Test adding an object with invalid parent"""

        try:
            self.ldb.add({
                "dn": "cn=ldaptestgroup,cn=thisdoesnotexist123,"
                   + self.base_dn,
                "objectclass": "group"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=thisdoesnotexist123,"
          + self.base_dn)

        try:
            self.ldb.add({
                "dn": "ou=testou,cn=users," + self.base_dn,
                "objectclass": "organizationalUnit"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NAMING_VIOLATION)

        self.delete_force(self.ldb, "ou=testou,cn=users," + self.base_dn)

    def test_invalid_attribute(self):
        """Test invalid attributes on schema/objectclasses"""
        print "Test invalid attributes on schema/objectclasses"""

        # attributes not in schema test

        # add operation

        try:
            self.ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "thisdoesnotexist": "x"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        self.ldb.add({
             "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
             "objectclass": "group"})

        # modify operation

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["thisdoesnotexist"] = MessageElement("x", FLAG_MOD_REPLACE,
          "thisdoesnotexist")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        # attributes not in objectclasses and mandatory attributes missing test
        # Use here a non-SAM entry since it doesn't have special triggers
        # associated which have an impact on the error results.

        # add operations

        # mandatory attribute missing
        try:
            self.ldb.add({
                "dn": "cn=ldaptestobject," + self.base_dn,
                "objectclass": "ipProtocol"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # inadequate but schema-valid attribute specified
        try:
            self.ldb.add({
                "dn": "cn=ldaptestobject," + self.base_dn,
                "objectclass": "ipProtocol",
                "ipProtocolNumber": "1",
                "uid" : "0"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        self.ldb.add({
            "dn": "cn=ldaptestobject," + self.base_dn,
            "objectclass": "ipProtocol",
            "ipProtocolNumber": "1"})

        # modify operations

        # inadequate but schema-valid attribute add trial
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestobject," + self.base_dn)
        m["uid"] = MessageElement("0", FLAG_MOD_ADD, "uid")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # mandatory attribute delete trial
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestobject," + self.base_dn)
        m["ipProtocolNumber"] = MessageElement([], FLAG_MOD_DELETE,
          "ipProtocolNumber")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        # mandatory attribute delete trial
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestobject," + self.base_dn)
        m["ipProtocolNumber"] = MessageElement([], FLAG_MOD_REPLACE,
          "ipProtocolNumber")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        self.delete_force(self.ldb, "cn=ldaptestobject," + self.base_dn)

    def test_single_valued_attributes(self):
        """Test single-valued attributes"""
        print "Test single-valued attributes"""

        try:
            self.ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "sAMAccountName": ["nam1", "nam2"]})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        self.ldb.add({
             "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
             "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement(["nam1","nam2"], FLAG_MOD_REPLACE,
          "sAMAccountName")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testgroupXX", FLAG_MOD_REPLACE,
          "sAMAccountName")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["sAMAccountName"] = MessageElement("testgroupXX2", FLAG_MOD_ADD,
          "sAMAccountName")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_multi_valued_attributes(self):
        """Test multi-valued attributes"""
        print "Test multi-valued attributes"""

# TODO: In this test I added some special tests where I got very unusual
# results back from a real AD. s4 doesn't match them and I've no idea how to
# implement those error cases (maybe there exists a special trigger for
# "description" attributes which handle them)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "description": "desc2",
            "objectclass": "group",
            "description": "desc1"})

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "description": ["desc1", "desc2"]})

#        m = Message()
#        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
#        m["description"] = MessageElement(["desc1","desc2"], FLAG_MOD_REPLACE,
#          "description")
#        try:
#            ldb.modify(m)
#            self.fail()
#        except LdbError, (num, _):
#            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc1", FLAG_MOD_REPLACE,
          "description")
        ldb.modify(m)

#        m = Message()
#        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
#        m["description"] = MessageElement("desc3", FLAG_MOD_ADD,
#          "description")
#        try:
#            ldb.modify(m)
#            self.fail()
#        except LdbError, (num, _):
#            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement(["desc1","desc2"], FLAG_MOD_DELETE,
          "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc1", FLAG_MOD_DELETE,
          "description")
        ldb.modify(m)

#        m = Message()
#        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
#        m["description"] = MessageElement(["desc1","desc2"], FLAG_MOD_REPLACE,
#          "description")
#        try:
#            ldb.modify(m)
#            self.fail()
#        except LdbError, (num, _):
#            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

#        m = Message()
#        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
#        m["description"] = MessageElement(["desc3", "desc4"], FLAG_MOD_ADD,
#          "description")
#        try:
#            ldb.modify(m)
#            self.fail()
#        except LdbError, (num, _):
#            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement("desc3", FLAG_MOD_ADD,
          "description")
        ldb.modify(m)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_empty_messages(self):
        """Test empty messages"""
        print "Test empty messages"""

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        try:
            ldb.add(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OBJECT_CLASS_VIOLATION)

        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_empty_attributes(self):
        """Test empty attributes"""
        print "Test empty attributes"""

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["objectClass"] = MessageElement("group", FLAG_MOD_ADD, "objectClass")
        m["description"] = MessageElement([], FLAG_MOD_ADD, "description")

        try:
            ldb.add(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        self.ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement([], FLAG_MOD_ADD, "description")

        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement([], FLAG_MOD_REPLACE, "description")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["description"] = MessageElement([], FLAG_MOD_DELETE, "description")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_ATTRIBUTE)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_instanceType(self):
        """Tests the 'instanceType' attribute"""
        print "Tests the 'instanceType' attribute"""

        try:
            self.ldb.add({
                "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
                "objectclass": "group",
                "instanceType": ["0", "1"]})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.ldb.add({
             "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
             "objectclass": "group"})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["instanceType"] = MessageElement("0", FLAG_MOD_REPLACE,
          "instanceType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["instanceType"] = MessageElement([], FLAG_MOD_REPLACE,
          "instanceType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["instanceType"] = MessageElement([], FLAG_MOD_DELETE, "instanceType")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_distinguished_name(self):
        """Tests the 'distinguishedName' attribute"""
        print "Tests the 'distinguishedName' attribute"""

        # a wrong "distinguishedName" attribute is obviously tolerated
        self.ldb.add({
              "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
              "objectclass": "group",
              "distinguishedName": "cn=ldaptest,cn=users," + self.base_dn})

        # proof if the DN has been set correctly
        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["distinguishedName"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("distinguishedName" in res[0])
        self.assertTrue(Dn(ldb, res[0]["distinguishedName"][0])
           == Dn(ldb, "cn=ldaptestgroup, cn=users," + self.base_dn))

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["distinguishedName"] = MessageElement(
          "cn=ldaptestuser,cn=users," + self.base_dn, FLAG_MOD_ADD,
          "distinguishedName")

        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["distinguishedName"] = MessageElement(
          "cn=ldaptestuser,cn=users," + self.base_dn, FLAG_MOD_REPLACE,
          "distinguishedName")

        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["distinguishedName"] = MessageElement(
          "cn=ldaptestuser,cn=users," + self.base_dn, FLAG_MOD_DELETE,
          "distinguishedName")

        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_rdn_name(self):
        """Tests the RDN"""
        print "Tests the RDN"""

        try:
            self.ldb.add({
                 "dn": "description=xyz,cn=users," + self.base_dn,
                 "objectclass": "group"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NAMING_VIOLATION)

        self.delete_force(self.ldb, "description=xyz,cn=users," + self.base_dn)

        # a wrong "name" attribute is obviously tolerated
        self.ldb.add({
             "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
             "objectclass": "group",
             "name": "ldaptestgroupx"})

        # proof if the name has been set correctly
        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                         scope=SCOPE_BASE, attrs=["name"])
        self.assertTrue(len(res) == 1)
        self.assertTrue("name" in res[0])
        self.assertTrue(res[0]["name"][0] == "ldaptestgroup")

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["name"] = MessageElement("cn=ldaptestuser", FLAG_MOD_REPLACE,
          "name")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_RDN)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["cn"] = MessageElement("ldaptestuser",
          FLAG_MOD_REPLACE, "cn")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_RDN)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)


        # this test needs to be disabled until we really understand
        # what the rDN length constraints are
    def DISABLED_test_largeRDN(self):
        """Testing large rDN (limit 64 characters)"""
        rdn = "CN=a012345678901234567890123456789012345678901234567890123456789012";
        self.delete_force(self.ldb, "%s,%s" % (rdn, self.base_dn))
        ldif = """
dn: %s,%s""" % (rdn,self.base_dn) + """
objectClass: container
"""
        self.ldb.add_ldif(ldif)
        self.delete_force(self.ldb, "%s,%s" % (rdn, self.base_dn))

        rdn = "CN=a0123456789012345678901234567890123456789012345678901234567890120";
        self.delete_force(self.ldb, "%s,%s" % (rdn, self.base_dn))
        try:
            ldif = """
dn: %s,%s""" % (rdn,self.base_dn) + """
objectClass: container
"""
            self.ldb.add_ldif(ldif)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_CONSTRAINT_VIOLATION)
        self.delete_force(self.ldb, "%s,%s" % (rdn, self.base_dn))

    def test_rename(self):
        """Tests the rename operation"""
        print "Tests the rename operations"""

        try:
            # cannot rename to be a child of itself
            ldb.rename(self.base_dn, "dc=test," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        try:
            # inexistent object
            ldb.rename("cn=ldaptestuser2,cn=users," + self.base_dn, "cn=ldaptestuser2,cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        self.ldb.add({
             "dn": "cn=ldaptestuser2,cn=users," + self.base_dn,
             "objectclass": ["user", "person"] })

        ldb.rename("cn=ldaptestuser2,cn=users," + self.base_dn, "cn=ldaptestuser2,cn=users," + self.base_dn)
        ldb.rename("cn=ldaptestuser2,cn=users," + self.base_dn, "cn=ldaptestuser3,cn=users," + self.base_dn)
        ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "cn=ldaptestUSER3,cn=users," + self.base_dn)

        try:
            # containment problem: a user entry cannot contain user entries
            ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "cn=ldaptestuser4,cn=ldaptestuser3,cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NAMING_VIOLATION)

        try:
            # invalid parent
            ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "cn=ldaptestuser3,cn=people,cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_OTHER)

        try:
            # invalid target DN syntax
            ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, ",cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INVALID_DN_SYNTAX)

        try:
            # invalid RDN name
            ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "ou=ldaptestuser3,cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        self.delete_force(self.ldb, "cn=ldaptestuser3,cn=users," + self.base_dn)

    def test_rename_twice(self):
        """Tests the rename operation twice - this corresponds to a past bug"""
        print "Tests the rename twice operation"""

        self.ldb.add({
             "dn": "cn=ldaptestuser5,cn=users," + self.base_dn,
             "objectclass": ["user", "person"] })

        ldb.rename("cn=ldaptestuser5,cn=users," + self.base_dn, "cn=ldaptestUSER5,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser5,cn=users," + self.base_dn)
        self.ldb.add({
             "dn": "cn=ldaptestuser5,cn=users," + self.base_dn,
             "objectclass": ["user", "person"] })
        ldb.rename("cn=ldaptestuser5,cn=Users," + self.base_dn, "cn=ldaptestUSER5,cn=users," + self.base_dn)
        res = ldb.search(expression="cn=ldaptestuser5")
        print "Found %u records" % len(res)
        self.assertEquals(len(res), 1, "Wrong number of hits for cn=ldaptestuser5")
        res = ldb.search(expression="(&(cn=ldaptestuser5)(objectclass=user))")
        print "Found %u records" % len(res)
        self.assertEquals(len(res), 1, "Wrong number of hits for (&(cn=ldaptestuser5)(objectclass=user))")
        self.delete_force(self.ldb, "cn=ldaptestuser5,cn=users," + self.base_dn)

    def test_parentGUID(self):
        """Test parentGUID behaviour"""
        print "Testing parentGUID behaviour\n"

        # TODO: This seems to fail on Windows Server. Hidden attribute?

        self.ldb.add({
            "dn": "cn=parentguidtest,cn=users," + self.base_dn,
            "objectclass":"user",
            "samaccountname":"parentguidtest"});
        res1 = ldb.search(base="cn=parentguidtest,cn=users," + self.base_dn, scope=SCOPE_BASE,
                          attrs=["parentGUID", "samaccountname"]);
        res2 = ldb.search(base="cn=users," + self.base_dn,scope=SCOPE_BASE,
                          attrs=["objectGUID"]);
        res3 = ldb.search(base=self.base_dn, scope=SCOPE_BASE,
                          attrs=["parentGUID"]);

        """Check if the parentGUID is valid """
        self.assertEquals(res1[0]["parentGUID"], res2[0]["objectGUID"]);

        """Check if it returns nothing when there is no parent object"""
        has_parentGUID = False
        for key in res3[0].keys():
            if key == "parentGUID":
                has_parentGUID = True
                break
        self.assertFalse(has_parentGUID);

        """Ensures that if you look for another object attribute after the constructed
            parentGUID, it will return correctly"""
        has_another_attribute = False
        for key in res1[0].keys():
            if key == "sAMAccountName":
                has_another_attribute = True
                break
        self.assertTrue(has_another_attribute)
        self.assertTrue(len(res1[0]["samaccountname"]) == 1)
        self.assertEquals(res1[0]["samaccountname"][0], "parentguidtest");

        print "Testing parentGUID behaviour on rename\n"

        self.ldb.add({
            "dn": "cn=testotherusers," + self.base_dn,
            "objectclass":"container"});
        res1 = ldb.search(base="cn=testotherusers," + self.base_dn,scope=SCOPE_BASE,
                          attrs=["objectGUID"]);
        ldb.rename("cn=parentguidtest,cn=users," + self.base_dn,
                   "cn=parentguidtest,cn=testotherusers," + self.base_dn);
        res2 = ldb.search(base="cn=parentguidtest,cn=testotherusers," + self.base_dn,
                          scope=SCOPE_BASE,
                          attrs=["parentGUID"]);
        self.assertEquals(res1[0]["objectGUID"], res2[0]["parentGUID"]);

        self.delete_force(self.ldb, "cn=parentguidtest,cn=testotherusers," + self.base_dn)
        self.delete_force(self.ldb, "cn=testotherusers," + self.base_dn)

    def test_groupType_int32(self):
        """Test groupType (int32) behaviour (should appear to be casted to a 32 bit signed integer before comparsion)"""
        print "Testing groupType (int32) behaviour\n"

        res1 = ldb.search(base=self.base_dn, scope=SCOPE_SUBTREE,
                          attrs=["groupType"], expression="groupType=2147483653");

        res2 = ldb.search(base=self.base_dn, scope=SCOPE_SUBTREE,
                          attrs=["groupType"], expression="groupType=-2147483643");

        self.assertEquals(len(res1), len(res2))

        self.assertTrue(res1.count > 0)

        self.assertEquals(res1[0]["groupType"][0], "-2147483643")

    def test_linked_attributes(self):
        """This tests the linked attribute behaviour"""
        print "Testing linked attribute behaviour\n"

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group"})

        # This should not work since "memberOf" is linked to "member"
        try:
            ldb.add({
                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
                "objectclass": ["user", "person"],
                "memberOf": "cn=ldaptestgroup,cn=users," + self.base_dn})
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["memberOf"] = MessageElement("cn=ldaptestgroup,cn=users," + self.base_dn,
          FLAG_MOD_ADD, "memberOf")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
          FLAG_MOD_ADD, "member")
        ldb.modify(m)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["memberOf"] = MessageElement("cn=ldaptestgroup,cn=users," + self.base_dn,
          FLAG_MOD_REPLACE, "memberOf")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["memberOf"] = MessageElement("cn=ldaptestgroup,cn=users," + self.base_dn,
          FLAG_MOD_DELETE, "memberOf")
        try:
            ldb.modify(m)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        m["member"] = MessageElement("cn=ldaptestuser,cn=users," + self.base_dn,
          FLAG_MOD_DELETE, "member")
        ldb.modify(m)

        # This should yield no results since the member attribute for
        # "ldaptestuser" should have been deleted
        res1 = ldb.search("cn=ldaptestgroup, cn=users," + self.base_dn,
                          scope=SCOPE_BASE,
                          expression="(member=cn=ldaptestuser,cn=users," + self.base_dn + ")",
                          attrs=[])
        self.assertTrue(len(res1) == 0)

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=users," + self.base_dn,
            "objectclass": "group",
            "member": "cn=ldaptestuser,cn=users," + self.base_dn})

        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

        # Make sure that the "member" attribute for "ldaptestuser" has been
        # removed
        res = ldb.search("cn=ldaptestgroup,cn=users," + self.base_dn,
                          scope=SCOPE_BASE, attrs=["member"])
        self.assertTrue(len(res) == 1)
        self.assertFalse("member" in res[0])

        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)

    def test_groups(self):
        """This tests the group behaviour (setting, changing) of a user account"""
        print "Testing group behaviour\n"

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
# TODO Some more investigation needed here
#        try:
#            ldb.add({
#                "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
#                "objectclass": ["user", "person"],
#                "primaryGroupID": str(group_rid_1)})
#            self.fail()
#        except LdbError, (num, _):
#            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)
#        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)

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

        ldb.add({
            "dn": "cn=ldaptestuser,cn=users," + self.base_dn,
            "objectclass": ["user", "person"]})

        # We should be able to reset our actual primary group
        m = Message()
        m.dn = Dn(ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        m["primaryGroupID"] = MessageElement("513", FLAG_MOD_REPLACE,
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

    def test_wkguid(self):
        """Test Well known GUID behaviours (including DN+Binary)"""
        print "Test Well known GUID behaviours (including DN+Binary)"""

        res = self.ldb.search(base=("<WKGUID=ab1d30f3768811d1aded00c04fd8d5cd,%s>" % self.base_dn), scope=SCOPE_BASE, attrs=[])
        self.assertEquals(len(res), 1)
        
        res2 = self.ldb.search(scope=SCOPE_BASE, attrs=["wellKnownObjects"], expression=("wellKnownObjects=B:32:ab1d30f3768811d1aded00c04fd8d5cd:%s" % res[0].dn))
        self.assertEquals(len(res2), 1)

        # Prove that the matching rule is over the whole DN+Binary
        res2 = self.ldb.search(scope=SCOPE_BASE, attrs=["wellKnownObjects"], expression=("wellKnownObjects=B:32:ab1d30f3768811d1aded00c04fd8d5cd"))
        self.assertEquals(len(res2), 0)
        # Prove that the matching rule is over the whole DN+Binary
        res2 = self.ldb.search(scope=SCOPE_BASE, attrs=["wellKnownObjects"], expression=("wellKnownObjects=%s") % res[0].dn)
        self.assertEquals(len(res2), 0)

    def test_subschemasubentry(self):
        """Test subSchemaSubEntry appears when requested, but not when not requested"""
        print "Test subSchemaSubEntry"""

        res = self.ldb.search(base=self.base_dn, scope=SCOPE_BASE, attrs=["subSchemaSubEntry"])
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["subSchemaSubEntry"][0], "CN=Aggregate,"+self.schema_dn)

        res = self.ldb.search(base=self.base_dn, scope=SCOPE_BASE, attrs=["*"])
        self.assertEquals(len(res), 1)
        self.assertTrue("subScheamSubEntry" not in res[0])

    def test_subtree_delete(self):
        """Tests subtree deletes"""

        print "Test subtree deletes"""

        ldb.add({
            "dn": "cn=ldaptestcontainer," + self.base_dn,
            "objectclass": "container"})
        ldb.add({
            "dn": "cn=entry1,cn=ldaptestcontainer," + self.base_dn,
            "objectclass": "container"})
        ldb.add({
            "dn": "cn=entry2,cn=ldaptestcontainer," + self.base_dn,
            "objectclass": "container"})

        try:
            ldb.delete("cn=ldaptestcontainer," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        ldb.delete("cn=ldaptestcontainer," + self.base_dn, ["tree_delete:0"])

        try:
            res = ldb.search("cn=ldaptestcontainer," + self.base_dn,
                             scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)
        try:
            res = ldb.search("cn=entry1,cn=ldaptestcontainer," + self.base_dn,
                             scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)
        try:
            res = ldb.search("cn=entry2,cn=ldaptestcontainer," + self.base_dn,
                             scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        self.delete_force(self.ldb, "cn=entry1,cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=entry2,cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcontainer," + self.base_dn)

    def test_all(self):
        """Basic tests"""

        print "Testing user add"

        ldb.add({
            "dn": "cn=ldaptestuser,cn=uSers," + self.base_dn,
            "objectclass": ["user", "person"],
            "cN": "LDAPtestUSER",
            "givenname": "ldap",
            "sn": "testy"})

        ldb.add({
            "dn": "cn=ldaptestgroup,cn=uSers," + self.base_dn,
            "objectclass": "group",
            "member": "cn=ldaptestuser,cn=useRs," + self.base_dn})

        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + self.base_dn,
            "objectclass": "computer",
            "cN": "LDAPtestCOMPUTER"})

        ldb.add({"dn": "cn=ldaptest2computer,cn=computers," + self.base_dn,
            "objectClass": "computer",
            "cn": "LDAPtest2COMPUTER",
            "userAccountControl": str(UF_WORKSTATION_TRUST_ACCOUNT),
            "displayname": "ldap testy"})

        try:
            ldb.add({"dn": "cn=ldaptestcomputer3,cn=computers," + self.base_dn,
                     "objectClass": "computer",
                     "cn": "LDAPtest2COMPUTER"
                     })
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INVALID_DN_SYNTAX)

        try:
            ldb.add({"dn": "cn=ldaptestcomputer3,cn=computers," + self.base_dn,
                     "objectClass": "computer",
                     "cn": "ldaptestcomputer3",
                     "sAMAccountType": str(ATYPE_NORMAL_ACCOUNT)
                })
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        ldb.add({"dn": "cn=ldaptestcomputer3,cn=computers," + self.base_dn,
                 "objectClass": "computer",
                 "cn": "LDAPtestCOMPUTER3"
                 })

        print "Testing ldb.search for (&(cn=ldaptestcomputer3)(objectClass=user))";
        res = ldb.search(self.base_dn, expression="(&(cn=ldaptestcomputer3)(objectClass=user))");
        self.assertEquals(len(res), 1, "Found only %d for (&(cn=ldaptestcomputer3)(objectClass=user))" % len(res))

        self.assertEquals(str(res[0].dn), ("CN=ldaptestcomputer3,CN=Computers," + self.base_dn));
        self.assertEquals(res[0]["cn"][0], "ldaptestcomputer3");
        self.assertEquals(res[0]["name"][0], "ldaptestcomputer3");
        self.assertEquals(res[0]["objectClass"][0], "top");
        self.assertEquals(res[0]["objectClass"][1], "person");
        self.assertEquals(res[0]["objectClass"][2], "organizationalPerson");
        self.assertEquals(res[0]["objectClass"][3], "user");
        self.assertEquals(res[0]["objectClass"][4], "computer");
        self.assertTrue("objectGUID" in res[0])
        self.assertTrue("whenCreated" in res[0])
        self.assertEquals(res[0]["objectCategory"][0], ("CN=Computer,CN=Schema,CN=Configuration," + self.base_dn));
        self.assertEquals(int(res[0]["primaryGroupID"][0]), 513);
        self.assertEquals(int(res[0]["sAMAccountType"][0]), ATYPE_NORMAL_ACCOUNT);
        self.assertEquals(int(res[0]["userAccountControl"][0]), UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE);

        self.delete_force(self.ldb, "cn=ldaptestcomputer3,cn=computers," + self.base_dn)

        print "Testing attribute or value exists behaviour"
        try:
            ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + self.base_dn + """
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: cifs/ldaptest2computer
""")
            self.fail()
        except LdbError, (num, msg):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + self.base_dn + """
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: cifs/ldaptest2computer
""")
        try:
            ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + self.base_dn + """
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
""")
            self.fail()
        except LdbError, (num, msg):
            self.assertEquals(num, ERR_ATTRIBUTE_OR_VALUE_EXISTS)

        print "Testing ranged results"
        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + self.base_dn + """
changetype: modify
replace: servicePrincipalName
""")

        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + self.base_dn + """
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/ldaptest2computer0
servicePrincipalName: host/ldaptest2computer1
servicePrincipalName: host/ldaptest2computer2
servicePrincipalName: host/ldaptest2computer3
servicePrincipalName: host/ldaptest2computer4
servicePrincipalName: host/ldaptest2computer5
servicePrincipalName: host/ldaptest2computer6
servicePrincipalName: host/ldaptest2computer7
servicePrincipalName: host/ldaptest2computer8
servicePrincipalName: host/ldaptest2computer9
servicePrincipalName: host/ldaptest2computer10
servicePrincipalName: host/ldaptest2computer11
servicePrincipalName: host/ldaptest2computer12
servicePrincipalName: host/ldaptest2computer13
servicePrincipalName: host/ldaptest2computer14
servicePrincipalName: host/ldaptest2computer15
servicePrincipalName: host/ldaptest2computer16
servicePrincipalName: host/ldaptest2computer17
servicePrincipalName: host/ldaptest2computer18
servicePrincipalName: host/ldaptest2computer19
servicePrincipalName: host/ldaptest2computer20
servicePrincipalName: host/ldaptest2computer21
servicePrincipalName: host/ldaptest2computer22
servicePrincipalName: host/ldaptest2computer23
servicePrincipalName: host/ldaptest2computer24
servicePrincipalName: host/ldaptest2computer25
servicePrincipalName: host/ldaptest2computer26
servicePrincipalName: host/ldaptest2computer27
servicePrincipalName: host/ldaptest2computer28
servicePrincipalName: host/ldaptest2computer29
""")

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE,
                         attrs=["servicePrincipalName;range=0-*"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        #print len(res[0]["servicePrincipalName;range=0-*"])
        self.assertEquals(len(res[0]["servicePrincipalName;range=0-*"]), 30)

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=0-19"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
            # print res[0]["servicePrincipalName;range=0-19"].length
        self.assertEquals(len(res[0]["servicePrincipalName;range=0-19"]), 20)


        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=0-30"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        self.assertEquals(len(res[0]["servicePrincipalName;range=0-*"]), 30)

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=0-40"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        self.assertEquals(len(res[0]["servicePrincipalName;range=0-*"]), 30)

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=30-40"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        self.assertEquals(len(res[0]["servicePrincipalName;range=30-*"]), 0)


        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=10-40"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        self.assertEquals(len(res[0]["servicePrincipalName;range=10-*"]), 20)
        # pos_11 = res[0]["servicePrincipalName;range=10-*"][18]

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=11-40"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        self.assertEquals(len(res[0]["servicePrincipalName;range=11-*"]), 19)
            # print res[0]["servicePrincipalName;range=11-*"][18]
            # print pos_11
            # self.assertEquals((res[0]["servicePrincipalName;range=11-*"][18]), pos_11)

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName;range=11-15"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
        self.assertEquals(len(res[0]["servicePrincipalName;range=11-15"]), 5)
            # self.assertEquals(res[0]["servicePrincipalName;range=11-15"][4], pos_11)

        res = ldb.search(self.base_dn, expression="(cn=ldaptest2computer))", scope=SCOPE_SUBTREE, attrs=["servicePrincipalName"])
        self.assertEquals(len(res), 1, "Could not find (cn=ldaptest2computer)")
            # print res[0]["servicePrincipalName"][18]
            # print pos_11
        self.assertEquals(len(res[0]["servicePrincipalName"]), 30)
            # self.assertEquals(res[0]["servicePrincipalName"][18], pos_11)

        self.delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        ldb.add({
            "dn": "cn=ldaptestuser2,cn=useRs," + self.base_dn,
            "objectClass": ["person", "user"],
            "cn": "LDAPtestUSER2",
            "givenname": "testy",
            "sn": "ldap user2"})

        print "Testing Ambigious Name Resolution"
        # Testing ldb.search for (&(anr=ldap testy)(objectClass=user))
        res = ldb.search(expression="(&(anr=ldap testy)(objectClass=user))")
        self.assertEquals(len(res), 3, "Found only %d of 3 for (&(anr=ldap testy)(objectClass=user))" % len(res))

        # Testing ldb.search for (&(anr=testy ldap)(objectClass=user))
        res = ldb.search(expression="(&(anr=testy ldap)(objectClass=user))")
        self.assertEquals(len(res), 2, "Found only %d of 2 for (&(anr=testy ldap)(objectClass=user))" % len(res))

        # Testing ldb.search for (&(anr=ldap)(objectClass=user))
        res = ldb.search(expression="(&(anr=ldap)(objectClass=user))")
        self.assertEquals(len(res), 4, "Found only %d of 4 for (&(anr=ldap)(objectClass=user))" % len(res))

        # Testing ldb.search for (&(anr==ldap)(objectClass=user))
        res = ldb.search(expression="(&(anr==ldap)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(anr==ldap)(objectClass=user)). Found only %d for (&(anr=ldap)(objectClass=user))" % len(res))

        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser,CN=Users," + self.base_dn))
        self.assertEquals(res[0]["cn"][0], "ldaptestuser")
        self.assertEquals(str(res[0]["name"]), "ldaptestuser")

        # Testing ldb.search for (&(anr=testy)(objectClass=user))
        res = ldb.search(expression="(&(anr=testy)(objectClass=user))")
        self.assertEquals(len(res), 2, "Found only %d for (&(anr=testy)(objectClass=user))" % len(res))

        # Testing ldb.search for (&(anr=testy ldap)(objectClass=user))
        res = ldb.search(expression="(&(anr=testy ldap)(objectClass=user))")
        self.assertEquals(len(res), 2, "Found only %d for (&(anr=testy ldap)(objectClass=user))" % len(res))

        # Testing ldb.search for (&(anr==testy ldap)(objectClass=user))
# this test disabled for the moment, as anr with == tests are not understood
#        res = ldb.search(expression="(&(anr==testy ldap)(objectClass=user))")
#        self.assertEquals(len(res), 1, "Found only %d for (&(anr==testy ldap)(objectClass=user))" % len(res))

#        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser,CN=Users," + self.base_dn))
#        self.assertEquals(res[0]["cn"][0], "ldaptestuser")
#        self.assertEquals(res[0]["name"][0], "ldaptestuser")

        # Testing ldb.search for (&(anr==testy ldap)(objectClass=user))
#        res = ldb.search(expression="(&(anr==testy ldap)(objectClass=user))")
#        self.assertEquals(len(res), 1, "Could not find (&(anr==testy ldap)(objectClass=user))")

#        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser,CN=Users," + self.base_dn))
#        self.assertEquals(res[0]["cn"][0], "ldaptestuser")
#        self.assertEquals(res[0]["name"][0], "ldaptestuser")

        # Testing ldb.search for (&(anr=testy ldap user)(objectClass=user))
        res = ldb.search(expression="(&(anr=testy ldap user)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(anr=testy ldap user)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser2,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestuser2")
        self.assertEquals(str(res[0]["name"]), "ldaptestuser2")

        # Testing ldb.search for (&(anr==testy ldap user2)(objectClass=user))
#        res = ldb.search(expression="(&(anr==testy ldap user2)(objectClass=user))")
#        self.assertEquals(len(res), 1, "Could not find (&(anr==testy ldap user2)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser2,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestuser2")
        self.assertEquals(str(res[0]["name"]), "ldaptestuser2")

        # Testing ldb.search for (&(anr==ldap user2)(objectClass=user))
#        res = ldb.search(expression="(&(anr==ldap user2)(objectClass=user))")
#        self.assertEquals(len(res), 1, "Could not find (&(anr==ldap user2)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser2,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestuser2")
        self.assertEquals(str(res[0]["name"]), "ldaptestuser2")

        # Testing ldb.search for (&(anr==not ldap user2)(objectClass=user))
#        res = ldb.search(expression="(&(anr==not ldap user2)(objectClass=user))")
#        self.assertEquals(len(res), 0, "Must not find (&(anr==not ldap user2)(objectClass=user))")

        # Testing ldb.search for (&(anr=not ldap user2)(objectClass=user))
        res = ldb.search(expression="(&(anr=not ldap user2)(objectClass=user))")
        self.assertEquals(len(res), 0, "Must not find (&(anr=not ldap user2)(objectClass=user))")

        # Testing ldb.search for (&(anr="testy ldap")(objectClass=user)) (ie, with quotes)
#        res = ldb.search(expression="(&(anr==\"testy ldap\")(objectClass=user))")
#        self.assertEquals(len(res), 0, "Found (&(anr==\"testy ldap\")(objectClass=user))")

        print "Testing Renames"

        attrs = ["objectGUID", "objectSid"]
        print "Testing ldb.search for (&(cn=ldaptestUSer2)(objectClass=user))"
        res_user = ldb.search(self.base_dn, expression="(&(cn=ldaptestUSer2)(objectClass=user))", scope=SCOPE_SUBTREE, attrs=attrs)
        self.assertEquals(len(res_user), 1, "Could not find (&(cn=ldaptestUSer2)(objectClass=user))")

        # Check rename works with extended/alternate DN forms
        ldb.rename("<SID=" + ldb.schema_format_value("objectSID", res_user[0]["objectSID"][0]) + ">" , "cn=ldaptestUSER3,cn=users," + self.base_dn)

        print "Testing ldb.search for (&(cn=ldaptestuser3)(objectClass=user))"
        res = ldb.search(expression="(&(cn=ldaptestuser3)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestuser3)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestUSER3,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestUSER3")
        self.assertEquals(str(res[0]["name"]), "ldaptestUSER3")

         #"Testing ldb.search for (&(&(cn=ldaptestuser3)(userAccountControl=*))(objectClass=user))"
        res = ldb.search(expression="(&(&(cn=ldaptestuser3)(userAccountControl=*))(objectClass=user))")
        self.assertEquals(len(res), 1, "(&(&(cn=ldaptestuser3)(userAccountControl=*))(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestUSER3,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestUSER3")
        self.assertEquals(str(res[0]["name"]), "ldaptestUSER3")

         #"Testing ldb.search for (&(&(cn=ldaptestuser3)(userAccountControl=546))(objectClass=user))"
        res = ldb.search(expression="(&(&(cn=ldaptestuser3)(userAccountControl=546))(objectClass=user))")
        self.assertEquals(len(res), 1, "(&(&(cn=ldaptestuser3)(userAccountControl=546))(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestUSER3,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestUSER3")
        self.assertEquals(str(res[0]["name"]), "ldaptestUSER3")

         #"Testing ldb.search for (&(&(cn=ldaptestuser3)(userAccountControl=547))(objectClass=user))"
        res = ldb.search(expression="(&(&(cn=ldaptestuser3)(userAccountControl=547))(objectClass=user))")
        self.assertEquals(len(res), 0, "(&(&(cn=ldaptestuser3)(userAccountControl=547))(objectClass=user))")

        # This is a Samba special, and does not exist in real AD
        #    print "Testing ldb.search for (dn=CN=ldaptestUSER3,CN=Users," + self.base_dn + ")"
        #    res = ldb.search("(dn=CN=ldaptestUSER3,CN=Users," + self.base_dn + ")")
        #    if (res.error != 0 || len(res) != 1) {
        #        print "Could not find (dn=CN=ldaptestUSER3,CN=Users," + self.base_dn + ")"
        #        self.assertEquals(len(res), 1)
        #    }
        #    self.assertEquals(res[0].dn, ("CN=ldaptestUSER3,CN=Users," + self.base_dn))
        #    self.assertEquals(res[0].cn, "ldaptestUSER3")
        #    self.assertEquals(res[0].name, "ldaptestUSER3")

        print "Testing ldb.search for (distinguishedName=CN=ldaptestUSER3,CN=Users," + self.base_dn + ")"
        res = ldb.search(expression="(distinguishedName=CN=ldaptestUSER3,CN=Users," + self.base_dn + ")")
        self.assertEquals(len(res), 1, "Could not find (dn=CN=ldaptestUSER3,CN=Users," + self.base_dn + ")")
        self.assertEquals(str(res[0].dn), ("CN=ldaptestUSER3,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestUSER3")
        self.assertEquals(str(res[0]["name"]), "ldaptestUSER3")

        # ensure we cannot add it again
        try:
            ldb.add({"dn": "cn=ldaptestuser3,cn=userS," + self.base_dn,
                      "objectClass": ["person", "user"],
                      "cn": "LDAPtestUSER3"})
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ENTRY_ALREADY_EXISTS)

        # rename back
        ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "cn=ldaptestuser2,cn=users," + self.base_dn)

        # ensure we cannot rename it twice
        try:
            ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn,
                       "cn=ldaptestuser2,cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        # ensure can now use that name
        ldb.add({"dn": "cn=ldaptestuser3,cn=users," + self.base_dn,
                      "objectClass": ["person", "user"],
                      "cn": "LDAPtestUSER3"})

        # ensure we now cannot rename
        try:
            ldb.rename("cn=ldaptestuser2,cn=users," + self.base_dn, "cn=ldaptestuser3,cn=users," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_ENTRY_ALREADY_EXISTS)
        try:
            ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "cn=ldaptestuser3,cn=configuration," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertTrue(num in (71, 64))

        ldb.rename("cn=ldaptestuser3,cn=users," + self.base_dn, "cn=ldaptestuser5,cn=users," + self.base_dn)

        ldb.delete("cn=ldaptestuser5,cn=users," + self.base_dn)

        self.delete_force(ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)

        ldb.rename("cn=ldaptestgroup,cn=users," + self.base_dn, "cn=ldaptestgroup2,cn=users," + self.base_dn)

        print "Testing subtree renames"

        ldb.add({"dn": "cn=ldaptestcontainer," + self.base_dn,
                 "objectClass": "container"})

        ldb.add({"dn": "CN=ldaptestuser4,CN=ldaptestcontainer," + self.base_dn,
                 "objectClass": ["person", "user"],
                 "cn": "LDAPtestUSER4"})

        ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + self.base_dn + """
changetype: modify
add: member
member: cn=ldaptestuser4,cn=ldaptestcontainer,""" + self.base_dn + """
member: cn=ldaptestcomputer,cn=computers,""" + self.base_dn + """
member: cn=ldaptestuser2,cn=users,""" + self.base_dn + """
""")

        print "Testing ldb.rename of cn=ldaptestcontainer," + self.base_dn + " to cn=ldaptestcontainer2," + self.base_dn
        ldb.rename("CN=ldaptestcontainer," + self.base_dn, "CN=ldaptestcontainer2," + self.base_dn)

        print "Testing ldb.search for (&(cn=ldaptestuser4)(objectClass=user))"
        res = ldb.search(expression="(&(cn=ldaptestuser4)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestuser4)(objectClass=user))")

        print "Testing subtree ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in (just renamed from) cn=ldaptestcontainer," + self.base_dn
        try:
            res = ldb.search("cn=ldaptestcontainer," + self.base_dn,
                    expression="(&(cn=ldaptestuser4)(objectClass=user))",
                    scope=SCOPE_SUBTREE)
            self.fail(res)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        print "Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in (just renamed from) cn=ldaptestcontainer," + self.base_dn
        try:
            res = ldb.search("cn=ldaptestcontainer," + self.base_dn,
                    expression="(&(cn=ldaptestuser4)(objectClass=user))", scope=SCOPE_ONELEVEL)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        print "Testing ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in renamed container"
        res = ldb.search("cn=ldaptestcontainer2," + self.base_dn, expression="(&(cn=ldaptestuser4)(objectClass=user))", scope=SCOPE_SUBTREE)
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestuser4)(objectClass=user)) under cn=ldaptestcontainer2," + self.base_dn)

        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn))
        self.assertEquals(res[0]["memberOf"][0].upper(), ("CN=ldaptestgroup2,CN=Users," + self.base_dn).upper())

        time.sleep(4)

        print "Testing ldb.search for (&(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn + ")(objectclass=group)) to check subtree renames and linked attributes"
        res = ldb.search(self.base_dn, expression="(&(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn + ")(objectclass=group))", scope=SCOPE_SUBTREE)
        self.assertEquals(len(res), 1, "Could not find (&(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn + ")(objectclass=group)), perhaps linked attributes are not consistant with subtree renames?")

        print "Testing ldb.rename (into itself) of cn=ldaptestcontainer2," + self.base_dn + " to cn=ldaptestcontainer,cn=ldaptestcontainer2," + self.base_dn
        try:
            ldb.rename("cn=ldaptestcontainer2," + self.base_dn, "cn=ldaptestcontainer,cn=ldaptestcontainer2," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        print "Testing ldb.rename (into non-existent container) of cn=ldaptestcontainer2," + self.base_dn + " to cn=ldaptestcontainer,cn=ldaptestcontainer3," + self.base_dn
        try:
            ldb.rename("cn=ldaptestcontainer2," + self.base_dn, "cn=ldaptestcontainer,cn=ldaptestcontainer3," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertTrue(num in (ERR_UNWILLING_TO_PERFORM, ERR_OTHER))

        print "Testing delete (should fail, not a leaf node) of renamed cn=ldaptestcontainer2," + self.base_dn
        try:
            ldb.delete("cn=ldaptestcontainer2," + self.base_dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        print "Testing base ldb.search for CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn
        res = ldb.search(expression="(objectclass=*)", base=("CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn), scope=SCOPE_BASE)
        self.assertEquals(len(res), 1)
        res = ldb.search(expression="(cn=ldaptestuser40)", base=("CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn), scope=SCOPE_BASE)
        self.assertEquals(len(res), 0)

        print "Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in cn=ldaptestcontainer2," + self.base_dn
        res = ldb.search(expression="(&(cn=ldaptestuser4)(objectClass=user))", base=("cn=ldaptestcontainer2," + self.base_dn), scope=SCOPE_ONELEVEL)
        # FIXME: self.assertEquals(len(res), 0)

        print "Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in cn=ldaptestcontainer2," + self.base_dn
        res = ldb.search(expression="(&(cn=ldaptestuser4)(objectClass=user))", base=("cn=ldaptestcontainer2," + self.base_dn), scope=SCOPE_SUBTREE)
        # FIXME: self.assertEquals(len(res), 0)

        print "Testing delete of subtree renamed "+("CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn)
        ldb.delete(("CN=ldaptestuser4,CN=ldaptestcontainer2," + self.base_dn))
        print "Testing delete of renamed cn=ldaptestcontainer2," + self.base_dn
        ldb.delete("cn=ldaptestcontainer2," + self.base_dn)

        ldb.add({"dn": "cn=ldaptestutf8user èùéìòà,cn=users," + self.base_dn, "objectClass": "user"})

        ldb.add({"dn": "cn=ldaptestutf8user2  èùéìòà,cn=users," + self.base_dn, "objectClass": "user"})

        print "Testing ldb.search for (&(cn=ldaptestuser)(objectClass=user))"
        res = ldb.search(expression="(&(cn=ldaptestuser)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestuser)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestuser,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestuser")
        self.assertEquals(str(res[0]["name"]), "ldaptestuser")
        self.assertEquals(set(res[0]["objectClass"]), set(["top", "person", "organizationalPerson", "user"]))
        self.assertTrue("objectGUID" in res[0])
        self.assertTrue("whenCreated" in res[0])
        self.assertEquals(str(res[0]["objectCategory"]), ("CN=Person,CN=Schema,CN=Configuration," + self.base_dn))
        self.assertEquals(int(res[0]["sAMAccountType"][0]), ATYPE_NORMAL_ACCOUNT)
        self.assertEquals(int(res[0]["userAccountControl"][0]), UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE)
        self.assertEquals(res[0]["memberOf"][0].upper(), ("CN=ldaptestgroup2,CN=Users," + self.base_dn).upper())
        self.assertEquals(len(res[0]["memberOf"]), 1)

        print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + self.base_dn + "))"
        res2 = ldb.search(expression="(&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + self.base_dn + "))")
        self.assertEquals(len(res2), 1, "Could not find (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + self.base_dn + "))")

        self.assertEquals(res[0].dn, res2[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon))"
        res3 = ldb.search(expression="(&(cn=ldaptestuser)(objectCategory=PerSon))")
        self.assertEquals(len(res3), 1, "Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)): matched %d" % len(res3))

        self.assertEquals(res[0].dn, res3[0].dn)

        if gc_ldb is not None:
            print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog"
            res3gc = gc_ldb.search(expression="(&(cn=ldaptestuser)(objectCategory=PerSon))")
            self.assertEquals(len(res3gc), 1)

            self.assertEquals(res[0].dn, res3gc[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in with 'phantom root' control"

        if gc_ldb is not None:
            res3control = gc_ldb.search(self.base_dn, expression="(&(cn=ldaptestuser)(objectCategory=PerSon))", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["search_options:1:2"])
            self.assertEquals(len(res3control), 1, "Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog")

            self.assertEquals(res[0].dn, res3control[0].dn)

        ldb.delete(res[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectClass=user))"
        res = ldb.search(expression="(&(cn=ldaptestcomputer)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestuser)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestcomputer,CN=Computers," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestcomputer")
        self.assertEquals(str(res[0]["name"]), "ldaptestcomputer")
        self.assertEquals(set(res[0]["objectClass"]), set(["top", "person", "organizationalPerson", "user", "computer"]))
        self.assertTrue("objectGUID" in res[0])
        self.assertTrue("whenCreated" in res[0])
        self.assertEquals(str(res[0]["objectCategory"]), ("CN=Computer,CN=Schema,CN=Configuration," + self.base_dn))
        self.assertEquals(int(res[0]["primaryGroupID"][0]), 513)
        self.assertEquals(int(res[0]["sAMAccountType"][0]), ATYPE_NORMAL_ACCOUNT)
        self.assertEquals(int(res[0]["userAccountControl"][0]), UF_NORMAL_ACCOUNT | UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE)
        self.assertEquals(res[0]["memberOf"][0].upper(), ("CN=ldaptestgroup2,CN=Users," + self.base_dn).upper())
        self.assertEquals(len(res[0]["memberOf"]), 1)

        print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + self.base_dn + "))"
        res2 = ldb.search(expression="(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + self.base_dn + "))")
        self.assertEquals(len(res2), 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + self.base_dn + "))")

        self.assertEquals(res[0].dn, res2[0].dn)

        if gc_ldb is not None:
            print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + self.base_dn + ")) in Global Catlog"
            res2gc = gc_ldb.search(expression="(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + self.base_dn + "))")
            self.assertEquals(len(res2gc), 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + self.base_dn + ")) in Global Catlog")

            self.assertEquals(res[0].dn, res2gc[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER))"
        res3 = ldb.search(expression="(&(cn=ldaptestcomputer)(objectCategory=compuTER))")
        self.assertEquals(len(res3), 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER))")

        self.assertEquals(res[0].dn, res3[0].dn)

        if gc_ldb is not None:
            print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog"
            res3gc = gc_ldb.search(expression="(&(cn=ldaptestcomputer)(objectCategory=compuTER))")
            self.assertEquals(len(res3gc), 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog")

            self.assertEquals(res[0].dn, res3gc[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestcomp*r)(objectCategory=compuTER))"
        res4 = ldb.search(expression="(&(cn=ldaptestcomp*r)(objectCategory=compuTER))")
        self.assertEquals(len(res4), 1, "Could not find (&(cn=ldaptestcomp*r)(objectCategory=compuTER))")

        self.assertEquals(res[0].dn, res4[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestcomput*)(objectCategory=compuTER))"
        res5 = ldb.search(expression="(&(cn=ldaptestcomput*)(objectCategory=compuTER))")
        self.assertEquals(len(res5), 1, "Could not find (&(cn=ldaptestcomput*)(objectCategory=compuTER))")

        self.assertEquals(res[0].dn, res5[0].dn)

        print "Testing ldb.search for (&(cn=*daptestcomputer)(objectCategory=compuTER))"
        res6 = ldb.search(expression="(&(cn=*daptestcomputer)(objectCategory=compuTER))")
        self.assertEquals(len(res6), 1, "Could not find (&(cn=*daptestcomputer)(objectCategory=compuTER))")

        self.assertEquals(res[0].dn, res6[0].dn)

        ldb.delete("<GUID=" + ldb.schema_format_value("objectGUID", res[0]["objectGUID"][0]) + ">")

        print "Testing ldb.search for (&(cn=ldaptest2computer)(objectClass=user))"
        res = ldb.search(expression="(&(cn=ldaptest2computer)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptest2computer)(objectClass=user))")

        self.assertEquals(str(res[0].dn), "CN=ldaptest2computer,CN=Computers," + self.base_dn)
        self.assertEquals(str(res[0]["cn"]), "ldaptest2computer")
        self.assertEquals(str(res[0]["name"]), "ldaptest2computer")
        self.assertEquals(list(res[0]["objectClass"]), ["top", "person", "organizationalPerson", "user", "computer"])
        self.assertTrue("objectGUID" in res[0])
        self.assertTrue("whenCreated" in res[0])
        self.assertEquals(res[0]["objectCategory"][0], "CN=Computer,CN=Schema,CN=Configuration," + self.base_dn)
        self.assertEquals(int(res[0]["sAMAccountType"][0]), ATYPE_WORKSTATION_TRUST)
        self.assertEquals(int(res[0]["userAccountControl"][0]), UF_WORKSTATION_TRUST_ACCOUNT)

        ldb.delete("<SID=" + ldb.schema_format_value("objectSID", res[0]["objectSID"][0]) + ">")

        attrs = ["cn", "name", "objectClass", "objectGUID", "objectSID", "whenCreated", "nTSecurityDescriptor", "memberOf", "allowedAttributes", "allowedAttributesEffective"]
        print "Testing ldb.search for (&(cn=ldaptestUSer2)(objectClass=user))"
        res_user = ldb.search(self.base_dn, expression="(&(cn=ldaptestUSer2)(objectClass=user))", scope=SCOPE_SUBTREE, attrs=attrs)
        self.assertEquals(len(res_user), 1, "Could not find (&(cn=ldaptestUSer2)(objectClass=user))")

        self.assertEquals(str(res_user[0].dn), ("CN=ldaptestuser2,CN=Users," + self.base_dn))
        self.assertEquals(str(res_user[0]["cn"]), "ldaptestuser2")
        self.assertEquals(str(res_user[0]["name"]), "ldaptestuser2")
        self.assertEquals(list(res_user[0]["objectClass"]), ["top", "person", "organizationalPerson", "user"])
        self.assertTrue("objectSid" in res_user[0])
        self.assertTrue("objectGUID" in res_user[0])
        self.assertTrue("whenCreated" in res_user[0])
        self.assertTrue("nTSecurityDescriptor" in res_user[0])
        self.assertTrue("allowedAttributes" in res_user[0])
        self.assertTrue("allowedAttributesEffective" in res_user[0])
        self.assertEquals(res_user[0]["memberOf"][0].upper(), ("CN=ldaptestgroup2,CN=Users," + self.base_dn).upper())

        ldaptestuser2_sid = res_user[0]["objectSid"][0]
        ldaptestuser2_guid = res_user[0]["objectGUID"][0]

        attrs = ["cn", "name", "objectClass", "objectGUID", "objectSID", "whenCreated", "nTSecurityDescriptor", "member", "allowedAttributes", "allowedAttributesEffective"]
        print "Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group))"
        res = ldb.search(self.base_dn, expression="(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs)
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestgroup2,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestgroup2")
        self.assertEquals(str(res[0]["name"]), "ldaptestgroup2")
        self.assertEquals(list(res[0]["objectClass"]), ["top", "group"])
        self.assertTrue("objectGUID" in res[0])
        self.assertTrue("objectSid" in res[0])
        self.assertTrue("whenCreated" in res[0])
        self.assertTrue("nTSecurityDescriptor" in res[0])
        self.assertTrue("allowedAttributes" in res[0])
        self.assertTrue("allowedAttributesEffective" in res[0])
        memberUP = []
        for m in res[0]["member"]:
            memberUP.append(m.upper())
        self.assertTrue(("CN=ldaptestuser2,CN=Users," + self.base_dn).upper() in memberUP)

        res = ldb.search(self.base_dn, expression="(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs, controls=["extended_dn:1:1"])
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group))")

        print res[0]["member"]
        memberUP = []
        for m in res[0]["member"]:
            memberUP.append(m.upper())
        print ("<GUID=" + ldb.schema_format_value("objectGUID", ldaptestuser2_guid) + ">;<SID=" + ldb.schema_format_value("objectSid", ldaptestuser2_sid) + ">;CN=ldaptestuser2,CN=Users," + self.base_dn).upper()

        self.assertTrue(("<GUID=" + ldb.schema_format_value("objectGUID", ldaptestuser2_guid) + ">;<SID=" + ldb.schema_format_value("objectSid", ldaptestuser2_sid) + ">;CN=ldaptestuser2,CN=Users," + self.base_dn).upper() in memberUP)

        print "Quicktest for linked attributes"
        ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + self.base_dn + """
changetype: modify
replace: member
member: CN=ldaptestuser2,CN=Users,""" + self.base_dn + """
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + self.base_dn + """
""")

        ldb.modify_ldif("""
dn: <GUID=""" + ldb.schema_format_value("objectGUID", res[0]["objectGUID"][0]) + """>
changetype: modify
replace: member
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + self.base_dn + """
""")

        ldb.modify_ldif("""
dn: <SID=""" + ldb.schema_format_value("objectSid", res[0]["objectSid"][0]) + """>
changetype: modify
delete: member
""")

        ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + self.base_dn + """
changetype: modify
add: member
member: <GUID=""" + ldb.schema_format_value("objectGUID", res[0]["objectGUID"][0]) + """>
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + self.base_dn + """
""")

        ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + self.base_dn + """
changetype: modify
replace: member
""")

        ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + self.base_dn + """
changetype: modify
add: member
member: <SID=""" + ldb.schema_format_value("objectSid", res_user[0]["objectSid"][0]) + """>
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + self.base_dn + """
""")

        ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + self.base_dn + """
changetype: modify
delete: member
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + self.base_dn + """
""")

        res = ldb.search(self.base_dn, expression="(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs)
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestgroup2,CN=Users," + self.base_dn))
        self.assertEquals(res[0]["member"][0], ("CN=ldaptestuser2,CN=Users," + self.base_dn))
        self.assertEquals(len(res[0]["member"]), 1)

        ldb.delete(("CN=ldaptestuser2,CN=Users," + self.base_dn))

        time.sleep(4)

        attrs = ["cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "member"]
        print "Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group)) to check linked delete"
        res = ldb.search(self.base_dn, expression="(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs)
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group)) to check linked delete")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestgroup2,CN=Users," + self.base_dn))
        self.assertTrue("member" not in res[0])

        print "Testing ldb.search for (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))"
# TODO UTF8 users don't seem to work fully anymore
#        res = ldb.search(expression="(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))")
        res = ldb.search(expression="(&(cn=ldaptestutf8user èùéìòà)(objectclass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))")

        self.assertEquals(str(res[0].dn), ("CN=ldaptestutf8user èùéìòà,CN=Users," + self.base_dn))
        self.assertEquals(str(res[0]["cn"]), "ldaptestutf8user èùéìòà")
        self.assertEquals(str(res[0]["name"]), "ldaptestutf8user èùéìòà")
        self.assertEquals(list(res[0]["objectClass"]), ["top", "person", "organizationalPerson", "user"])
        self.assertTrue("objectGUID" in res[0])
        self.assertTrue("whenCreated" in res[0])

        ldb.delete(res[0].dn)

        print "Testing ldb.search for (&(cn=ldaptestutf8user2*)(objectClass=user))"
        res = ldb.search(expression="(&(cn=ldaptestutf8user2*)(objectClass=user))")
        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestutf8user2*)(objectClass=user))")

        ldb.delete(res[0].dn)

        ldb.delete(("CN=ldaptestgroup2,CN=Users," + self.base_dn))

        print "Testing ldb.search for (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))"
# TODO UTF8 users don't seem to work fully anymore
#        res = ldb.search(expression="(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))")
#        self.assertEquals(len(res), 1, "Could not find (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))")

        print "Testing that we can't get at the configuration DN from the main search base"
        res = ldb.search(self.base_dn, expression="objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertEquals(len(res), 0)

        print "Testing that we can get at the configuration DN from the main search base on the LDAP port with the 'phantom root' search_options control"
        res = ldb.search(self.base_dn, expression="objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["search_options:1:2"])
        self.assertTrue(len(res) > 0)

        if gc_ldb is not None:
            print "Testing that we can get at the configuration DN from the main search base on the GC port with the search_options control == 0"

            res = gc_ldb.search(self.base_dn, expression="objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["search_options:1:0"])
            self.assertTrue(len(res) > 0)

            print "Testing that we do find configuration elements in the global catlog"
            res = gc_ldb.search(self.base_dn, expression="objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
            self.assertTrue(len(res) > 0)

            print "Testing that we do find configuration elements and user elements at the same time"
            res = gc_ldb.search(self.base_dn, expression="(|(objectClass=crossRef)(objectClass=person))", scope=SCOPE_SUBTREE, attrs=["cn"])
            self.assertTrue(len(res) > 0)

            print "Testing that we do find configuration elements in the global catlog, with the configuration basedn"
            res = gc_ldb.search(self.configuration_dn, expression="objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
            self.assertTrue(len(res) > 0)

        print "Testing that we can get at the configuration DN on the main LDAP port"
        res = ldb.search(self.configuration_dn, expression="objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertTrue(len(res) > 0)

        print "Testing objectCategory canonacolisation"
        res = ldb.search(self.configuration_dn, expression="objectCategory=ntDsDSA", scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertTrue(len(res) > 0, "Didn't find any records with objectCategory=ntDsDSA")
        self.assertTrue(len(res) != 0)

        res = ldb.search(self.configuration_dn, expression="objectCategory=CN=ntDs-DSA," + self.schema_dn, scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertTrue(len(res) > 0, "Didn't find any records with objectCategory=CN=ntDs-DSA," + self.schema_dn)
        self.assertTrue(len(res) != 0)

        print "Testing objectClass attribute order on "+ self.base_dn
        res = ldb.search(expression="objectClass=domain", base=self.base_dn,
                         scope=SCOPE_BASE, attrs=["objectClass"])
        self.assertEquals(len(res), 1)

        self.assertEquals(list(res[0]["objectClass"]), ["top", "domain", "domainDNS"])

    #  check enumeration

        print "Testing ldb.search for objectCategory=person"
        res = ldb.search(self.base_dn, expression="objectCategory=person", scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertTrue(len(res) > 0)

        print "Testing ldb.search for objectCategory=person with domain scope control"
        res = ldb.search(self.base_dn, expression="objectCategory=person", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["domain_scope:1"])
        self.assertTrue(len(res) > 0)

        print "Testing ldb.search for objectCategory=user"
        res = ldb.search(self.base_dn, expression="objectCategory=user", scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertTrue(len(res) > 0)

        print "Testing ldb.search for objectCategory=user with domain scope control"
        res = ldb.search(self.base_dn, expression="objectCategory=user", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["domain_scope:1"])
        self.assertTrue(len(res) > 0)

        print "Testing ldb.search for objectCategory=group"
        res = ldb.search(self.base_dn, expression="objectCategory=group", scope=SCOPE_SUBTREE, attrs=["cn"])
        self.assertTrue(len(res) > 0)

        print "Testing ldb.search for objectCategory=group with domain scope control"
        res = ldb.search(self.base_dn, expression="objectCategory=group", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["domain_scope:1"])
        self.assertTrue(len(res) > 0)

        print "Testing creating a user with the posixAccount objectClass"
        self.ldb.add_ldif("""dn: cn=posixuser,CN=Users,%s
objectClass: top
objectClass: person
objectClass: posixAccount
objectClass: user
objectClass: organizationalPerson
cn: posixuser
uid: posixuser
sn: posixuser
uidNumber: 10126
gidNumber: 10126
homeDirectory: /home/posixuser
loginShell: /bin/bash
gecos: Posix User;;;
description: A POSIX user"""% (self.base_dn))

        print "Testing removing the posixAccount objectClass from an existing user"
        self.ldb.modify_ldif("""dn: cn=posixuser,CN=Users,%s
changetype: modify
delete: objectClass
objectClass: posixAccount"""% (self.base_dn))

        print "Testing adding the posixAccount objectClass to an existing user"
        self.ldb.modify_ldif("""dn: cn=posixuser,CN=Users,%s
changetype: modify
add: objectClass
objectClass: posixAccount"""% (self.base_dn))

        self.delete_force(self.ldb, "cn=posixuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser2,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser3,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser4,cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser4,cn=ldaptestcontainer2," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestuser5,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestgroup2,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcomputer,cn=computers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptest2computer,cn=computers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcomputer3,cn=computers," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestutf8user èùéìòà,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestutf8user2  èùéìòà,cn=users," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcontainer," + self.base_dn)
        self.delete_force(self.ldb, "cn=ldaptestcontainer2," + self.base_dn)

    def test_security_descriptor_add(self):
        """ Testing ldb.add_ldif() for nTSecurityDescriptor """
        user_name = "testdescriptoruser1"
        user_dn = "CN=%s,CN=Users,%s" % (user_name, self.base_dn)
        #
        # Test add_ldif() with SDDL security descriptor input
        #
        self.delete_force(self.ldb, user_dn)
        try:
            sddl = "O:DUG:DUD:PAI(A;;RPWP;;;AU)S:PAI"
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name + """
nTSecurityDescriptor: """ + sddl)
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack( security.descriptor, desc )
            desc_sddl = desc.as_sddl( self.domain_sid )
            self.assertEqual(desc_sddl, sddl)
        finally:
            self.delete_force(self.ldb, user_dn)
        #
        # Test add_ldif() with BASE64 security descriptor
        #
        try:
            sddl = "O:DUG:DUD:PAI(A;;RPWP;;;AU)S:PAI"
            desc = security.descriptor.from_sddl(sddl, self.domain_sid)
            desc_binary = ndr_pack(desc)
            desc_base64 = base64.b64encode(desc_binary)
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name + """
nTSecurityDescriptor:: """ + desc_base64)
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            self.assertEqual(desc_sddl, sddl)
        finally:
            self.delete_force(self.ldb, user_dn)

    def test_security_descriptor_add_neg(self):
        """Test add_ldif() with BASE64 security descriptor input using WRONG domain SID
            Negative test
        """
        user_name = "testdescriptoruser1"
        user_dn = "CN=%s,CN=Users,%s" % (user_name, self.base_dn)
        self.delete_force(self.ldb, user_dn)
        try:
            sddl = "O:DUG:DUD:PAI(A;;RPWP;;;AU)S:PAI"
            desc = security.descriptor.from_sddl(sddl, security.dom_sid('S-1-5-21'))
            desc_base64 = base64.b64encode( ndr_pack(desc) )
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name + """
nTSecurityDescriptor:: """ + desc_base64)
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            self.assertTrue("nTSecurityDescriptor" in res[0])
        finally:
            self.delete_force(self.ldb, user_dn)

    def test_security_descriptor_modify(self):
        """ Testing ldb.modify_ldif() for nTSecurityDescriptor """
        user_name = "testdescriptoruser2"
        user_dn = "CN=%s,CN=Users,%s" % (user_name, self.base_dn)
        #
        # Delete user object and test modify_ldif() with SDDL security descriptor input
        # Add ACE to the original descriptor test
        #
        try:
            self.delete_force(self.ldb, user_dn)
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name)
            # Modify descriptor
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            sddl = desc_sddl[:desc_sddl.find("(")] + "(A;;RPWP;;;AU)" + desc_sddl[desc_sddl.find("("):]
            mod = """
dn: """ + user_dn + """
changetype: modify
replace: nTSecurityDescriptor
nTSecurityDescriptor: """ + sddl
            self.ldb.modify_ldif(mod)
            # Read modified descriptor
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            self.assertEqual(desc_sddl, sddl)
        finally:
            self.delete_force(self.ldb, user_dn)
        #
        # Test modify_ldif() with SDDL security descriptor input
        # New desctiptor test
        #
        try:
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name)
            # Modify descriptor
            sddl = "O:DUG:DUD:PAI(A;;RPWP;;;AU)S:PAI"
            mod = """
dn: """ + user_dn + """
changetype: modify
replace: nTSecurityDescriptor
nTSecurityDescriptor: """ + sddl
            self.ldb.modify_ldif(mod)
            # Read modified descriptor
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            self.assertEqual(desc_sddl, sddl)
        finally:
            self.delete_force(self.ldb, user_dn)
        #
        # Test modify_ldif() with BASE64 security descriptor input
        # Add ACE to the original descriptor test
        #
        try:
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name)
            # Modify descriptor
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            sddl = desc_sddl[:desc_sddl.find("(")] + "(A;;RPWP;;;AU)" + desc_sddl[desc_sddl.find("("):]
            desc = security.descriptor.from_sddl(sddl, self.domain_sid)
            desc_base64 = base64.b64encode(ndr_pack(desc))
            mod = """
dn: """ + user_dn + """
changetype: modify
replace: nTSecurityDescriptor
nTSecurityDescriptor:: """ + desc_base64
            self.ldb.modify_ldif(mod)
            # Read modified descriptor
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            self.assertEqual(desc_sddl, sddl)
        finally:
            self.delete_force(self.ldb, user_dn)
        #
        # Test modify_ldif() with BASE64 security descriptor input
        # New descriptor test
        #
        try:
            self.delete_force(self.ldb, user_dn)
            self.ldb.add_ldif("""
dn: """ + user_dn + """
objectclass: user
sAMAccountName: """ + user_name)
            # Modify descriptor
            sddl = "O:DUG:DUD:PAI(A;;RPWP;;;AU)S:PAI"
            desc = security.descriptor.from_sddl(sddl, self.domain_sid)
            desc_base64 = base64.b64encode(ndr_pack(desc))
            mod = """
dn: """ + user_dn + """
changetype: modify
replace: nTSecurityDescriptor
nTSecurityDescriptor:: """ + desc_base64
            self.ldb.modify_ldif(mod)
            # Read modified descriptor
            res = self.ldb.search(base=user_dn, attrs=["nTSecurityDescriptor"])
            desc = res[0]["nTSecurityDescriptor"][0]
            desc = ndr_unpack(security.descriptor, desc)
            desc_sddl = desc.as_sddl(self.domain_sid)
            self.assertEqual(desc_sddl, sddl)
        finally:
            self.delete_force(self.ldb, user_dn)


class BaseDnTests(unittest.TestCase):

    def setUp(self):
        super(BaseDnTests, self).setUp()
        self.ldb = ldb

    def test_rootdse_attrs(self):
        """Testing for all rootDSE attributes"""
        res = self.ldb.search(scope=SCOPE_BASE, attrs=[])
        self.assertEquals(len(res), 1)

    def test_highestcommittedusn(self):
        """Testing for highestCommittedUSN"""
        res = self.ldb.search("", scope=SCOPE_BASE, attrs=["highestCommittedUSN"])
        self.assertEquals(len(res), 1)
        self.assertTrue(int(res[0]["highestCommittedUSN"][0]) != 0)

    def test_netlogon(self):
        """Testing for netlogon via LDAP"""
        res = self.ldb.search("", scope=SCOPE_BASE, attrs=["netlogon"])
        self.assertEquals(len(res), 0)

    def test_netlogon_highestcommitted_usn(self):
        """Testing for netlogon and highestCommittedUSN via LDAP"""
        res = self.ldb.search("", scope=SCOPE_BASE,
                attrs=["netlogon", "highestCommittedUSN"])
        self.assertEquals(len(res), 0)

    def test_namingContexts(self):
        """Testing for namingContexts in rootDSE"""
        res = self.ldb.search("", scope=SCOPE_BASE,
                attrs=["namingContexts", "defaultNamingContext", "schemaNamingContext", "configurationNamingContext"])
        self.assertEquals(len(res), 1)
        
        ncs = set([])
        for nc in res[0]["namingContexts"]:
            self.assertTrue(nc not in ncs)
            ncs.add(nc)

        self.assertTrue(res[0]["defaultNamingContext"][0] in ncs)
        self.assertTrue(res[0]["configurationNamingContext"][0] in ncs)
        self.assertTrue(res[0]["schemaNamingContext"][0] in ncs)


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
if not runner.run(unittest.makeSuite(BaseDnTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(BasicTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
