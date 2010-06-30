#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse
import sys
import os

sys.path.append("bin/python")
import samba
samba.ensure_external_module("subunit", "subunit/python")
samba.ensure_external_module("testtools", "testtools")

import samba.getopt as options

from samba.auth import system_session
from ldb import SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT
from samba import Ldb

from subunit.run import SubunitTestRunner
import unittest

parser = optparse.OptionParser("deletetest.py [options] <host|file>")
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

class BasicDeleteTests(unittest.TestCase):

    def delete_force(self, ldb, dn):
        try:
            ldb.delete(dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

    def GUID_string(self, guid):
        return self.ldb.schema_format_value("objectGUID", guid)

    def find_basedn(self, ldb):
        res = ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["defaultNamingContext"])
        self.assertEquals(len(res), 1)
        return res[0]["defaultNamingContext"][0]

    def setUp(self):
        self.ldb = ldb
        self.base_dn = self.find_basedn(ldb)

    def search_guid(self,guid):
        print "SEARCH by GUID %s" % self.GUID_string(guid)

        expression = "(objectGUID=%s)" % self.GUID_string(guid)
        res = ldb.search(expression=expression,
                         controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        return res[0]

    def search_dn(self,dn):
        print "SEARCH by DN %s" % dn

        res = ldb.search(expression="(objectClass=*)",
                         base=dn,
                         scope=SCOPE_BASE,
                         controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        return res[0]

    def del_attr_values(self, delObj):
        print "Checking attributes for %s" % delObj["dn"]

        self.assertEquals(delObj["isDeleted"][0],"TRUE")
        self.assertTrue(not("objectCategory" in delObj))
        self.assertTrue(not("sAMAccountType" in delObj))

    def preserved_attributes_list(self, liveObj, delObj):
        print "Checking for preserved attributes list"

        preserved_list = ["nTSecurityDescriptor", "attributeID", "attributeSyntax", "dNReferenceUpdate", "dNSHostName",
        "flatName", "governsID", "groupType", "instanceType", "lDAPDisplayName", "legacyExchangeDN",
        "isDeleted", "isRecycled", "lastKnownParent", "msDS-LastKnownRDN", "mS-DS-CreatorSID",
        "mSMQOwnerID", "nCName", "objectClass", "distinguishedName", "objectGUID", "objectSid",
        "oMSyntax", "proxiedObjectName", "name", "replPropertyMetaData", "sAMAccountName",
        "securityIdentifier", "sIDHistory", "subClassOf", "systemFlags", "trustPartner", "trustDirection",
        "trustType", "trustAttributes", "userAccountControl", "uSNChanged", "uSNCreated", "whenCreated"]

        for a in liveObj:
            if a in preserved_list:
                self.assertTrue(a in delObj)

    def check_rdn(self, liveObj, delObj, rdnName):
        print "Checking for correct rDN"
        rdn=liveObj[rdnName][0]
        rdn2=delObj[rdnName][0]
        name2=delObj[rdnName][0]
        guid=liveObj["objectGUID"][0]
        self.assertEquals(rdn2, rdn + "\nDEL:" + self.GUID_string(guid))
        self.assertEquals(name2, rdn + "\nDEL:" + self.GUID_string(guid))

    def delete_deleted(self, ldb, dn):
        print "Testing the deletion of the already deleted dn %s" % dn

        try:
            ldb.delete(dn)
            self.fail()
        except LdbError, (num, _):
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

    def test_all(self):
        """Basic delete tests"""

        print self.base_dn

        dn1="cn=testuser,cn=users," + self.base_dn
        dn2="cn=testuser2,cn=users," + self.base_dn
        grp1="cn=testdelgroup1,cn=users," + self.base_dn

        self.delete_force(self.ldb, dn1)
        self.delete_force(self.ldb, dn2)
        self.delete_force(self.ldb, grp1)

        ldb.add({
            "dn": dn1,
            "objectclass": "user",
            "cn": "testuser",
            "description": "test user description",
            "samaccountname": "testuser"})

        ldb.add({
            "dn": dn2,
            "objectclass": "user",
            "cn": "testuser2",
            "description": "test user 2 description",
            "samaccountname": "testuser2"})

        ldb.add({
            "dn": grp1,
            "objectclass": "group",
            "cn": "testdelgroup1",
            "description": "test group",
            "samaccountname": "testdelgroup1",
            "member": [ dn1, dn2 ] })

        objLive1 = self.search_dn(dn1)
        guid1=objLive1["objectGUID"][0]

        objLive2 = self.search_dn(dn2)
        guid2=objLive2["objectGUID"][0]

        objLive3 = self.search_dn(grp1)
        guid3=objLive3["objectGUID"][0]

        ldb.delete(dn1)
        ldb.delete(dn2)
        ldb.delete(grp1)

        objDeleted1 = self.search_guid(guid1)
        objDeleted2 = self.search_guid(guid2)
        objDeleted3 = self.search_guid(guid3)

        self.del_attr_values(objDeleted1)
        self.del_attr_values(objDeleted2)
        self.del_attr_values(objDeleted3)

        self.preserved_attributes_list(objLive1, objDeleted1)
        self.preserved_attributes_list(objLive2, objDeleted2)

        self.check_rdn(objLive1, objDeleted1, "cn")
        self.check_rdn(objLive2, objDeleted2, "cn")
        self.check_rdn(objLive3, objDeleted3, "cn")

        self.delete_deleted(ldb, dn1)
        self.delete_deleted(ldb, dn2)
        self.delete_deleted(ldb, grp1)

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = Ldb(host, credentials=creds, session_info=system_session(), lp=lp)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(BasicDeleteTests)).wasSuccessful():
    rc = 1

sys.exit(rc)
