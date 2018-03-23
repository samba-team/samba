#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import optparse
import sys
import os

sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

from samba.auth import system_session
from ldb import SCOPE_BASE, LdbError, Message, MessageElement, Dn, FLAG_MOD_ADD, FLAG_MOD_DELETE, FLAG_MOD_REPLACE
from ldb import ERR_NO_SUCH_OBJECT, ERR_NOT_ALLOWED_ON_NON_LEAF, ERR_ENTRY_ALREADY_EXISTS, ERR_ATTRIBUTE_OR_VALUE_EXISTS
from ldb import ERR_UNWILLING_TO_PERFORM, ERR_OPERATIONS_ERROR
from samba.samdb import SamDB
from samba.tests import delete_force

parser = optparse.OptionParser("deletetest.py [options] <host|file>")
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

class BaseDeleteTests(samba.tests.TestCase):

    def GUID_string(self, guid):
        return self.ldb.schema_format_value("objectGUID", guid)

    def setUp(self):
        super(BaseDeleteTests, self).setUp()
        self.ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)

        self.base_dn = self.ldb.domain_dn()
        self.configuration_dn = self.ldb.get_config_basedn().get_linearized()

    def search_guid(self, guid):
        print("SEARCH by GUID %s" % self.GUID_string(guid))

        res = self.ldb.search(base="<GUID=%s>" % self.GUID_string(guid),
                         scope=SCOPE_BASE, controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        return res[0]

    def search_dn(self,dn):
        print("SEARCH by DN %s" % dn)

        res = self.ldb.search(expression="(objectClass=*)",
                         base=dn,
                         scope=SCOPE_BASE,
                         controls=["show_deleted:1"])
        self.assertEquals(len(res), 1)
        return res[0]


class BasicDeleteTests(BaseDeleteTests):

    def setUp(self):
        super(BasicDeleteTests, self).setUp()

    def del_attr_values(self, delObj):
        print("Checking attributes for %s" % delObj["dn"])

        self.assertEquals(delObj["isDeleted"][0],"TRUE")
        self.assertTrue(not("objectCategory" in delObj))
        self.assertTrue(not("sAMAccountType" in delObj))

    def preserved_attributes_list(self, liveObj, delObj):
        print("Checking for preserved attributes list")

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
        print("Checking for correct rDN")
        rdn=liveObj[rdnName][0]
        rdn2=delObj[rdnName][0]
        name2=delObj["name"][0]
        dn_rdn=delObj.dn.get_rdn_value()
        guid=liveObj["objectGUID"][0]
        self.assertEquals(rdn2, rdn + "\nDEL:" + self.GUID_string(guid))
        self.assertEquals(name2, rdn + "\nDEL:" + self.GUID_string(guid))
        self.assertEquals(name2, dn_rdn)

    def delete_deleted(self, ldb, dn):
        print("Testing the deletion of the already deleted dn %s" % dn)

        try:
            ldb.delete(dn)
            self.fail()
        except LdbError as e:
            (num, _) = e.args
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

    def test_delete_protection(self):
        """Delete protection tests"""

        print(self.base_dn)

        delete_force(self.ldb, "cn=entry1,cn=ldaptestcontainer," + self.base_dn)
        delete_force(self.ldb, "cn=entry2,cn=ldaptestcontainer," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestcontainer," + self.base_dn)

        self.ldb.add({
            "dn": "cn=ldaptestcontainer," + self.base_dn,
            "objectclass": "container"})
        self.ldb.add({
            "dn": "cn=entry1,cn=ldaptestcontainer," + self.base_dn,
            "objectclass": "container"})
        self.ldb.add({
            "dn": "cn=entry2,cn=ldaptestcontainer," + self.base_dn,
            "objectclass": "container"})

        try:
            self.ldb.delete("cn=ldaptestcontainer," + self.base_dn)
            self.fail()
        except LdbError as e1:
            (num, _) = e1.args
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        self.ldb.delete("cn=ldaptestcontainer," + self.base_dn, ["tree_delete:1"])

        try:
            res = self.ldb.search("cn=ldaptestcontainer," + self.base_dn,
                             scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError as e2:
            (num, _) = e2.args
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)
        try:
            res = self.ldb.search("cn=entry1,cn=ldaptestcontainer," + self.base_dn,
                             scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)
        try:
            res = self.ldb.search("cn=entry2,cn=ldaptestcontainer," + self.base_dn,
                             scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError as e4:
            (num, _) = e4.args
            self.assertEquals(num, ERR_NO_SUCH_OBJECT)

        delete_force(self.ldb, "cn=entry1,cn=ldaptestcontainer," + self.base_dn)
        delete_force(self.ldb, "cn=entry2,cn=ldaptestcontainer," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestcontainer," + self.base_dn)

        # Performs some protected object delete testing

        res = self.ldb.search(base="", expression="", scope=SCOPE_BASE,
                         attrs=["dsServiceName", "dNSHostName"])
        self.assertEquals(len(res), 1)

        # Delete failing since DC's nTDSDSA object is protected
        try:
            self.ldb.delete(res[0]["dsServiceName"][0])
            self.fail()
        except LdbError as e5:
            (num, _) = e5.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        res = self.ldb.search(self.base_dn, attrs=["rIDSetReferences"],
                         expression="(&(objectClass=computer)(dNSHostName=" + res[0]["dNSHostName"][0] + "))")
        self.assertEquals(len(res), 1)

        # Deletes failing since DC's rIDSet object is protected
        try:
            self.ldb.delete(res[0]["rIDSetReferences"][0])
            self.fail()
        except LdbError as e6:
            (num, _) = e6.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)
        try:
            self.ldb.delete(res[0]["rIDSetReferences"][0], ["tree_delete:1"])
            self.fail()
        except LdbError as e7:
            (num, _) = e7.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        # Deletes failing since three main crossRef objects are protected

        try:
            self.ldb.delete("cn=Enterprise Schema,cn=Partitions," + self.configuration_dn)
            self.fail()
        except LdbError as e8:
            (num, _) = e8.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)
        try:
            self.ldb.delete("cn=Enterprise Schema,cn=Partitions," + self.configuration_dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e9:
            (num, _) = e9.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb.delete("cn=Enterprise Configuration,cn=Partitions," + self.configuration_dn)
            self.fail()
        except LdbError as e10:
            (num, _) = e10.args
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)
        try:
            self.ldb.delete("cn=Enterprise Configuration,cn=Partitions," + self.configuration_dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e11:
            (num, _) = e11.args
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        res = self.ldb.search("cn=Partitions," + self.configuration_dn, attrs=[],
                         expression="(nCName=%s)" % self.base_dn)
        self.assertEquals(len(res), 1)

        try:
            self.ldb.delete(res[0].dn)
            self.fail()
        except LdbError as e12:
            (num, _) = e12.args
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)
        try:
            self.ldb.delete(res[0].dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e13:
            (num, _) = e13.args
            self.assertEquals(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        # Delete failing since "SYSTEM_FLAG_DISALLOW_DELETE"
        try:
            self.ldb.delete("CN=Users," + self.base_dn)
            self.fail()
        except LdbError as e14:
            (num, _) = e14.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

        # Tree-delete failing since "isCriticalSystemObject"
        try:
            self.ldb.delete("CN=Computers," + self.base_dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e15:
            (num, _) = e15.args
            self.assertEquals(num, ERR_UNWILLING_TO_PERFORM)

    def test_all(self):
        """Basic delete tests"""

        print(self.base_dn)

        # user current time in ms to make unique objects
        import time
        marker = str(int(round(time.time()*1000)))
        usr1_name = "u_" + marker
        usr2_name = "u2_" + marker
        grp_name = "g1_" + marker
        site_name = "s1_" + marker

        usr1 = "cn=%s,cn=users,%s" % (usr1_name, self.base_dn)
        usr2 = "cn=%s,cn=users,%s" % (usr2_name, self.base_dn)
        grp1 = "cn=%s,cn=users,%s" % (grp_name, self.base_dn)
        sit1 = "cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)
        ss1 = "cn=NTDS Site Settings,cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)
        srv1 = "cn=Servers,cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)
        srv2 = "cn=TESTSRV,cn=Servers,cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)

        delete_force(self.ldb, usr1)
        delete_force(self.ldb, usr2)
        delete_force(self.ldb, grp1)
        delete_force(self.ldb, ss1)
        delete_force(self.ldb, srv2)
        delete_force(self.ldb, srv1)
        delete_force(self.ldb, sit1)

        self.ldb.add({
            "dn": usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": usr1_name})

        self.ldb.add({
            "dn": usr2,
            "objectclass": "user",
            "description": "test user 2 description",
            "samaccountname": usr2_name})

        self.ldb.add({
            "dn": grp1,
            "objectclass": "group",
            "description": "test group",
            "samaccountname": grp_name,
            "member": [ usr1, usr2 ],
            "isDeleted": "FALSE" })

        self.ldb.add({
            "dn": sit1,
            "objectclass": "site" })

        self.ldb.add({
            "dn": ss1,
            "objectclass": ["applicationSiteSettings", "nTDSSiteSettings"] })

        self.ldb.add({
            "dn": srv1,
            "objectclass": "serversContainer" })

        self.ldb.add({
            "dn": srv2,
            "objectClass": "server" })

        objLive1 = self.search_dn(usr1)
        guid1=objLive1["objectGUID"][0]

        objLive2 = self.search_dn(usr2)
        guid2=objLive2["objectGUID"][0]

        objLive3 = self.search_dn(grp1)
        guid3=objLive3["objectGUID"][0]

        objLive4 = self.search_dn(sit1)
        guid4=objLive4["objectGUID"][0]

        objLive5 = self.search_dn(ss1)
        guid5=objLive5["objectGUID"][0]

        objLive6 = self.search_dn(srv1)
        guid6=objLive6["objectGUID"][0]

        objLive7 = self.search_dn(srv2)
        guid7=objLive7["objectGUID"][0]

        self.ldb.delete(usr1)
        self.ldb.delete(usr2)
        self.ldb.delete(grp1)
        self.ldb.delete(srv1, ["tree_delete:1"])
        self.ldb.delete(sit1, ["tree_delete:1"])

        objDeleted1 = self.search_guid(guid1)
        objDeleted2 = self.search_guid(guid2)
        objDeleted3 = self.search_guid(guid3)
        objDeleted4 = self.search_guid(guid4)
        objDeleted5 = self.search_guid(guid5)
        objDeleted6 = self.search_guid(guid6)
        objDeleted7 = self.search_guid(guid7)

        self.del_attr_values(objDeleted1)
        self.del_attr_values(objDeleted2)
        self.del_attr_values(objDeleted3)
        self.del_attr_values(objDeleted4)
        self.del_attr_values(objDeleted5)
        self.del_attr_values(objDeleted6)
        self.del_attr_values(objDeleted7)

        self.preserved_attributes_list(objLive1, objDeleted1)
        self.preserved_attributes_list(objLive2, objDeleted2)
        self.preserved_attributes_list(objLive3, objDeleted3)
        self.preserved_attributes_list(objLive4, objDeleted4)
        self.preserved_attributes_list(objLive5, objDeleted5)
        self.preserved_attributes_list(objLive6, objDeleted6)
        self.preserved_attributes_list(objLive7, objDeleted7)

        self.check_rdn(objLive1, objDeleted1, "cn")
        self.check_rdn(objLive2, objDeleted2, "cn")
        self.check_rdn(objLive3, objDeleted3, "cn")
        self.check_rdn(objLive4, objDeleted4, "cn")
        self.check_rdn(objLive5, objDeleted5, "cn")
        self.check_rdn(objLive6, objDeleted6, "cn")
        self.check_rdn(objLive7, objDeleted7, "cn")

        self.delete_deleted(self.ldb, usr1)
        self.delete_deleted(self.ldb, usr2)
        self.delete_deleted(self.ldb, grp1)
        self.delete_deleted(self.ldb, sit1)
        self.delete_deleted(self.ldb, ss1)
        self.delete_deleted(self.ldb, srv1)
        self.delete_deleted(self.ldb, srv2)

        self.assertTrue("CN=Deleted Objects" in str(objDeleted1.dn))
        self.assertTrue("CN=Deleted Objects" in str(objDeleted2.dn))
        self.assertTrue("CN=Deleted Objects" in str(objDeleted3.dn))
        self.assertFalse("CN=Deleted Objects" in str(objDeleted4.dn))
        self.assertTrue("CN=Deleted Objects" in str(objDeleted5.dn))
        self.assertFalse("CN=Deleted Objects" in str(objDeleted6.dn))
        self.assertFalse("CN=Deleted Objects" in str(objDeleted7.dn))


if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)
