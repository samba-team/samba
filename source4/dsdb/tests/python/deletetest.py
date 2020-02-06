#!/usr/bin/env python3
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
from samba import dsdb
from samba.compat import get_string

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
        return get_string(self.ldb.schema_format_value("objectGUID", guid))

    def setUp(self):
        super(BaseDeleteTests, self).setUp()
        self.ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)

        self.base_dn = self.ldb.domain_dn()
        self.configuration_dn = self.ldb.get_config_basedn().get_linearized()

    def search_guid(self, guid):
        print("SEARCH by GUID %s" % self.GUID_string(guid))

        res = self.ldb.search(base="<GUID=%s>" % self.GUID_string(guid),
                              scope=SCOPE_BASE,
                              controls=["show_deleted:1"],
                              attrs=["*", "parentGUID"])
        self.assertEqual(len(res), 1)
        return res[0]

    def search_dn(self, dn):
        print("SEARCH by DN %s" % dn)

        res = self.ldb.search(expression="(objectClass=*)",
                              base=dn,
                              scope=SCOPE_BASE,
                              controls=["show_deleted:1"],
                              attrs=["*", "parentGUID"])
        self.assertEqual(len(res), 1)
        return res[0]


class BasicDeleteTests(BaseDeleteTests):

    def setUp(self):
        super(BasicDeleteTests, self).setUp()

    def del_attr_values(self, delObj):
        print("Checking attributes for %s" % delObj["dn"])

        self.assertEqual(str(delObj["isDeleted"][0]), "TRUE")
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
        rdn = liveObj[rdnName][0]
        rdn2 = delObj[rdnName][0]
        name2 = delObj["name"][0]
        dn_rdn = delObj.dn.get_rdn_value()
        guid = liveObj["objectGUID"][0]
        self.assertEqual(str(rdn2), ("%s\nDEL:%s" % (rdn, self.GUID_string(guid))))
        self.assertEqual(str(name2), ("%s\nDEL:%s" % (rdn, self.GUID_string(guid))))
        self.assertEqual(str(name2), dn_rdn)

    def delete_deleted(self, ldb, dn):
        print("Testing the deletion of the already deleted dn %s" % dn)

        try:
            ldb.delete(dn)
            self.fail()
        except LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

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
            self.assertEqual(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        self.ldb.delete("cn=ldaptestcontainer," + self.base_dn, ["tree_delete:1"])

        try:
            res = self.ldb.search("cn=ldaptestcontainer," + self.base_dn,
                                  scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError as e2:
            (num, _) = e2.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)
        try:
            res = self.ldb.search("cn=entry1,cn=ldaptestcontainer," + self.base_dn,
                                  scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)
        try:
            res = self.ldb.search("cn=entry2,cn=ldaptestcontainer," + self.base_dn,
                                  scope=SCOPE_BASE, attrs=[])
            self.fail()
        except LdbError as e4:
            (num, _) = e4.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

        delete_force(self.ldb, "cn=entry1,cn=ldaptestcontainer," + self.base_dn)
        delete_force(self.ldb, "cn=entry2,cn=ldaptestcontainer," + self.base_dn)
        delete_force(self.ldb, "cn=ldaptestcontainer," + self.base_dn)

        # Performs some protected object delete testing

        res = self.ldb.search(base="", expression="", scope=SCOPE_BASE,
                              attrs=["dsServiceName", "dNSHostName"])
        self.assertEqual(len(res), 1)

        # Delete failing since DC's nTDSDSA object is protected
        try:
            self.ldb.delete(res[0]["dsServiceName"][0])
            self.fail()
        except LdbError as e5:
            (num, _) = e5.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        res = self.ldb.search(self.base_dn, attrs=["rIDSetReferences"],
                              expression="(&(objectClass=computer)(dNSHostName=" + str(res[0]["dNSHostName"][0]) + "))")
        self.assertEqual(len(res), 1)

        # Deletes failing since DC's rIDSet object is protected
        try:
            self.ldb.delete(res[0]["rIDSetReferences"][0])
            self.fail()
        except LdbError as e6:
            (num, _) = e6.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        try:
            self.ldb.delete(res[0]["rIDSetReferences"][0], ["tree_delete:1"])
            self.fail()
        except LdbError as e7:
            (num, _) = e7.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Deletes failing since three main crossRef objects are protected

        try:
            self.ldb.delete("cn=Enterprise Schema,cn=Partitions," + self.configuration_dn)
            self.fail()
        except LdbError as e8:
            (num, _) = e8.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        try:
            self.ldb.delete("cn=Enterprise Schema,cn=Partitions," + self.configuration_dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e9:
            (num, _) = e9.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        try:
            self.ldb.delete("cn=Enterprise Configuration,cn=Partitions," + self.configuration_dn)
            self.fail()
        except LdbError as e10:
            (num, _) = e10.args
            self.assertEqual(num, ERR_NOT_ALLOWED_ON_NON_LEAF)
        try:
            self.ldb.delete("cn=Enterprise Configuration,cn=Partitions," + self.configuration_dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e11:
            (num, _) = e11.args
            self.assertEqual(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        res = self.ldb.search("cn=Partitions," + self.configuration_dn, attrs=[],
                              expression="(nCName=%s)" % self.base_dn)
        self.assertEqual(len(res), 1)

        try:
            self.ldb.delete(res[0].dn)
            self.fail()
        except LdbError as e12:
            (num, _) = e12.args
            self.assertEqual(num, ERR_NOT_ALLOWED_ON_NON_LEAF)
        try:
            self.ldb.delete(res[0].dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e13:
            (num, _) = e13.args
            self.assertEqual(num, ERR_NOT_ALLOWED_ON_NON_LEAF)

        # Delete failing since "SYSTEM_FLAG_DISALLOW_DELETE"
        try:
            self.ldb.delete("CN=Users," + self.base_dn)
            self.fail()
        except LdbError as e14:
            (num, _) = e14.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)

        # Tree-delete failing since "isCriticalSystemObject"
        try:
            self.ldb.delete("CN=Computers," + self.base_dn, ["tree_delete:1"])
            self.fail()
        except LdbError as e15:
            (num, _) = e15.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)


class BasicTreeDeleteTests(BasicDeleteTests):

    def setUp(self):
        super(BasicTreeDeleteTests, self).setUp()

        # user current time in ms to make unique objects
        import time
        marker = str(int(round(time.time() * 1000)))
        usr1_name = "u_" + marker
        usr2_name = "u2_" + marker
        grp_name = "g1_" + marker
        site_name = "s1_" + marker

        self.usr1 = "cn=%s,cn=users,%s" % (usr1_name, self.base_dn)
        self.usr2 = "cn=%s,cn=users,%s" % (usr2_name, self.base_dn)
        self.grp1 = "cn=%s,cn=users,%s" % (grp_name, self.base_dn)
        self.sit1 = "cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)
        self.ss1 = "cn=NTDS Site Settings,cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)
        self.srv1 = "cn=Servers,cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)
        self.srv2 = "cn=TESTSRV,cn=Servers,cn=%s,cn=sites,%s" % (site_name, self.configuration_dn)

        delete_force(self.ldb, self.usr1)
        delete_force(self.ldb, self.usr2)
        delete_force(self.ldb, self.grp1)
        delete_force(self.ldb, self.ss1)
        delete_force(self.ldb, self.srv2)
        delete_force(self.ldb, self.srv1)
        delete_force(self.ldb, self.sit1)

        self.ldb.add({
            "dn": self.usr1,
            "objectclass": "user",
            "description": "test user description",
            "samaccountname": usr1_name})

        self.ldb.add({
            "dn": self.usr2,
            "objectclass": "user",
            "description": "test user 2 description",
            "samaccountname": usr2_name})

        self.ldb.add({
            "dn": self.grp1,
            "objectclass": "group",
            "description": "test group",
            "samaccountname": grp_name,
            "member": [self.usr1, self.usr2],
            "isDeleted": "FALSE"})

        self.ldb.add({
            "dn": self.sit1,
            "objectclass": "site"})

        self.ldb.add({
            "dn": self.ss1,
            "objectclass": ["applicationSiteSettings", "nTDSSiteSettings"]})

        self.ldb.add({
            "dn": self.srv1,
            "objectclass": "serversContainer"})

        self.ldb.add({
            "dn": self.srv2,
            "objectClass": "server"})

        self.objLive1 = self.search_dn(self.usr1)
        self.guid1 = self.objLive1["objectGUID"][0]

        self.objLive2 = self.search_dn(self.usr2)
        self.guid2 = self.objLive2["objectGUID"][0]

        self.objLive3 = self.search_dn(self.grp1)
        self.guid3 = self.objLive3["objectGUID"][0]

        self.objLive4 = self.search_dn(self.sit1)
        self.guid4 = self.objLive4["objectGUID"][0]

        self.objLive5 = self.search_dn(self.ss1)
        self.guid5 = self.objLive5["objectGUID"][0]

        self.objLive6 = self.search_dn(self.srv1)
        self.guid6 = self.objLive6["objectGUID"][0]

        self.objLive7 = self.search_dn(self.srv2)
        self.guid7 = self.objLive7["objectGUID"][0]

        self.deleted_objects_config_dn \
            = self.ldb.get_wellknown_dn(self.ldb.get_config_basedn(),
                                        dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER)
        deleted_objects_config_obj \
            = self.search_dn(self.deleted_objects_config_dn)

        self.deleted_objects_config_guid \
            = deleted_objects_config_obj["objectGUID"][0]

        self.deleted_objects_domain_dn \
            = self.ldb.get_wellknown_dn(self.ldb.get_default_basedn(),
                                        dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER)
        deleted_objects_domain_obj \
            = self.search_dn(self.deleted_objects_domain_dn)

        self.deleted_objects_domain_guid \
            = deleted_objects_domain_obj["objectGUID"][0]

        self.deleted_objects_domain_dn \
            = self.ldb.get_wellknown_dn(self.ldb.get_default_basedn(),
                                        dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER)
        sites_obj = self.search_dn("cn=sites,%s"
                                   % self.ldb.get_config_basedn())
        self.sites_dn = sites_obj.dn
        self.sites_guid \
            = sites_obj["objectGUID"][0]

    def test_all(self):
        """Basic delete tests"""

        self.ldb.delete(self.usr1)
        self.ldb.delete(self.usr2)
        self.ldb.delete(self.grp1)
        self.ldb.delete(self.srv1, ["tree_delete:1"])
        self.ldb.delete(self.sit1, ["tree_delete:1"])

        self.check_all()

    def test_tree_delete(self):
        """Basic delete tests,
           but use just one tree delete for the config records
        """

        self.ldb.delete(self.usr1)
        self.ldb.delete(self.usr2)
        self.ldb.delete(self.grp1)
        self.ldb.delete(self.sit1, ["tree_delete:1"])

        self.check_all()

    def check_all(self):
        objDeleted1 = self.search_guid(self.guid1)
        objDeleted2 = self.search_guid(self.guid2)
        objDeleted3 = self.search_guid(self.guid3)
        objDeleted4 = self.search_guid(self.guid4)
        objDeleted5 = self.search_guid(self.guid5)
        objDeleted6 = self.search_guid(self.guid6)
        objDeleted7 = self.search_guid(self.guid7)

        self.del_attr_values(objDeleted1)
        self.del_attr_values(objDeleted2)
        self.del_attr_values(objDeleted3)
        self.del_attr_values(objDeleted4)
        self.del_attr_values(objDeleted5)
        self.del_attr_values(objDeleted6)
        self.del_attr_values(objDeleted7)

        self.preserved_attributes_list(self.objLive1, objDeleted1)
        self.preserved_attributes_list(self.objLive2, objDeleted2)
        self.preserved_attributes_list(self.objLive3, objDeleted3)
        self.preserved_attributes_list(self.objLive4, objDeleted4)
        self.preserved_attributes_list(self.objLive5, objDeleted5)
        self.preserved_attributes_list(self.objLive6, objDeleted6)
        self.preserved_attributes_list(self.objLive7, objDeleted7)

        self.check_rdn(self.objLive1, objDeleted1, "cn")
        self.check_rdn(self.objLive2, objDeleted2, "cn")
        self.check_rdn(self.objLive3, objDeleted3, "cn")
        self.check_rdn(self.objLive4, objDeleted4, "cn")
        self.check_rdn(self.objLive5, objDeleted5, "cn")
        self.check_rdn(self.objLive6, objDeleted6, "cn")
        self.check_rdn(self.objLive7, objDeleted7, "cn")

        self.delete_deleted(self.ldb, self.usr1)
        self.delete_deleted(self.ldb, self.usr2)
        self.delete_deleted(self.ldb, self.grp1)
        self.delete_deleted(self.ldb, self.sit1)
        self.delete_deleted(self.ldb, self.ss1)
        self.delete_deleted(self.ldb, self.srv1)
        self.delete_deleted(self.ldb, self.srv2)

        self.assertTrue("CN=Deleted Objects" in str(objDeleted1.dn))
        self.assertEqual(objDeleted1.dn.parent(),
                         self.deleted_objects_domain_dn)
        self.assertEqual(objDeleted1["parentGUID"][0],
                         self.deleted_objects_domain_guid)

        self.assertTrue("CN=Deleted Objects" in str(objDeleted2.dn))
        self.assertEqual(objDeleted2.dn.parent(),
                         self.deleted_objects_domain_dn)
        self.assertEqual(objDeleted2["parentGUID"][0],
                         self.deleted_objects_domain_guid)

        self.assertTrue("CN=Deleted Objects" in str(objDeleted3.dn))
        self.assertEqual(objDeleted3.dn.parent(),
                         self.deleted_objects_domain_dn)
        self.assertEqual(objDeleted3["parentGUID"][0],
                         self.deleted_objects_domain_guid)

        self.assertFalse("CN=Deleted Objects" in str(objDeleted4.dn))
        self.assertEqual(objDeleted4.dn.parent(),
                         self.sites_dn)
        self.assertEqual(objDeleted4["parentGUID"][0],
                         self.sites_guid)

        self.assertTrue("CN=Deleted Objects" in str(objDeleted5.dn))
        self.assertEqual(objDeleted5.dn.parent(),
                         self.deleted_objects_config_dn)
        self.assertEqual(objDeleted5["parentGUID"][0],
                         self.deleted_objects_config_guid)

        self.assertFalse("CN=Deleted Objects" in str(objDeleted6.dn))
        self.assertEqual(objDeleted6.dn.parent(),
                         objDeleted4.dn)
        self.assertEqual(objDeleted6["parentGUID"][0],
                         objDeleted4["objectGUID"][0])

        self.assertFalse("CN=Deleted Objects" in str(objDeleted7.dn))
        self.assertEqual(objDeleted7.dn.parent(),
                         objDeleted6.dn)
        self.assertEqual(objDeleted7["parentGUID"][0],
                         objDeleted6["objectGUID"][0])

        objDeleted1 = self.search_guid(self.guid1)
        objDeleted2 = self.search_guid(self.guid2)
        objDeleted3 = self.search_guid(self.guid3)
        objDeleted4 = self.search_guid(self.guid4)
        objDeleted5 = self.search_guid(self.guid5)
        objDeleted6 = self.search_guid(self.guid6)
        objDeleted7 = self.search_guid(self.guid7)

        self.del_attr_values(objDeleted1)
        self.del_attr_values(objDeleted2)
        self.del_attr_values(objDeleted3)
        self.del_attr_values(objDeleted4)
        self.del_attr_values(objDeleted5)
        self.del_attr_values(objDeleted6)
        self.del_attr_values(objDeleted7)

        self.preserved_attributes_list(self.objLive1, objDeleted1)
        self.preserved_attributes_list(self.objLive2, objDeleted2)
        self.preserved_attributes_list(self.objLive3, objDeleted3)
        self.preserved_attributes_list(self.objLive4, objDeleted4)
        self.preserved_attributes_list(self.objLive5, objDeleted5)
        self.preserved_attributes_list(self.objLive6, objDeleted6)
        self.preserved_attributes_list(self.objLive7, objDeleted7)

        self.check_rdn(self.objLive1, objDeleted1, "cn")
        self.check_rdn(self.objLive2, objDeleted2, "cn")
        self.check_rdn(self.objLive3, objDeleted3, "cn")
        self.check_rdn(self.objLive4, objDeleted4, "cn")
        self.check_rdn(self.objLive5, objDeleted5, "cn")
        self.check_rdn(self.objLive6, objDeleted6, "cn")
        self.check_rdn(self.objLive7, objDeleted7, "cn")

        self.delete_deleted(self.ldb, self.usr1)
        self.delete_deleted(self.ldb, self.usr2)
        self.delete_deleted(self.ldb, self.grp1)
        self.delete_deleted(self.ldb, self.sit1)
        self.delete_deleted(self.ldb, self.ss1)
        self.delete_deleted(self.ldb, self.srv1)
        self.delete_deleted(self.ldb, self.srv2)

        self.assertTrue("CN=Deleted Objects" in str(objDeleted1.dn))
        self.assertEqual(objDeleted1.dn.parent(),
                         self.deleted_objects_domain_dn)
        self.assertEqual(objDeleted1["parentGUID"][0],
                         self.deleted_objects_domain_guid)
        self.assertTrue("CN=Deleted Objects" in str(objDeleted2.dn))
        self.assertEqual(objDeleted2.dn.parent(),
                         self.deleted_objects_domain_dn)
        self.assertEqual(objDeleted2["parentGUID"][0],
                         self.deleted_objects_domain_guid)
        self.assertTrue("CN=Deleted Objects" in str(objDeleted3.dn))
        self.assertEqual(objDeleted3.dn.parent(),
                         self.deleted_objects_domain_dn)
        self.assertEqual(objDeleted3["parentGUID"][0],
                         self.deleted_objects_domain_guid)
        self.assertFalse("CN=Deleted Objects" in str(objDeleted4.dn))
        self.assertTrue("CN=Deleted Objects" in str(objDeleted5.dn))
        self.assertEqual(objDeleted5.dn.parent(),
                         self.deleted_objects_config_dn)
        self.assertEqual(objDeleted5["parentGUID"][0],
                         self.deleted_objects_config_guid)
        self.assertFalse("CN=Deleted Objects" in str(objDeleted6.dn))
        self.assertFalse("CN=Deleted Objects" in str(objDeleted7.dn))


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)
