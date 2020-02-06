#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
import optparse
import sys
sys.path.insert(0, "bin/python")
import samba
from samba.tests.subunitrun import TestProgram, SubunitOptions

from ldb import (LdbError, ERR_NO_SUCH_OBJECT, Message,
                 MessageElement, Dn, FLAG_MOD_REPLACE)
import samba.tests
import samba.dsdb as dsdb
import samba.getopt as options
import random

parser = optparse.OptionParser("urgent_replication.py [options] <host>")
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


class UrgentReplicationTests(samba.tests.TestCase):

    def delete_force(self, ldb, dn):
        try:
            ldb.delete(dn, ["relax:0"])
        except LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)

    def setUp(self):
        super(UrgentReplicationTests, self).setUp()
        self.ldb = samba.tests.connect_samdb(host, global_schema=False)
        self.base_dn = self.ldb.domain_dn()

        print("baseDN: %s\n" % self.base_dn)

    def test_nonurgent_object(self):
        """Test if the urgent replication is not activated when handling a non urgent object."""
        self.ldb.add({
            "dn": "cn=nonurgenttest,cn=users," + self.base_dn,
            "objectclass": "user",
            "samaccountname": "nonurgenttest",
            "description": "nonurgenttest description"})

        # urgent replication should not be enabled when creating
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should not be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "cn=nonurgenttest,cn=users," + self.base_dn)
        m["description"] = MessageElement("new description", FLAG_MOD_REPLACE,
                                          "description")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should not be enabled when deleting
        self.delete_force(self.ldb, "cn=nonurgenttest,cn=users," + self.base_dn)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

    def test_nTDSDSA_object(self):
        """Test if the urgent replication is activated when handling a nTDSDSA object."""
        self.ldb.add({
            "dn": "cn=test server,cn=Servers,cn=Default-First-Site-Name,cn=Sites,%s" %
            self.ldb.get_config_basedn(),
            "objectclass": "server",
            "cn": "test server",
            "name": "test server",
            "systemFlags": "50000000"}, ["relax:0"])

        self.ldb.add_ldif(
            """dn: cn=NTDS Settings test,cn=test server,cn=Servers,cn=Default-First-Site-Name,cn=Sites,cn=Configuration,%s""" % (self.base_dn) + """
objectclass: nTDSDSA
cn: NTDS Settings test
options: 1
instanceType: 4
systemFlags: 33554432""", ["relax:0"])

        # urgent replication should be enabled when creation
        res = self.ldb.load_partition_usn("cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should NOT be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "cn=NTDS Settings test,cn=test server,cn=Servers,cn=Default-First-Site-Name,cn=Sites,cn=Configuration," + self.base_dn)
        m["options"] = MessageElement("0", FLAG_MOD_REPLACE,
                                      "options")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn("cn=Configuration," + self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when deleting
        self.delete_force(self.ldb, "cn=NTDS Settings test,cn=test server,cn=Servers,cn=Default-First-Site-Name,cn=Sites,cn=Configuration," + self.base_dn)
        res = self.ldb.load_partition_usn("cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        self.delete_force(self.ldb, "cn=test server,cn=Servers,cn=Default-First-Site-Name,cn=Sites,cn=Configuration," + self.base_dn)

    def test_crossRef_object(self):
        """Test if the urgent replication is activated when handling a crossRef object."""
        self.ldb.add({
            "dn": "CN=test crossRef,CN=Partitions,CN=Configuration," + self.base_dn,
            "objectClass": "crossRef",
            "cn": "test crossRef",
            "dnsRoot": self.get_loadparm().get("realm").lower(),
            "instanceType": "4",
            "nCName": self.base_dn,
            "showInAdvancedViewOnly": "TRUE",
            "name": "test crossRef",
            "systemFlags": "1"}, ["relax:0"])

        # urgent replication should be enabled when creating
        res = self.ldb.load_partition_usn("cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should NOT be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "cn=test crossRef,CN=Partitions,CN=Configuration," + self.base_dn)
        m["systemFlags"] = MessageElement("0", FLAG_MOD_REPLACE,
                                          "systemFlags")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn("cn=Configuration," + self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when deleting
        self.delete_force(self.ldb, "cn=test crossRef,CN=Partitions,CN=Configuration," + self.base_dn)
        res = self.ldb.load_partition_usn("cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

    def test_attributeSchema_object(self):
        """Test if the urgent replication is activated when handling an attributeSchema object"""

        self.ldb.add_ldif(
            """dn: CN=test attributeSchema,cn=Schema,CN=Configuration,%s""" % self.base_dn + """
objectClass: attributeSchema
cn: test attributeSchema
instanceType: 4
isSingleValued: FALSE
showInAdvancedViewOnly: FALSE
attributeID: 1.3.6.1.4.1.7165.4.6.1.4.""" + str(random.randint(1, 100000)) + """
attributeSyntax: 2.5.5.12
adminDisplayName: test attributeSchema
adminDescription: test attributeSchema
oMSyntax: 64
systemOnly: FALSE
searchFlags: 8
lDAPDisplayName: testAttributeSchema
name: test attributeSchema""")

        # urgent replication should be enabled when creating
        res = self.ldb.load_partition_usn("cn=Schema,cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "CN=test attributeSchema,CN=Schema,CN=Configuration," + self.base_dn)
        m["lDAPDisplayName"] = MessageElement("updatedTestAttributeSchema", FLAG_MOD_REPLACE,
                                              "lDAPDisplayName")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn("cn=Schema,cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

    def test_classSchema_object(self):
        """Test if the urgent replication is activated when handling a classSchema object."""
        try:
            self.ldb.add_ldif(
                            """dn: CN=test classSchema,CN=Schema,CN=Configuration,%s""" % self.base_dn + """
objectClass: classSchema
cn: test classSchema
instanceType: 4
subClassOf: top
governsId: 1.3.6.1.4.1.7165.4.6.2.4.""" + str(random.randint(1, 100000)) + """
rDNAttID: cn
showInAdvancedViewOnly: TRUE
adminDisplayName: test classSchema
adminDescription: test classSchema
objectClassCategory: 1
lDAPDisplayName: testClassSchema
name: test classSchema
systemOnly: FALSE
systemPossSuperiors: dfsConfiguration
systemMustContain: msDFS-SchemaMajorVersion
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCD
 CLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)
systemFlags: 16
defaultHidingValue: TRUE""")

            # urgent replication should be enabled when creating
            res = self.ldb.load_partition_usn("cn=Schema,cn=Configuration," + self.base_dn)
            self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        except LdbError:
            print("Not testing urgent replication when creating classSchema object ...\n")

        # urgent replication should be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "CN=test classSchema,CN=Schema,CN=Configuration," + self.base_dn)
        m["lDAPDisplayName"] = MessageElement("updatedTestClassSchema", FLAG_MOD_REPLACE,
                                              "lDAPDisplayName")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn("cn=Schema,cn=Configuration," + self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

    def test_secret_object(self):
        """Test if the urgent replication is activated when handling a secret object."""

        self.ldb.add({
            "dn": "cn=test secret,cn=System," + self.base_dn,
            "objectClass": "secret",
            "cn": "test secret",
            "name": "test secret",
            "currentValue": "xxxxxxx"})

        # urgent replication should be enabled when creating
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "cn=test secret,cn=System," + self.base_dn)
        m["currentValue"] = MessageElement("yyyyyyyy", FLAG_MOD_REPLACE,
                                           "currentValue")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should NOT be enabled when deleting
        self.delete_force(self.ldb, "cn=test secret,cn=System," + self.base_dn)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

    def test_rIDManager_object(self):
        """Test if the urgent replication is activated when handling a rIDManager object."""
        self.ldb.add_ldif(
            """dn: CN=RID Manager test,CN=System,%s""" % self.base_dn + """
objectClass: rIDManager
cn: RID Manager test
instanceType: 4
showInAdvancedViewOnly: TRUE
name: RID Manager test
systemFlags: -1946157056
isCriticalSystemObject: TRUE
rIDAvailablePool: 133001-1073741823""", ["relax:0"])

        # urgent replication should be enabled when creating
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when modifying
        m = Message()
        m.dn = Dn(self.ldb, "CN=RID Manager test,CN=System," + self.base_dn)
        m["systemFlags"] = MessageElement("0", FLAG_MOD_REPLACE,
                                          "systemFlags")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should NOT be enabled when deleting
        self.delete_force(self.ldb, "CN=RID Manager test,CN=System," + self.base_dn)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

    def test_urgent_attributes(self):
        """Test if the urgent replication is activated when handling urgent attributes of an object."""

        self.ldb.add({
            "dn": "cn=user UrgAttr test,cn=users," + self.base_dn,
            "objectclass": "user",
            "samaccountname": "user UrgAttr test",
            "userAccountControl": str(dsdb.UF_NORMAL_ACCOUNT),
            "lockoutTime": "0",
            "pwdLastSet": "0",
            "description": "urgent attributes test description"})

        # urgent replication should NOT be enabled when creating
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when modifying userAccountControl
        m = Message()
        m.dn = Dn(self.ldb, "cn=user UrgAttr test,cn=users," + self.base_dn)
        m["userAccountControl"] = MessageElement(str(dsdb.UF_NORMAL_ACCOUNT + dsdb.UF_DONT_EXPIRE_PASSWD), FLAG_MOD_REPLACE,
                                                 "userAccountControl")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when modifying lockoutTime
        m = Message()
        m.dn = Dn(self.ldb, "cn=user UrgAttr test,cn=users," + self.base_dn)
        m["lockoutTime"] = MessageElement("1", FLAG_MOD_REPLACE,
                                          "lockoutTime")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should be enabled when modifying pwdLastSet
        m = Message()
        m.dn = Dn(self.ldb, "cn=user UrgAttr test,cn=users," + self.base_dn)
        m["pwdLastSet"] = MessageElement("-1", FLAG_MOD_REPLACE,
                                         "pwdLastSet")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertEqual(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should NOT be enabled when modifying a not-urgent
        # attribute
        m = Message()
        m.dn = Dn(self.ldb, "cn=user UrgAttr test,cn=users," + self.base_dn)
        m["description"] = MessageElement("updated urgent attributes test description",
                                          FLAG_MOD_REPLACE, "description")
        self.ldb.modify(m)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])

        # urgent replication should NOT be enabled when deleting
        self.delete_force(self.ldb, "cn=user UrgAttr test,cn=users," + self.base_dn)
        res = self.ldb.load_partition_usn(self.base_dn)
        self.assertNotEquals(res["uSNHighest"], res["uSNUrgent"])


TestProgram(module=__name__, opts=subunitopts)
