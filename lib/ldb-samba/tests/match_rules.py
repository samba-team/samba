#!/usr/bin/env python3

import optparse
import sys
import os
import samba
import samba.getopt as options

from samba.tests.subunitrun import SubunitOptions, TestProgram

from samba.samdb import SamDB
from samba.auth import system_session
from ldb import Message, MessageElement, Dn, LdbError
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from ldb import SCOPE_BASE, SCOPE_SUBTREE, SCOPE_ONELEVEL

# TODO I'm ignoring case in these tests for now.
#       This should be fixed to work inline with Windows.
#       The literal strings are in the case Windows uses.
# Windows appear to preserve casing of the RDN and uppercase the other keys.


class MatchRulesTests(samba.tests.TestCase):
    def setUp(self):
        super(MatchRulesTests, self).setUp()
        self.lp = lp
        self.ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.ou = "OU=matchrulestest,%s" % self.base_dn
        self.ou_users = "OU=users,%s" % self.ou
        self.ou_groups = "OU=groups,%s" % self.ou
        self.ou_computers = "OU=computers,%s" % self.ou

        # Add a organizational unit to create objects
        self.ldb.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})

        # Add the following OU hierarchy and set otherWellKnownObjects,
        # which has BinaryDN syntax:
        #
        # o1
        # |--> o2
        # |    |--> o3
        # |    |    |-->o4

        self.ldb.add({
            "dn": "OU=o1,%s" % self.ou,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": "OU=o2,OU=o1,%s" % self.ou,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": "OU=o3,OU=o2,OU=o1,%s" % self.ou,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": "OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou,
            "objectclass": "organizationalUnit"})

        m = Message()
        m.dn = Dn(self.ldb, self.ou)
        m["otherWellKnownObjects"] = MessageElement("B:32:00000000000000000000000000000001:OU=o1,%s" % self.ou,
                                                    FLAG_MOD_ADD, "otherWellKnownObjects")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "OU=o1,%s" % self.ou)
        m["otherWellKnownObjects"] = MessageElement("B:32:00000000000000000000000000000002:OU=o2,OU=o1,%s" % self.ou,
                                                    FLAG_MOD_ADD, "otherWellKnownObjects")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "OU=o2,OU=o1,%s" % self.ou)
        m["otherWellKnownObjects"] = MessageElement("B:32:00000000000000000000000000000003:OU=o3,OU=o2,OU=o1,%s" % self.ou,
                                                    FLAG_MOD_ADD, "otherWellKnownObjects")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "OU=o3,OU=o2,OU=o1,%s" % self.ou)
        m["otherWellKnownObjects"] = MessageElement("B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou,
                                                    FLAG_MOD_ADD, "otherWellKnownObjects")
        self.ldb.modify(m)

        # Create OU for users and groups
        self.ldb.add({
            "dn": self.ou_users,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": self.ou_groups,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": self.ou_computers,
            "objectclass": "organizationalUnit"})

        # Add four groups
        self.ldb.add({
            "dn": "cn=g1,%s" % self.ou_groups,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=g2,%s" % self.ou_groups,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=g4,%s" % self.ou_groups,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=g3,%s" % self.ou_groups,
            "objectclass": "group"})

        # Add four users
        self.ldb.add({
            "dn": "cn=u1,%s" % self.ou_users,
            "objectclass": "user"})
        self.ldb.add({
            "dn": "cn=u2,%s" % self.ou_users,
            "objectclass": "user"})
        self.ldb.add({
            "dn": "cn=u3,%s" % self.ou_users,
            "objectclass": "user"})
        self.ldb.add({
            "dn": "cn=u4,%s" % self.ou_users,
            "objectclass": "user"})

        # Add computers to test Object(DN-Binary) syntax
        self.ldb.add({
            "dn": "cn=c1,%s" % self.ou_computers,
            "objectclass": "computer",
            "dNSHostName": "c1.%s" % self.lp.get("realm").lower(),
            "servicePrincipalName": ["HOST/c1"],
            "sAMAccountName": "c1$",
            "userAccountControl": "83890178"})

        self.ldb.add({
            "dn": "cn=c2,%s" % self.ou_computers,
            "objectclass": "computer",
            "dNSHostName": "c2.%s" % self.lp.get("realm").lower(),
            "servicePrincipalName": ["HOST/c2"],
            "sAMAccountName": "c2$",
            "userAccountControl": "83890178"})

        self.ldb.add({
            "dn": "cn=c3,%s" % self.ou_computers,
            "objectclass": "computer",
            "dNSHostName": "c3.%s" % self.lp.get("realm").lower(),
            "servicePrincipalName": ["HOST/c3"],
            "sAMAccountName": "c3$",
            "userAccountControl": "83890178"})

        # Create the following hierarchy:
        # g4
        # |--> u4
        # |--> g3
        # |    |--> u3
        # |    |--> g2
        # |    |    |--> u2
        # |    |    |--> g1
        # |    |    |    |--> u1

        # u1 member of g1
        m = Message()
        m.dn = Dn(self.ldb, "CN=g1,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u1,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u2 member of g2
        m = Message()
        m.dn = Dn(self.ldb, "CN=g2,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=u2,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u3 member of g3
        m = Message()
        m.dn = Dn(self.ldb, "cn=g3,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u3,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u4 member of g4
        m = Message()
        m.dn = Dn(self.ldb, "cn=g4,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=u4,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # g3 member of g4
        m = Message()
        m.dn = Dn(self.ldb, "CN=g4,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=g3,%s" % self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # g2 member of g3
        m = Message()
        m.dn = Dn(self.ldb, "cn=g3,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=g2,%s" % self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # g1 member of g2
        m = Message()
        m.dn = Dn(self.ldb, "cn=g2,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=g1,%s" % self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # The msDS-RevealedUsers is owned by system and cannot be modified
        # directly. Set the schemaUpgradeInProgress flag as workaround
        # and create this hierarchy:
        # ou=computers
        # |-> c1
        # |   |->c2
        # |   |  |->u1

        #
        # While appropriate for this test, this is NOT a good practice
        # in general.  This is only done here because the alternative
        # is to make a schema modification.
        #
        # IF/WHEN Samba protects this attribute better, this
        # particular part of the test can be removed, as the same code
        # is covered by the addressBookRoots2 case well enough.
        #
        m = Message()
        m.dn = Dn(self.ldb, "")
        m["e1"] = MessageElement("1", FLAG_MOD_REPLACE, "schemaUpgradeInProgress")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "cn=c2,%s" % self.ou_computers)
        m["e1"] = MessageElement("B:8:01010101:cn=c3,%s" % self.ou_computers,
                                 FLAG_MOD_ADD, "msDS-RevealedUsers")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "cn=c1,%s" % self.ou_computers)
        m["e1"] = MessageElement("B:8:01010101:cn=c2,%s" % self.ou_computers,
                                 FLAG_MOD_ADD, "msDS-RevealedUsers")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "")
        m["e1"] = MessageElement("0", FLAG_MOD_REPLACE, "schemaUpgradeInProgress")
        self.ldb.modify(m)

        # Add a couple of ms-Exch-Configuration-Container to test forward-link
        # attributes without backward link (addressBookRoots2)
        # e1
        # |--> e2
        # |    |--> c1
        self.ldb.add({
            "dn": "cn=e1,%s" % self.ou,
            "objectclass": "msExchConfigurationContainer"})
        self.ldb.add({
            "dn": "cn=e2,%s" % self.ou,
            "objectclass": "msExchConfigurationContainer"})

        m = Message()
        m.dn = Dn(self.ldb, "cn=e2,%s" % self.ou)
        m["e1"] = MessageElement("cn=c1,%s" % self.ou_computers,
                                 FLAG_MOD_ADD, "addressBookRoots2")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "cn=e1,%s" % self.ou)
        m["e1"] = MessageElement("cn=e2,%s" % self.ou,
                                 FLAG_MOD_ADD, "addressBookRoots2")
        self.ldb.modify(m)

    def tearDown(self):
        super(MatchRulesTests, self).tearDown()
        self.ldb.delete(self.ou, controls=['tree_delete:0'])

    def test_u1_member_of_g4(self):
        # Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                               scope=SCOPE_BASE,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        # Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                               scope=SCOPE_BASE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=u1,%s" % self.ou_users).lower())

    def test_g1_member_of_g4(self):
        # Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        # Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g1,%s" % self.ou_groups).lower())

    def test_u1_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g1,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g1,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

    def test_u2_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g2,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

    def test_u3_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g3,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

    def test_u4_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_users,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

    def test_extended_dn_u1(self):
        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                               scope=SCOPE_BASE,
                               expression="objectClass=*",
                               attrs=['objectSid', 'objectGUID'])
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("cn=u1,%s" % self.ou_users).lower())

        sid = self.ldb.schema_format_value("objectSid", res1[0]["objectSid"][0]).decode('utf8')
        guid = self.ldb.schema_format_value("objectGUID", res1[0]['objectGUID'][0]).decode('utf8')

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<SID=%s>" % sid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g1,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g1,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g1,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g1,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g1,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g1,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

    def test_extended_dn_u2(self):
        res1 = self.ldb.search("cn=u2,%s" % self.ou_users,
                               scope=SCOPE_BASE,
                               expression="objectClass=*",
                               attrs=['objectSid', 'objectGUID'])
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("cn=u2,%s" % self.ou_users).lower())

        sid = self.ldb.schema_format_value("objectSid", res1[0]["objectSid"][0]).decode('utf8')
        guid = self.ldb.schema_format_value("objectGUID", res1[0]['objectGUID'][0]).decode('utf8')

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<SID=%s>" % sid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g2,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g2,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g2,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

    def test_extended_dn_u3(self):
        res1 = self.ldb.search("cn=u3,%s" % self.ou_users,
                               scope=SCOPE_BASE,
                               expression="objectClass=*",
                               attrs=['objectSid', 'objectGUID'])
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("cn=u3,%s" % self.ou_users).lower())

        sid = self.ldb.schema_format_value("objectSid", res1[0]["objectSid"][0]).decode('utf8')
        guid = self.ldb.schema_format_value("objectGUID", res1[0]['objectGUID'][0]).decode('utf8')

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<SID=%s>" % sid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g3,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g3,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=g3,%s" % self.ou_groups).lower() in dn_list)
        self.assertTrue(("CN=g4,%s" % self.ou_groups).lower() in dn_list)

    def test_extended_dn_u4(self):
        res1 = self.ldb.search("cn=u4,%s" % self.ou_users,
                               scope=SCOPE_BASE,
                               expression="objectClass=*",
                               attrs=['objectSid', 'objectGUID'])
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("cn=u4,%s" % self.ou_users).lower())

        sid = self.ldb.schema_format_value("objectSid", res1[0]["objectSid"][0]).decode('utf8')
        guid = self.ldb.schema_format_value("objectGUID", res1[0]['objectGUID'][0]).decode('utf8')

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<SID=%s>" % sid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=g4,%s" % self.ou_groups).lower())

    def test_object_dn_binary(self):
        res1 = self.ldb.search(self.ou_computers,
                               scope=SCOPE_SUBTREE,
                               expression="msDS-RevealedUsers=B:8:01010101:cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=c2,%s" % self.ou_computers).lower())

        res1 = self.ldb.search(self.ou_computers,
                               scope=SCOPE_ONELEVEL,
                               expression="msDS-RevealedUsers=B:8:01010101:cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=c2,%s" % self.ou_computers).lower())

        res1 = self.ldb.search(self.ou_computers,
                               scope=SCOPE_SUBTREE,
                               expression="msDS-RevealedUsers:1.2.840.113556.1.4.1941:=B:8:01010101:cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=c1,%s" % self.ou_computers).lower() in dn_list)
        self.assertTrue(("CN=c2,%s" % self.ou_computers).lower() in dn_list)

        res1 = self.ldb.search(self.ou_computers,
                               scope=SCOPE_ONELEVEL,
                               expression="msDS-RevealedUsers:1.2.840.113556.1.4.1941:=B:8:01010101:cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=c1,%s" % self.ou_computers).lower() in dn_list)
        self.assertTrue(("CN=c2,%s" % self.ou_computers).lower() in dn_list)

    def test_one_way_links(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="addressBookRoots2=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=e2,%s" % self.ou).lower())

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_ONELEVEL,
                               expression="addressBookRoots2=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("CN=e2,%s" % self.ou).lower())

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="addressBookRoots2:1.2.840.113556.1.4.1941:=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=e1,%s" % self.ou).lower() in dn_list)
        self.assertTrue(("CN=e2,%s" % self.ou).lower() in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_ONELEVEL,
                               expression="addressBookRoots2:1.2.840.113556.1.4.1941:=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn).lower() for res in res1]
        self.assertTrue(("CN=e1,%s" % self.ou).lower() in dn_list)
        self.assertTrue(("CN=e2,%s" % self.ou).lower() in dn_list)

    def test_not_linked_attrs(self):
        res1 = self.ldb.search(self.base_dn,
                               scope=SCOPE_BASE,
                               expression="wellKnownObjects=B:32:aa312825768811d1aded00c04fd8d5cd:CN=computers,%s" % self.base_dn)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), self.base_dn.lower())

    def test_invalid_basedn(self):
        res1 = self.ldb.search(self.base_dn,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=c1,ou=computers,ou=matchrulestest,%sXX" % self.base_dn)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.base_dn,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=XX,ou=computers,ou=matchrulestest,%s" % self.base_dn)
        self.assertEqual(len(res1), 0)

    def test_subtree(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="otherWellKnownObjects=B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn).lower(), ("OU=o3,OU=o2,OU=o1,%s" % self.ou).lower())

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_ONELEVEL,
                               expression="otherWellKnownObjects=B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="otherWellKnownObjects:1.2.840.113556.1.4.1941:=B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_ONELEVEL,
                               expression="otherWellKnownObjects:1.2.840.113556.1.4.1941:=B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
        self.assertEqual(len(res1), 0)

    def test_unknown_oid(self):
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:2.4.681.226012.2.8.3882:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:8.16.8720.1008448.8.32.15528:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.3.4:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

    def test_nul_text(self):
        self.assertRaises((ValueError,TypeError),
                          lambda: self.ldb.search("cn=g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="\00member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users))
        self.assertRaises((ValueError,TypeError),
                          lambda: self.ldb.search("cn=g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840\00.113556.1.4.1941:=cn=u1,%s" % self.ou_users))
        self.assertRaises((ValueError,TypeError),
                          lambda: self.ldb.search("cn=g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840.113556.1.4.1941:=cn=u1\00,%s" % self.ou_users))
        self.assertRaises(LdbError,
                          lambda: self.ldb.search("cn=\00g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users))
        self.assertRaises(LdbError,
                          lambda: self.ldb.search("cn=g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840.113556.1.4.1941:"))
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=")
        self.assertEqual(len(res1), 0)
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=")
        self.assertEqual(len(res1), 0)
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=nonexistent")
        self.assertEqual(len(res1), 0)
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=nonexistent")
        self.assertEqual(len(res1), 0)
        self.assertRaises(LdbError,
                          lambda: self.ldb.search("cn=\00g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840.113556.1.4.1941:cn=u1,%s" % self.ou_users))
        self.assertRaises(LdbError,
                          lambda: self.ldb.search("cn=\00g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840.113556.1.4.1941:=cn=u1"))
        self.assertRaises(LdbError,
                          lambda: self.ldb.search("cn=\00g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member:1.2.840.113556.1.4.1941:=cn="))
        self.assertRaises(LdbError,
                          lambda: self.ldb.search("cn=\00g4,%s" % self.ou_groups,
                                                  scope=SCOPE_BASE,
                                                  expression="member::=cn=u1,%s" % self.ou_users))

    def test_misc_matches(self):
        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g2,%s" % self.ou_groups)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g2,%s" % self.ou_groups)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), ("CN=g3,%s" % self.ou_groups))

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), ("CN=g3,%s" % self.ou_groups))

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                               scope=SCOPE_BASE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_ONELEVEL,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou_groups,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)


class MatchRuleConditionTests(samba.tests.TestCase):
    def setUp(self):
        super(MatchRuleConditionTests, self).setUp()
        self.lp = lp
        self.ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.ou = "OU=matchruleconditiontests,%s" % self.base_dn
        self.ou_users = "OU=users,%s" % self.ou
        self.ou_groups = "OU=groups,%s" % self.ou
        self.ou_computers = "OU=computers,%s" % self.ou

        # Add a organizational unit to create objects
        self.ldb.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})

        # Create users, groups, and computers
        self.ldb.add({
            "dn": self.ou_users,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": self.ou_groups,
            "objectclass": "organizationalUnit"})
        self.ldb.add({
            "dn": self.ou_computers,
            "objectclass": "organizationalUnit"})

        self.ldb.add({
            "dn": "cn=g1,%s" % self.ou_groups,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=g2,%s" % self.ou_groups,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=g3,%s" % self.ou_groups,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=g4,%s" % self.ou_groups,
            "objectclass": "group"})

        self.ldb.add({
            "dn": "cn=u1,%s" % self.ou_users,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=u2,%s" % self.ou_users,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=u3,%s" % self.ou_users,
            "objectclass": "group"})
        self.ldb.add({
            "dn": "cn=u4,%s" % self.ou_users,
            "objectclass": "group"})

        self.ldb.add({
            "dn": "cn=c1,%s" % self.ou_computers,
            "objectclass": "user"})

        self.ldb.add({
            "dn": "cn=c2,%s" % self.ou_computers,
            "objectclass": "user"})

        self.ldb.add({
            "dn": "cn=c3,%s" % self.ou_computers,
            "objectclass": "user"})

        self.ldb.add({
            "dn": "cn=c4,%s" % self.ou_computers,
            "objectclass": "user"})

        # Assign groups according to the following structure:
        #  g1-->g2---->g3   --g4
        #     \  |    / |  / / |
        #  u1- >u2-- | u3<- | u4
        #     \     \ \      \ |
        #  c1* >c2   ->c3     c4
        # *c1 is a member of u1, u2, u3, and u4

        # u2 is a member of g1 and g2
        m = Message()
        m.dn = Dn(self.ldb, "CN=g1,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u2,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=g2,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u2,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # g2 is a member of g1
        m = Message()
        m.dn = Dn(self.ldb, "CN=g1,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=g2,%s" % self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # g3 is a member of g2
        m = Message()
        m.dn = Dn(self.ldb, "CN=g2,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=g3,%s" % self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u3 is a member of g3 and g4
        m = Message()
        m.dn = Dn(self.ldb, "CN=g3,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u3,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=g4,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u3,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u4 is a member of g4
        m = Message()
        m.dn = Dn(self.ldb, "CN=g4,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=u4,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # c1 is a member of u1, u2, u3, and u4
        m = Message()
        m.dn = Dn(self.ldb, "CN=u1,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c1,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=u2,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c1,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=u3,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c1,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=u4,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c1,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # c2 is a member of u1
        m = Message()
        m.dn = Dn(self.ldb, "CN=u1,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c2,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # c3 is a member of u2 and g3
        m = Message()
        m.dn = Dn(self.ldb, "CN=u2,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c3,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=g3,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=c3,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # c4 is a member of u4 and g4
        m = Message()
        m.dn = Dn(self.ldb, "CN=u4,%s" % self.ou_users)
        m["member"] = MessageElement("CN=c4,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        m = Message()
        m.dn = Dn(self.ldb, "CN=g4,%s" % self.ou_groups)
        m["member"] = MessageElement("CN=c4,%s" % self.ou_computers,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

    def tearDown(self):
        super(MatchRuleConditionTests, self).tearDown()
        self.ldb.delete(self.ou, controls=['tree_delete:0'])

    def test_g1_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 6)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

    def test_g2_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=g2,%s" % self.ou_groups)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s" % self.ou_groups)
        self.assertEqual(len(res1), 5)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=g2,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g1,%s" % self.ou_groups)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g2,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g1,%s" % self.ou_groups)

    def test_g3_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=g3,%s" % self.ou_groups)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s" % self.ou_groups)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=g3,%s" % self.ou_groups)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g2,%s" % self.ou_groups)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g3,%s" % self.ou_groups)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)

    def test_g4_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertEqual(len(res1), 0)

    def test_u1_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c2,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c2,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertEqual(len(res1), 0)

    def test_u2_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u2,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)

    def test_u3_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=c1,%s" % self.ou_computers)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=u3,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=c1,%s" % self.ou_computers)

    def test_u4_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g4,%s" % self.ou_groups)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=g4,%s" % self.ou_groups)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=u4,%s" % self.ou_users)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

    def test_c1_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u1,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 8)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u1,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=c1,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

    def test_c2_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=c2,%s" % self.ou_computers)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=u1,%s" % self.ou_users)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=c2,%s" % self.ou_computers)
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=u1,%s" % self.ou_users)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=c2,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=c2,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

    def test_c3_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 4)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=c3,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

    def test_c4_members(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member=cn=c4,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="member:1.2.840.113556.1.4.1941:=cn=c4,%s" % self.ou_computers)
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf=cn=c4,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression="memberOf:1.2.840.113556.1.4.1941:=cn=c4,%s" % self.ou_computers)
        self.assertEqual(len(res1), 0)

    def test_or_member_queries(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(member:1.2.840.113556.1.4.1941:=cn=c1,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c2,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 8)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u1,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(member:1.2.840.113556.1.4.1941:=cn=c2,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c3,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 5)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u1,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(member:1.2.840.113556.1.4.1941:=cn=c2,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c4,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u1,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(member:1.2.840.113556.1.4.1941:=cn=c3,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c4,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 6)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(member:1.2.840.113556.1.4.1941:=cn=u1,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c4,%s))") % (
                                    self.ou_users, self.ou_computers))
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g4,%s" % self.ou_groups in dn_list)

    def test_and_member_queries(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(member:1.2.840.113556.1.4.1941:=cn=c1,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c2,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 1)
        self.assertEqual(str(res1[0].dn), "CN=u1,%s" % self.ou_users)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(member:1.2.840.113556.1.4.1941:=cn=c2,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=c3,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 0)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(member:1.2.840.113556.1.4.1941:=cn=c3,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=u3,%s))") % (
                                    self.ou_computers, self.ou_users))
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=g1,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(member:1.2.840.113556.1.4.1941:=cn=c1,%s)"
                                           "(member:1.2.840.113556.1.4.1941:=cn=u4,%s))") % (
                                    self.ou_computers, self.ou_computers))
        self.assertEqual(len(res1), 0)

    def test_or_memberOf_queries(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 6)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 6)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 8)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g2,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s))") %
                               (self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 5)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 7)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(|(memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 5)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u4,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c4,%s" % self.ou_computers in dn_list)

    def test_and_memberOf_queries(self):
        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 5)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u2,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=g3,%s" % self.ou_groups in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 3)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)
        self.assertTrue("CN=c3,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g2,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g3,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s))") % (
                                    self.ou_groups, self.ou_groups))
        self.assertEqual(len(res1), 2)
        dn_list = [str(res.dn) for res in res1]
        self.assertTrue("CN=u3,%s" % self.ou_users in dn_list)
        self.assertTrue("CN=c1,%s" % self.ou_computers in dn_list)

        res1 = self.ldb.search(self.ou,
                               scope=SCOPE_SUBTREE,
                               expression=("(&(memberOf:1.2.840.113556.1.4.1941:=cn=g1,%s)"
                                           "(memberOf:1.2.840.113556.1.4.1941:=cn=c1,%s))") % (
                                    self.ou_groups, self.ou_computers))
        self.assertEqual(len(res1), 0)


parser = optparse.OptionParser("match_rules.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)
