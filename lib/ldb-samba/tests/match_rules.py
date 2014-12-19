#!/usr/bin/env python

import optparse
import sys
import os
import unittest
import samba
import samba.getopt as options

from samba.tests.subunitrun import SubunitOptions, TestProgram

from samba.tests import delete_force
from samba.dcerpc import security, misc
from samba.samdb import SamDB
from samba.auth import system_session
from samba.ndr import ndr_unpack
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from ldb import SCOPE_BASE, SCOPE_SUBTREE

class MatchRulesTests(samba.tests.TestCase):
    def setUp(self):
        super(MatchRulesTests, self).setUp()
        self.lp = lp
        self.ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.ou = "ou=matchrulestest,%s" % self.base_dn
        self.ou_users = "ou=users,%s" % self.ou
        self.ou_groups = "ou=groups,%s" % self.ou
        self.ou_computers = "ou=computers,%s" % self.ou

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
            "objectclass": "group" })
        self.ldb.add({
            "dn": "cn=g2,%s" % self.ou_groups,
            "objectclass": "group" })
        self.ldb.add({
            "dn": "cn=g3,%s" % self.ou_groups,
            "objectclass": "group" })
        self.ldb.add({
            "dn": "cn=g4,%s" % self.ou_groups,
            "objectclass": "group" })

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
        m.dn = Dn(self.ldb, "cn=g1,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=u1,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u2 member of g2
        m = Message()
        m.dn = Dn(self.ldb, "cn=g2,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=u2,%s" % self.ou_users,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # u3 member of g3
        m = Message()
        m.dn = Dn(self.ldb, "cn=g3,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=u3,%s" % self.ou_users,
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
        m.dn = Dn(self.ldb, "cn=g4,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=g3,%s" % self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

        # g2 member of g3
        m = Message()
        m.dn = Dn(self.ldb, "cn=g3,%s" % self.ou_groups)
        m["member"] = MessageElement("cn=g2,%s" % self.ou_groups,
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
        delete_force(self.ldb, "cn=u4,%s" % self.ou_users)
        delete_force(self.ldb, "cn=u3,%s" % self.ou_users)
        delete_force(self.ldb, "cn=u2,%s" % self.ou_users)
        delete_force(self.ldb, "cn=u1,%s" % self.ou_users)
        delete_force(self.ldb, "cn=g4,%s" % self.ou_groups)
        delete_force(self.ldb, "cn=g3,%s" % self.ou_groups)
        delete_force(self.ldb, "cn=g2,%s" % self.ou_groups)
        delete_force(self.ldb, "cn=g1,%s" % self.ou_groups)
        delete_force(self.ldb, "cn=c1,%s" % self.ou_computers)
        delete_force(self.ldb, "cn=c2,%s" % self.ou_computers)
        delete_force(self.ldb, "cn=c3,%s" % self.ou_computers)
        delete_force(self.ldb, self.ou_users)
        delete_force(self.ldb, self.ou_groups)
        delete_force(self.ldb, self.ou_computers)
        delete_force(self.ldb, "OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
        delete_force(self.ldb, "OU=o3,OU=o2,OU=o1,%s" % self.ou)
        delete_force(self.ldb, "OU=o2,OU=o1,%s" % self.ou)
        delete_force(self.ldb, "OU=o1,%s" % self.ou)
        delete_force(self.ldb, "CN=e2,%s" % self.ou)
        delete_force(self.ldb, "CN=e1,%s" % self.ou)
        delete_force(self.ldb, self.ou)

    def test_u1_member_of_g4(self):
        # Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 0)

        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                        scope=SCOPE_BASE,
                        expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 0)

        # Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                        scope=SCOPE_BASE,
                        expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 1)

    def test_g1_member_of_g4(self):
        # Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member=cn=g1,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 0)

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 0)

        # Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 1)

    def test_u1_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 4)

    def test_u2_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u2,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u2,%s" % self.ou_users)
        self.assertTrue(len(res1) == 3)

    def test_u3_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u3,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u3,%s" % self.ou_users)
        self.assertTrue(len(res1) == 2)

    def test_u4_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u4,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u4,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

    def test_extended_dn(self):
        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                        scope=SCOPE_BASE,
                        expression="objectClass=*",
                        attrs=['objectSid', 'objectGUID'])
        self.assertTrue(len(res1) == 1)

        sid = self.ldb.schema_format_value("objectSid", res1[0]["objectSid"][0])
        guid = self.ldb.schema_format_value("objectGUID", res1[0]['objectGUID'][0])

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=<SID=%s>" % sid)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=<GUID=%s>" % guid)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=<SID=%s>" % sid)
        self.assertTrue(len(res1) == 4)

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=<GUID=%s>" % guid)
        self.assertTrue(len(res1) == 4)

    def test_object_dn_binary(self):
        res1 = self.ldb.search(self.ou_computers,
                        scope=SCOPE_SUBTREE,
                        expression="msDS-RevealedUsers=B:8:01010101:cn=c3,%s" % self.ou_computers)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou_computers,
                        scope=SCOPE_SUBTREE,
                        expression="msDS-RevealedUsers:1.2.840.113556.1.4.1941:=B:8:01010101:cn=c3,%s" % self.ou_computers)
        self.assertTrue(len(res1) == 2)

    def test_one_way_links(self):
        res1 = self.ldb.search(self.ou,
                        scope=SCOPE_SUBTREE,
                        expression="addressBookRoots2=cn=c1,%s" % self.ou_computers)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.ou,
                        scope=SCOPE_SUBTREE,
                        expression="addressBookRoots2:1.2.840.113556.1.4.1941:=cn=c1,%s" % self.ou_computers)
        self.assertTrue(len(res1) == 2)

    def test_not_linked_attrs(self):
        res1 = self.ldb.search(self.base_dn,
                        scope=SCOPE_BASE,
                        expression="wellKnownObjects=B:32:aa312825768811d1aded00c04fd8d5cd:CN=computers,%s" % self.base_dn)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search(self.base_dn,
                        scope=SCOPE_BASE,
                        expression="wellKnownObjects:1.2.840.113556.1.4.1941:=B:32:aa312825768811d1aded00c04fd8d5cd:CN=computers,%s" % self.base_dn)
        self.assertTrue(len(res1) == 0)


	res1 = self.ldb.search(self.ou,
			scope=SCOPE_SUBTREE,
			expression="otherWellKnownObjects=B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
	self.assertTrue(len(res1) == 1)

	res1 = self.ldb.search(self.ou,
			scope=SCOPE_SUBTREE,
			expression="otherWellKnownObjects:1.2.840.113556.1.4.1941:=B:32:00000000000000000000000000000004:OU=o4,OU=o3,OU=o2,OU=o1,%s" % self.ou)
	self.assertTrue(len(res1) == 0)

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

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

TestProgram(module=__name__, opts=subunitopts)
