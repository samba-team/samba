#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse
import sys
import os
import base64
import re
import random

sys.path.append("bin/python")
import samba
samba.ensure_external_module("subunit", "subunit/python")
samba.ensure_external_module("testtools", "testtools")

import samba.getopt as options

# Some error messages that are being tested
from ldb import SCOPE_SUBTREE, SCOPE_BASE, LdbError, ERR_NO_SUCH_OBJECT

# For running the test unit
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

from samba import gensec
from samba.samdb import SamDB
from samba.credentials import Credentials
from samba.auth import system_session
from samba.dsdb import DS_DOMAIN_FUNCTION_2008
from samba.dcerpc.security import (
    SECINFO_OWNER, SECINFO_GROUP, SECINFO_DACL, SECINFO_SACL)
from subunit.run import SubunitTestRunner
import samba.tests
import unittest

parser = optparse.OptionParser("sec_descriptor [options] <host>")
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
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

#
# Tests start here
#

class DescriptorTests(samba.tests.TestCase):

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

    def find_domain_sid(self, ldb):
        res = ldb.search(base=self.base_dn, expression="(objectClass=*)", scope=SCOPE_BASE)
        return ndr_unpack( security.dom_sid,res[0]["objectSid"][0])

    def get_users_domain_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def modify_desc(self, _ldb, object_dn, desc, controls=None):
        assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
        mod = """
dn: """ + object_dn + """
changetype: modify
replace: nTSecurityDescriptor
"""
        if isinstance(desc, str):
            mod += "nTSecurityDescriptor: %s" % desc
        elif isinstance(desc, security.descriptor):
            mod += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.modify_ldif(mod, controls)

    def create_domain_ou(self, _ldb, ou_dn, desc=None, controls=None):
        ldif = """
dn: """ + ou_dn + """
ou: """ + ou_dn.split(",")[0][3:] + """
objectClass: organizationalUnit
url: www.example.com
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif, controls)

    def create_domain_user(self, _ldb, user_dn, desc=None):
        ldif = """
dn: """ + user_dn + """
sAMAccountName: """ + user_dn.split(",")[0][3:] + """
objectClass: user
userPassword: samba123@
url: www.example.com
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif)

    def create_domain_group(self, _ldb, group_dn, desc=None):
        ldif = """
dn: """ + group_dn + """
objectClass: group
sAMAccountName: """ + group_dn.split(",")[0][3:] + """
groupType: 4
url: www.example.com
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif)

    def get_unique_schema_class_name(self):
        while True:
            class_name = "test-class%s" % random.randint(1,100000)
            class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
            try:
                self.ldb_admin.search(base=class_dn, attrs=["*"])
            except LdbError, (num, _):
                self.assertEquals(num, ERR_NO_SUCH_OBJECT)
                return class_name

    def create_schema_class(self, _ldb, object_dn, desc=None):
        ldif = """
dn: """ + object_dn + """
objectClass: classSchema
objectCategory: CN=Class-Schema,""" + self.schema_dn + """
defaultObjectCategory: """ + object_dn + """
distinguishedName: """ + object_dn + """
governsID: 1.2.840.""" + str(random.randint(1,100000)) + """.1.5.9939
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
systemFlags: 16
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif)

    def create_configuration_container(self, _ldb, object_dn, desc=None):
        ldif = """
dn: """ + object_dn + """
objectClass: container
objectCategory: CN=Container,""" + self.schema_dn + """
showInAdvancedViewOnly: TRUE
instanceType: 4
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif)

    def create_configuration_specifier(self, _ldb, object_dn, desc=None):
        ldif = """
dn: """ + object_dn + """
objectClass: displaySpecifier
showInAdvancedViewOnly: TRUE
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif)

    def read_desc(self, object_dn, controls=None):
        res = self.ldb_admin.search(base=object_dn, scope=SCOPE_BASE, attrs=["nTSecurityDescriptor"], controls=controls)
        desc = res[0]["nTSecurityDescriptor"][0]
        return ndr_unpack(security.descriptor, desc)

    def create_active_user(self, _ldb, user_dn):
        ldif = """
dn: """ + user_dn + """
sAMAccountName: """ + user_dn.split(",")[0][3:] + """
objectClass: user
unicodePwd:: """ + base64.b64encode("\"samba123@\"".encode('utf-16-le')) + """
url: www.example.com
"""
        _ldb.add_ldif(ldif)

    def add_user_to_group(self, _ldb, username, groupname):
        ldif = """
dn: """ +  self.get_users_domain_dn(groupname) + """
changetype: modify
add: member
member: """ + self.get_users_domain_dn(username)
        _ldb.modify_ldif(ldif)

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        ldb_target = SamDB(url=host, credentials=creds_tmp, lp=lp)
        return ldb_target

    def get_object_sid(self, object_dn):
        res = self.ldb_admin.search(object_dn)
        return ndr_unpack( security.dom_sid, res[0]["objectSid"][0] )

    def dacl_add_ace(self, object_dn, ace):
        desc = self.read_desc( object_dn )
        desc_sddl = desc.as_sddl( self.domain_sid )
        if ace in desc_sddl:
            return
        if desc_sddl.find("(") >= 0:
            desc_sddl = desc_sddl[:desc_sddl.index("(")] + ace + desc_sddl[desc_sddl.index("("):]
        else:
            desc_sddl = desc_sddl + ace
        self.modify_desc(self.ldb_admin, object_dn, desc_sddl)

    def get_desc_sddl(self, object_dn, controls=None):
        """ Return object nTSecutiryDescriptor in SDDL format
        """
        desc = self.read_desc(object_dn, controls)
        return desc.as_sddl(self.domain_sid)

    def create_enable_user(self, username):
        user_dn = self.get_users_domain_dn(username)
        self.create_active_user(self.ldb_admin, user_dn)
        self.ldb_admin.enable_account("(sAMAccountName=" + username + ")")

    def setUp(self):
        super(DescriptorTests, self).setUp()
        self.ldb_admin = ldb
        self.base_dn = self.find_basedn(self.ldb_admin)
        self.configuration_dn = self.find_configurationdn(self.ldb_admin)
        self.schema_dn = self.find_schemadn(self.ldb_admin)
        self.domain_sid = self.find_domain_sid(self.ldb_admin)
        print "baseDN: %s" % self.base_dn

    ################################################################################################

    ## Tests for DOMAIN

    # Default descriptor tests #####################################################################

class OwnerGroupDescriptorTests(DescriptorTests):

    def deleteAll(self):
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser1"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser2"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser3"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser4"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser5"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser6"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser7"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser8"))
        # DOMAIN
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("test_domain_group1"))
        self.delete_force(self.ldb_admin, "CN=test_domain_user1,OU=test_domain_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_domain_ou2,OU=test_domain_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_domain_ou1," + self.base_dn)
        # SCHEMA
        # CONFIGURATION
        self.delete_force(self.ldb_admin, "CN=test-specifier1,CN=test-container1,CN=DisplaySpecifiers," \
                + self.configuration_dn)
        self.delete_force(self.ldb_admin, "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn)

    def setUp(self):
        super(OwnerGroupDescriptorTests, self).setUp()
        self.deleteAll()
            ### Create users
            # User 1
        self.create_enable_user("testuser1")
        self.add_user_to_group(self.ldb_admin, "testuser1", "Enterprise Admins")
            # User 2
        self.create_enable_user("testuser2")
        self.add_user_to_group(self.ldb_admin, "testuser2", "Domain Admins")
            # User 3
        self.create_enable_user("testuser3")
        self.add_user_to_group(self.ldb_admin, "testuser3", "Schema Admins")
            # User 4
        self.create_enable_user("testuser4")
            # User 5
        self.create_enable_user("testuser5")
        self.add_user_to_group(self.ldb_admin, "testuser5", "Enterprise Admins")
        self.add_user_to_group(self.ldb_admin, "testuser5", "Domain Admins")
            # User 6
        self.create_enable_user("testuser6")
        self.add_user_to_group(self.ldb_admin, "testuser6", "Enterprise Admins")
        self.add_user_to_group(self.ldb_admin, "testuser6", "Domain Admins")
        self.add_user_to_group(self.ldb_admin, "testuser6", "Schema Admins")
            # User 7
        self.create_enable_user("testuser7")
        self.add_user_to_group(self.ldb_admin, "testuser7", "Domain Admins")
        self.add_user_to_group(self.ldb_admin, "testuser7", "Schema Admins")
            # User 8
        self.create_enable_user("testuser8")
        self.add_user_to_group(self.ldb_admin, "testuser8", "Enterprise Admins")
        self.add_user_to_group(self.ldb_admin, "testuser8", "Schema Admins")

        self.results = {
            # msDS-Behavior-Version < DS_DOMAIN_FUNCTION_2008
            "ds_behavior_win2003" : {
                "100" : "O:EAG:DU",
                "101" : "O:DAG:DU",
                "102" : "O:%sG:DU",
                "103" : "O:%sG:DU",
                "104" : "O:DAG:DU",
                "105" : "O:DAG:DU",
                "106" : "O:DAG:DU",
                "107" : "O:EAG:DU",
                "108" : "O:DAG:DA",
                "109" : "O:DAG:DA",
                "110" : "O:%sG:DA",
                "111" : "O:%sG:DA",
                "112" : "O:DAG:DA",
                "113" : "O:DAG:DA",
                "114" : "O:DAG:DA",
                "115" : "O:DAG:DA",
                "130" : "O:EAG:DU",
                "131" : "O:DAG:DU",
                "132" : "O:SAG:DU",
                "133" : "O:%sG:DU",
                "134" : "O:EAG:DU",
                "135" : "O:SAG:DU",
                "136" : "O:SAG:DU",
                "137" : "O:SAG:DU",
                "138" : "O:DAG:DA",
                "139" : "O:DAG:DA",
                "140" : "O:%sG:DA",
                "141" : "O:%sG:DA",
                "142" : "O:DAG:DA",
                "143" : "O:DAG:DA",
                "144" : "O:DAG:DA",
                "145" : "O:DAG:DA",
                "160" : "O:EAG:DU",
                "161" : "O:DAG:DU",
                "162" : "O:%sG:DU",
                "163" : "O:%sG:DU",
                "164" : "O:EAG:DU",
                "165" : "O:EAG:DU",
                "166" : "O:DAG:DU",
                "167" : "O:EAG:DU",
                "168" : "O:DAG:DA",
                "169" : "O:DAG:DA",
                "170" : "O:%sG:DA",
                "171" : "O:%sG:DA",
                "172" : "O:DAG:DA",
                "173" : "O:DAG:DA",
                "174" : "O:DAG:DA",
                "175" : "O:DAG:DA",
            },
            # msDS-Behavior-Version >= DS_DOMAIN_FUNCTION_2008
            "ds_behavior_win2008" : {
                "100" : "O:EAG:EA",
                "101" : "O:DAG:DA",
                "102" : "O:%sG:DU",
                "103" : "O:%sG:DU",
                "104" : "O:DAG:DA",
                "105" : "O:DAG:DA",
                "106" : "O:DAG:DA",
                "107" : "O:EAG:EA",
                "108" : "O:DAG:DA",
                "109" : "O:DAG:DA",
                "110" : "O:%sG:DA",
                "111" : "O:%sG:DA",
                "112" : "O:DAG:DA",
                "113" : "O:DAG:DA",
                "114" : "O:DAG:DA",
                "115" : "O:DAG:DA",
                "130" : "O:EAG:EA",
                "131" : "O:DAG:DA",
                "132" : "O:SAG:SA",
                "133" : "O:%sG:DU",
                "134" : "O:EAG:EA",
                "135" : "O:SAG:SA",
                "136" : "O:SAG:SA",
                "137" : "O:SAG:SA",
                "138" : "",
                "139" : "",
                "140" : "O:%sG:DA",
                "141" : "O:%sG:DA",
                "142" : "",
                "143" : "",
                "144" : "",
                "145" : "",
                "160" : "O:EAG:EA",
                "161" : "O:DAG:DA",
                "162" : "O:%sG:DU",
                "163" : "O:%sG:DU",
                "164" : "O:EAG:EA",
                "165" : "O:EAG:EA",
                "166" : "O:DAG:DA",
                "167" : "O:EAG:EA",
                "168" : "O:DAG:DA",
                "169" : "O:DAG:DA",
                "170" : "O:%sG:DA",
                "171" : "O:%sG:DA",
                "172" : "O:DAG:DA",
                "173" : "O:DAG:DA",
                "174" : "O:DAG:DA",
                "175" : "O:DAG:DA",
            },
        }
        # Discover 'msDS-Behavior-Version'
        res = self.ldb_admin.search(base=self.base_dn, expression="distinguishedName=%s" % self.base_dn, \
                attrs=['msDS-Behavior-Version'])
        res = int(res[0]['msDS-Behavior-Version'][0])
        if res < DS_DOMAIN_FUNCTION_2008:
            self.DS_BEHAVIOR = "ds_behavior_win2003"
        else:
            self.DS_BEHAVIOR = "ds_behavior_win2008"

    def tearDown(self):
        super(DescriptorTests, self).tearDown()
        self.deleteAll()

    def check_user_belongs(self, user_dn, groups=[]):
        """ Test wether user is member of the expected group(s) """
        if groups != []:
            # User is member of at least one additional group
            res = self.ldb_admin.search(user_dn, attrs=["memberOf"])
            res = [x.upper() for x in sorted(list(res[0]["memberOf"]))]
            expected = []
            for x in groups:
                expected.append(self.get_users_domain_dn(x))
            expected = [x.upper() for x in sorted(expected)]
            self.assertEqual(expected, res)
        else:
            # User is not a member of any additional groups but default
            res = self.ldb_admin.search(user_dn, attrs=["*"])
            res = [x.upper() for x in res[0].keys()]
            self.assertFalse( "MEMBEROF" in res)

    def check_modify_inheritance(self, _ldb, object_dn, owner_group=""):
        # Modify
        ace = "(D;;CC;;;LG)" # Deny Create Children to Guest account
        if owner_group != "":
            self.modify_desc(_ldb, object_dn, owner_group + "D:" + ace)
        else:
            self.modify_desc(_ldb, object_dn, "D:" + ace)
        # Make sure the modify operation has been applied
        desc_sddl = self.get_desc_sddl(object_dn)
        self.assertTrue(ace in desc_sddl)
        # Make sure we have identical result for both "add" and "modify"
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        print self._testMethodName
        test_number = self._testMethodName[5:]
        self.assertEqual(self.results[self.DS_BEHAVIOR][test_number], res)

    def test_100(self):
        """ Enterprise admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_group(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_101(self):
        """ Domain admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_group(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_102(self):
        """ Schema admin group member with CC right creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;CI;WPWDCC;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_user(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        # This fails, research why
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_103(self):
        """ Regular user with CC right creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;CI;WPWDCC;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_user(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #this fails, research why
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_104(self):
        """ Enterprise & Domain admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_group(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_105(self):
        """ Enterprise & Domain & Schema admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_group(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_106(self):
        """ Domain & Schema admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_group(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_107(self):
        """ Enterprise & Schema admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_group(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    # Control descriptor tests #####################################################################

    def test_108(self):
        """ Enterprise admin group member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_domain_group(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_109(self):
        """ Domain admin group member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_domain_group(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_110(self):
        """ Schema admin group member with CC right creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;CI;WOWDCC;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_user(_ldb, object_dn, desc_sddl)
        desc = self.read_desc(object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_111(self):
        """ Regular user with CC right creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;CI;WOWDCC;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_user(_ldb, object_dn, desc_sddl)
        desc = self.read_desc(object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_112(self):
        """ Domain & Enterprise admin group member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_domain_group(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_113(self):
        """ Domain & Enterprise & Schema admin group  member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_domain_group(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_114(self):
        """ Domain & Schema admin group  member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_domain_group(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_115(self):
        """ Enterprise & Schema admin group  member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_domain_group(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_999(self):
        user_name = "Administrator"
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(D;CI;WP;;;S-1-3-0)"
        #mod = ""
        self.dacl_add_ace(object_dn, mod)
        desc_sddl = self.get_desc_sddl(object_dn)
        # Create additional object into the first one
        object_dn = "OU=test_domain_ou2," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)

    ## Tests for SCHEMA

    # Defalt descriptor tests ##################################################################

    def test_130(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_131(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_132(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        #self.check_modify_inheritance(_ldb, class_dn)

    def test_133(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        #Change Schema partition descriptor
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #self.check_modify_inheritance(_ldb, class_dn)

    def test_134(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        #Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_135(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_136(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_137(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    # Custom descriptor tests ##################################################################

    def test_138(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_139(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_140(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_141(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_142(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_143(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_144(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_145(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_name = self.get_unique_schema_class_name()
        class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
        self.create_schema_class(_ldb, class_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    ## Tests for CONFIGURATION

    # Defalt descriptor tests ##################################################################

    def test_160(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_161(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_162(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;;WDCC;;;AU)"
        self.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_specifier(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_163(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;CI;WDCC;;;AU)"
        self.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_specifier(_ldb, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_164(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_165(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_166(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_167(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    # Custom descriptor tests ##################################################################

    def test_168(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_169(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_170(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        self.create_configuration_specifier(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_171(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.get_object_sid( self.get_users_domain_dn(user_name) )
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        self.create_configuration_specifier(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_172(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_173(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_174(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_175(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        self.delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.get_desc_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    ########################################################################################
    # Inharitance tests for DACL

class DaclDescriptorTests(DescriptorTests):

    def deleteAll(self):
        self.delete_force(self.ldb_admin, "CN=test_inherit_group,OU=test_inherit_ou," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_inherit_ou," + self.base_dn)

    def setUp(self):
        super(DaclDescriptorTests, self).setUp()
        self.deleteAll()

    def create_clean_ou(self, object_dn):
        """ Base repeating setup for unittests to follow """
        res = self.ldb_admin.search(base=self.base_dn, scope=SCOPE_SUBTREE, \
                expression="distinguishedName=%s" % object_dn)
        # Make sure top testing OU has been deleted before starting the test
        self.assertEqual(res, [])
        self.create_domain_ou(self.ldb_admin, object_dn)
        desc_sddl = self.get_desc_sddl(object_dn)
        # Make sure there are inheritable ACEs initially
        self.assertTrue("CI" in desc_sddl or "OI" in desc_sddl)
        # Find and remove all inherit ACEs
        res = re.findall("\(.*?\)", desc_sddl)
        res = [x for x in res if ("CI" in x) or ("OI" in x)]
        for x in res:
            desc_sddl = desc_sddl.replace(x, "")
        # Add flag 'protected' in both DACL and SACL so no inherit ACEs
        # can propagate from above
        # remove SACL, we are not interested
        desc_sddl = desc_sddl.replace(":AI", ":AIP")
        self.modify_desc(self.ldb_admin, object_dn, desc_sddl)
        # Verify all inheritable ACEs are gone
        desc_sddl = self.get_desc_sddl(object_dn)
        self.assertFalse("CI" in desc_sddl)
        self.assertFalse("OI" in desc_sddl)

    def test_200(self):
        """ OU with protected flag and child group. See if the group has inherit ACEs.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn)
        # Make sure created group object contains NO inherit ACEs
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertFalse("ID" in desc_sddl)

    def test_201(self):
        """ OU with protected flag and no inherit ACEs, child group with custom descriptor.
            Verify group has custom and default ACEs only.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Create group child object using custom security descriptor
        sddl = "O:AUG:AUD:AI(D;;WP;;;DU)"
        self.create_domain_group(self.ldb_admin, group_dn, sddl)
        # Make sure created group descriptor has NO additional ACEs
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertEqual(desc_sddl, sddl)
        sddl = "O:AUG:AUD:AI(D;;CC;;;LG)"
        self.modify_desc(self.ldb_admin, group_dn, sddl)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertEqual(desc_sddl, sddl)

    def test_202(self):
        """ OU with protected flag and add couple non-inheritable ACEs, child group.
            See if the group has any of the added ACEs.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom non-inheritable ACEs
        mod = "(D;;WP;;;DU)(A;;RP;;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        # Verify all inheritable ACEs are gone
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn)
        # Make sure created group object contains NO inherit ACEs
        # also make sure the added above non-inheritable ACEs are absent too
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertFalse("ID" in desc_sddl)
        for x in re.findall("\(.*?\)", mod):
            self.assertFalse(x in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertFalse("ID" in desc_sddl)
        for x in re.findall("\(.*?\)", mod):
            self.assertFalse(x in desc_sddl)

    def test_203(self):
        """ OU with protected flag and add 'CI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "(D;CI;WP;;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        mod = mod.replace(";CI;", ";CIID;")
        self.assertTrue(mod in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue(mod in desc_sddl)

    def test_204(self):
        """ OU with protected flag and add 'OI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "(D;OI;WP;;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        mod = mod.replace(";OI;", ";OIIOID;") # change it how it's gonna look like
        self.assertTrue(mod in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" +moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue(mod in desc_sddl)

    def test_205(self):
        """ OU with protected flag and add 'OA' for GUID & 'CI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'name' attribute & 'CI' ACE
        mod = "(OA;CI;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        mod = mod.replace(";CI;", ";CIID;") # change it how it's gonna look like
        self.assertTrue(mod in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue(mod in desc_sddl)

    def test_206(self):
        """ OU with protected flag and add 'OA' for GUID & 'OI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'name' attribute & 'OI' ACE
        mod = "(OA;OI;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        mod = mod.replace(";OI;", ";OIIOID;") # change it how it's gonna look like
        self.assertTrue(mod in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue(mod in desc_sddl)

    def test_207(self):
        """ OU with protected flag and add 'OA' for OU specific GUID & 'CI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'st' attribute (OU specific) & 'CI' ACE
        mod = "(OA;CI;WP;bf967a39-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        mod = mod.replace(";CI;", ";CIID;") # change it how it's gonna look like
        self.assertTrue(mod in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue(mod in desc_sddl)

    def test_208(self):
        """ OU with protected flag and add 'OA' for OU specific GUID & 'OI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'st' attribute (OU specific) & 'OI' ACE
        mod = "(OA;OI;WP;bf967a39-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        mod = mod.replace(";OI;", ";OIIOID;") # change it how it's gonna look like
        self.assertTrue(mod in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:(OA;OI;WP;bf967a39-0de6-11d0-a285-00aa003049e2;;DU)" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue(mod in desc_sddl)

    def test_209(self):
        """ OU with protected flag and add 'CI' ACE with 'CO' SID, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "(D;CI;WP;;;CO)"
        moded = "(D;;CC;;;LG)"
        self.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.get_desc_sddl(ou_dn)
        # Create group child object
        self.create_domain_group(self.ldb_admin, group_dn, "O:AUG:AUD:AI(A;;CC;;;AU)")
        # Make sure created group object contains only the above inherited ACE(s)
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue("(D;ID;WP;;;AU)" in desc_sddl)
        self.assertTrue("(D;CIIOID;WP;;;CO)" in desc_sddl)
        self.modify_desc(self.ldb_admin, group_dn, "D:" + moded)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue(moded in desc_sddl)
        self.assertTrue("(D;ID;WP;;;DA)" in desc_sddl)
        self.assertTrue("(D;CIIOID;WP;;;CO)" in desc_sddl)

    def test_210(self):
        """ OU with protected flag, provide ACEs with ID flag raised. Should be ignored.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        self.create_clean_ou(ou_dn)
        # Add some custom  ACE
        mod = "D:(D;CIIO;WP;;;CO)(A;ID;WP;;;AU)"
        self.create_domain_group(self.ldb_admin, group_dn, mod)
        # Make sure created group object does not contain the ID ace
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertFalse("(A;ID;WP;;;AU)" in desc_sddl)

    def test_211(self):
        """ Provide ACE with CO SID, should be expanded and replaced
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "D:(D;CI;WP;;;CO)"
        self.create_domain_group(self.ldb_admin, group_dn, mod)
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue("(D;;WP;;;DA)(D;CIIO;WP;;;CO)" in desc_sddl)

    def test_212(self):
        """ Provide ACE with IO flag, should be ignored
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "D:(D;CIIO;WP;;;CO)"
        self.create_domain_group(self.ldb_admin, group_dn, mod)
        # Make sure created group object contains only the above inherited ACE(s)
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertTrue("(D;CIIO;WP;;;CO)" in desc_sddl)
        self.assertFalse("(D;;WP;;;DA)" in desc_sddl)
        self.assertFalse("(D;CIIO;WP;;;CO)(D;CIIO;WP;;;CO)" in desc_sddl)

    def test_213(self):
        """ Provide ACE with IO flag, should be ignored
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "D:(D;IO;WP;;;DA)"
        self.create_domain_group(self.ldb_admin, group_dn, mod)
        # Make sure created group object contains only the above inherited ACE(s)
        # that we've added manually
        desc_sddl = self.get_desc_sddl(group_dn)
        self.assertFalse("(D;IO;WP;;;DA)" in desc_sddl)

    ########################################################################################


class SdFlagsDescriptorTests(DescriptorTests):
    def deleteAll(self):
        self.delete_force(self.ldb_admin, "OU=test_sdflags_ou," + self.base_dn)

    def setUp(self):
        super(SdFlagsDescriptorTests, self).setUp()
        self.test_descr = "O:AUG:AUD:(D;;CC;;;LG)S:(OU;;WP;;;AU)"
        self.deleteAll()

    def test_301(self):
        """ Modify a descriptor with OWNER_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        self.modify_desc(self.ldb_admin, ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_OWNER)])
        desc_sddl = self.get_desc_sddl(ou_dn)
        # make sure we have modified the owner
        self.assertTrue("O:AU" in desc_sddl)
        # make sure nothing else has been modified
        self.assertFalse("G:AU" in desc_sddl)
        self.assertFalse("D:(D;;CC;;;LG)" in desc_sddl)
        self.assertFalse("(OU;;WP;;;AU)" in desc_sddl)

    def test_302(self):
        """ Modify a descriptor with GROUP_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        self.modify_desc(self.ldb_admin, ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_GROUP)])
        desc_sddl = self.get_desc_sddl(ou_dn)
        # make sure we have modified the group
        self.assertTrue("G:AU" in desc_sddl)
        # make sure nothing else has been modified
        self.assertFalse("O:AU" in desc_sddl)
        self.assertFalse("D:(D;;CC;;;LG)" in desc_sddl)
        self.assertFalse("(OU;;WP;;;AU)" in desc_sddl)

    def test_303(self):
        """ Modify a descriptor with SACL_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        self.modify_desc(self.ldb_admin, ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_DACL)])
        desc_sddl = self.get_desc_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertTrue("(D;;CC;;;LG)" in desc_sddl)
        # make sure nothing else has been modified
        self.assertFalse("O:AU" in desc_sddl)
        self.assertFalse("G:AU" in desc_sddl)
        self.assertFalse("(OU;;WP;;;AU)" in desc_sddl)

    def test_304(self):
        """ Modify a descriptor with SACL_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        self.modify_desc(self.ldb_admin, ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_SACL)])
        desc_sddl = self.get_desc_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertTrue("(OU;;WP;;;AU)" in desc_sddl)
        # make sure nothing else has been modified
        self.assertFalse("O:AU" in desc_sddl)
        self.assertFalse("G:AU" in desc_sddl)
        self.assertFalse("(D;;CC;;;LG)" in desc_sddl)

    def test_305(self):
        """ Modify a descriptor with 0x0 set.
            Contrary to logic this is interpreted as no control,
            which is the same as 0xF
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        self.modify_desc(self.ldb_admin, ou_dn, self.test_descr, controls=["sd_flags:1:0"])
        desc_sddl = self.get_desc_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertTrue("(OU;;WP;;;AU)" in desc_sddl)
        # make sure nothing else has been modified
        self.assertTrue("O:AU" in desc_sddl)
        self.assertTrue("G:AU" in desc_sddl)
        self.assertTrue("(D;;CC;;;LG)" in desc_sddl)

    def test_306(self):
        """ Modify a descriptor with 0xF set.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        self.modify_desc(self.ldb_admin, ou_dn, self.test_descr, controls=["sd_flags:1:15"])
        desc_sddl = self.get_desc_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertTrue("(OU;;WP;;;AU)" in desc_sddl)
        # make sure nothing else has been modified
        self.assertTrue("O:AU" in desc_sddl)
        self.assertTrue("G:AU" in desc_sddl)
        self.assertTrue("(D;;CC;;;LG)" in desc_sddl)

    def test_307(self):
        """ Read a descriptor with OWNER_SECURITY_INFORMATION
            Only the owner part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        desc_sddl = self.get_desc_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_OWNER)])
        # make sure we have read the owner
        self.assertTrue("O:" in desc_sddl)
        # make sure we have read nothing else
        self.assertFalse("G:" in desc_sddl)
        self.assertFalse("D:" in desc_sddl)
        self.assertFalse("S:" in desc_sddl)

    def test_308(self):
        """ Read a descriptor with GROUP_SECURITY_INFORMATION
            Only the group part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        desc_sddl = self.get_desc_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_GROUP)])
        # make sure we have read the owner
        self.assertTrue("G:" in desc_sddl)
        # make sure we have read nothing else
        self.assertFalse("O:" in desc_sddl)
        self.assertFalse("D:" in desc_sddl)
        self.assertFalse("S:" in desc_sddl)

    def test_309(self):
        """ Read a descriptor with SACL_SECURITY_INFORMATION
            Only the sacl part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        desc_sddl = self.get_desc_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_SACL)])
        # make sure we have read the owner
        self.assertTrue("S:" in desc_sddl)
        # make sure we have read nothing else
        self.assertFalse("O:" in desc_sddl)
        self.assertFalse("D:" in desc_sddl)
        self.assertFalse("G:" in desc_sddl)

    def test_310(self):
        """ Read a descriptor with DACL_SECURITY_INFORMATION
            Only the dacl part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.create_domain_ou(self.ldb_admin, ou_dn)
        desc_sddl = self.get_desc_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_DACL)])
        # make sure we have read the owner
        self.assertTrue("D:" in desc_sddl)
        # make sure we have read nothing else
        self.assertFalse("O:" in desc_sddl)
        self.assertFalse("S:" in desc_sddl)
        self.assertFalse("G:" in desc_sddl)


class RightsAttributesTests(DescriptorTests):

    def deleteAll(self):
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser_attr"))
        self.delete_force(self.ldb_admin, self.get_users_domain_dn("testuser_attr2"))
        self.delete_force(self.ldb_admin, "OU=test_domain_ou1," + self.base_dn)

    def setUp(self):
        super(RightsAttributesTests, self).setUp()
        self.deleteAll()
            ### Create users
            # User 1
        self.create_enable_user("testuser_attr")
        # User 2, Domain Admins
        self.create_enable_user("testuser_attr2")
        self.add_user_to_group(self.ldb_admin, "testuser_attr2", "Domain Admins")

    def test_sDRightsEffective(self):
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        print self.get_users_domain_dn("testuser_attr")
        user_sid = self.get_object_sid(self.get_users_domain_dn("testuser_attr"))
        #give testuser1 read access so attributes can be retrieved
        mod = "(A;CI;RP;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        _ldb = self.get_ldb_connection("testuser_attr", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["sDRightsEffective"])
        #user whould have no rights at all
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["sDRightsEffective"][0], "0")
        #give the user Write DACL and see what happens
        mod = "(A;CI;WD;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["sDRightsEffective"])
        #user whould have DACL_SECURITY_INFORMATION
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["sDRightsEffective"][0], ("%d") % SECINFO_DACL)
        #give the user Write Owners and see what happens
        mod = "(A;CI;WO;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["sDRightsEffective"])
        #user whould have DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["sDRightsEffective"][0], ("%d") % (SECINFO_DACL | SECINFO_GROUP | SECINFO_OWNER))
        #no way to grant security privilege bu adding ACE's so we use a memeber of Domain Admins
        _ldb = self.get_ldb_connection("testuser_attr2", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["sDRightsEffective"])
        #user whould have DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION
        self.assertEquals(len(res), 1)
        self.assertEquals(res[0]["sDRightsEffective"][0], \
                          ("%d") % (SECINFO_DACL | SECINFO_GROUP | SECINFO_OWNER | SECINFO_SACL))

    def test_allowedChildClassesEffective(self):
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid(self.get_users_domain_dn("testuser_attr"))
        #give testuser1 read access so attributes can be retrieved
        mod = "(A;CI;RP;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        _ldb = self.get_ldb_connection("testuser_attr", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["allowedChildClassesEffective"])
        #there should be no allowed child classes
        self.assertEquals(len(res), 1)
        self.assertFalse("allowedChildClassesEffective" in res[0].keys())
        #give the user the right to create children of type user
        mod = "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["allowedChildClassesEffective"])
        # allowedChildClassesEffective should only have one value, user
        self.assertEquals(len(res), 1)
        self.assertEquals(len(res[0]["allowedChildClassesEffective"]), 1)
        self.assertEquals(res[0]["allowedChildClassesEffective"][0], "user")

    def test_allowedAttributesEffective(self):
        object_dn = "OU=test_domain_ou1," + self.base_dn
        self.delete_force(self.ldb_admin, object_dn)
        self.create_domain_ou(self.ldb_admin, object_dn)
        user_sid = self.get_object_sid(self.get_users_domain_dn("testuser_attr"))
        #give testuser1 read access so attributes can be retrieved
        mod = "(A;CI;RP;;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod)
        _ldb = self.get_ldb_connection("testuser_attr", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["allowedAttributesEffective"])
        #there should be no allowed attributes
        self.assertEquals(len(res), 1)
        self.assertFalse("allowedAttributesEffective" in res[0].keys())
        #give the user the right to write displayName and managedBy
        mod2 = "(OA;CI;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        mod = "(OA;CI;WP;0296c120-40da-11d1-a9c0-0000f80367c1;;%s)" % str(user_sid)
        # also rights to modify an read only attribute, fromEntry
        mod3 = "(OA;CI;WP;9a7ad949-ca53-11d1-bbd0-0080c76670c0;;%s)" % str(user_sid)
        self.dacl_add_ace(object_dn, mod + mod2 + mod3)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                         attrs=["allowedAttributesEffective"])
        # value should only contain user and managedBy
        self.assertEquals(len(res), 1)
        self.assertEquals(len(res[0]["allowedAttributesEffective"]), 2)
        self.assertTrue("displayName" in res[0]["allowedAttributesEffective"])
        self.assertTrue("managedBy" in res[0]["allowedAttributesEffective"])

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = SamDB(host, credentials=creds, session_info=system_session(), lp=lp, options=["modules:paged_searches"])

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(OwnerGroupDescriptorTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(DaclDescriptorTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(SdFlagsDescriptorTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(RightsAttributesTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
