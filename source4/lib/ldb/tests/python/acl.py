#!/usr/bin/python
# -*- coding: utf-8 -*-
# This is unit with PPD tests

import getopt
import optparse
import sys
import os
import base64
import re

sys.path.append("bin/python")
sys.path.append("../lib/subunit/python")

import samba.getopt as options

# Some error messages that are being tested
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT, ERR_INVALID_DN_SYNTAX, ERR_UNWILLING_TO_PERFORM
from ldb import ERR_INSUFFICIENT_ACCESS_RIGHTS

# For running the test unit
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

from samba.auth import system_session
from samba import Ldb
from subunit import SubunitTestRunner
import unittest

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

#
# Tests start here
#

class AclTests(unittest.TestCase):

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

    def find_domain_sid(self, ldb):
        res = ldb.search(base=self.base_dn, expression="(objectClass=*)", scope=SCOPE_BASE)
        return ndr_unpack( security.dom_sid,res[0]["objectSid"][0])

    def setUp(self):
        self.ldb_admin = ldb
        self.base_dn = self.find_basedn(self.ldb_admin)
        self.domain_sid = self.find_domain_sid(self.ldb_admin)
        print "baseDN: %s" % self.base_dn
        self.SAMBA = False; self.WIN = False
        res = self.ldb_admin.search(base="",expression="", scope=SCOPE_BASE,
                                    attrs=["vendorName"])
        if res and "vendorName" in res[0].keys() and res[0]["vendorName"][0].find("Samba Team") != -1:
            self.SAMBA = True
        else:
            self.WIN = True
        if self.WIN:
            # Modify acluser1 & acluser2 to be excluded from 'Doamin Admin' group
            try:
                ldif = """
dn: CN=Domain Admins,CN=Users,""" + self.base_dn + """
changetype: modify
delete: member
member: """ + self.get_user_dn("acluser1")
                self.ldb_admin.modify_ldif(ldif)
                ldif = """
dn: CN=Domain Admins,CN=Users,""" + self.base_dn + """
changetype: modify
delete: member
member: """ + self.get_user_dn("acluser2")
                self.ldb_admin.modify_ldif(ldif)
            except LdbError, (num, _):
                self.assertEquals(num, ERR_UNWILLING_TO_PERFORM) # LDAP_ENTRY_ALREADY_EXISTS

    def tearDown(self):
        # Add
        self.delete_force(self.ldb_admin, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_add_ou1," + self.base_dn)
        # Modify
        self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        # Search
        self.delete_force(self.ldb_admin, "CN=test_search_user1,OU=test_search_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_search_ou1," + self.base_dn)
        # Delete
        self.delete_force(self.ldb_admin, self.get_user_dn("test_delete_user1"))
        # Rename OU3
        self.delete_force(self.ldb_admin, "CN=test_rename_user1,OU=test_rename_ou3,OU=test_rename_ou2," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_rename_user2,OU=test_rename_ou3,OU=test_rename_ou2," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_rename_user5,OU=test_rename_ou3,OU=test_rename_ou2," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_rename_ou3,OU=test_rename_ou2," + self.base_dn)
        # Rename OU2
        self.delete_force(self.ldb_admin, "CN=test_rename_user1,OU=test_rename_ou2," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_rename_user2,OU=test_rename_ou2," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_rename_user5,OU=test_rename_ou2," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_rename_ou2," + self.base_dn)
        # Rename OU1
        self.delete_force(self.ldb_admin, "CN=test_rename_user1,OU=test_rename_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_rename_user2,OU=test_rename_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_rename_user5,OU=test_rename_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_rename_ou1," + self.base_dn)

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def modify_desc(self, object_dn, desc):
        """ Modify security descriptor using either SDDL string
            or security.descriptor object
        """	
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
        self.ldb_admin.modify_ldif(mod)
        return
        # Everything below is used in case of emergency or 
        # double modify verification of some sort
        assert(isinstance(desc, security.descriptor))
        fn = "/tmp/tmpMod"
        f = open(fn, "w"); f.write(mod); f.close()
        cmd = "ldapmodify -x -h %s -D %s -w %s -f %s" \
                % (host[7:], self.get_user_dn(creds.get_username()), creds.get_password(), fn)
        return os.system( cmd ) == 0

    def add_group_member(self, _ldb, group_dn, member_dn):
        """ Modify user to ge member of a group 
            e.g. User to be 'Doamin Admin' group member
        """
        ldif = """
dn: """ + group_dn + """
changetype: add
member: """ + member_dn
        _ldb.modify_ldif(ldif)
    
    def create_ou(self, _ldb, ou_dn, desc=None):
        ou_dict = {
            "dn" : ou_dn,
            "ou" : ou_dn.split(",")[0][3:],
            "objectClass" : "organizationalUnit",
            "url" : "www.bbc.co.uk",
        }
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add(ou_dict)

    def create_user(self, _ldb, user_dn, desc=None):
        user_dict = {
            "dn" : user_dn,
            "sAMAccountName" : user_dn.split(",")[0][3:],
            "objectClass" : "user",
            "userPassword" : "samba123@",
            "url" : "www.bbc.co.uk",
        }
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add(user_dict)

    def create_group(self, _ldb, group_dn, desc=None):
        group_dict = {
            "dn" : group_dn,
            "objectClass" : "group",
            "sAMAccountName" : group_dn.split(",")[0][3:],
            "groupType" : "4",
            "url" : "www.bbc.co.uk",
        }
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add(group_dict)

    def read_desc(self, object_dn):
        res = self.ldb_admin.search(object_dn, SCOPE_BASE, None, ["nTSecurityDescriptor"])
        desc = res[0]["nTSecurityDescriptor"][0]
        return ndr_unpack( security.descriptor, desc )

    def enable_account(self,  user_dn):
        """Enable an account.
        :param user_dn: Dn of the account to enable.
        """
        res = self.ldb_admin.search(user_dn, SCOPE_BASE, None, ["userAccountControl"])
        assert len(res) == 1
        userAccountControl = res[0]["userAccountControl"][0]
        userAccountControl = int(userAccountControl)
        if (userAccountControl & 0x2):
            userAccountControl = userAccountControl & ~0x2 # remove disabled bit
        if (userAccountControl & 0x20):
            userAccountControl = userAccountControl & ~0x20 # remove 'no password required' bit
        mod = """
dn: """ + user_dn + """
changetype: modify
replace: userAccountControl
userAccountControl: %s""" % userAccountControl
        if self.WIN:
            mod = re.sub("userAccountControl: \d.*", "userAccountControl: 544", mod)
        self.ldb_admin.modify_ldif(mod)

    def get_ldb_connection(self, target_username, target_password):
        username_save = creds.get_username(); password_save = creds.get_password()
        creds.set_username(target_username)
        creds.set_password(target_password)
        ldb_target = Ldb(host, credentials=creds, session_info=system_session(), lp=lp)
        creds.set_username(username_save); creds.set_password(password_save)
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
        self.modify_desc(object_dn, desc_sddl)

    def get_desc_sddl(self, object_dn):
        """ Return object nTSecutiryDescriptor in SDDL format
        """
        desc = self.read_desc(object_dn)
        return desc.as_sddl(self.domain_sid)
    
    # Testing section

    def test_add_domainadmin_notowner(self):
        """ 1 Testing OU with the rights of Doman Admin not creator of the OU """
        # Creating simple user
        if self.SAMBA:
            # Create domain admin that will be creator of OU parent-child structure
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
            # Create second domain admin that will not be creator of OU parent-child structure
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser2"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser2"))
            self.enable_account(self.get_user_dn("acluser2"))
        # Test if we have any additional groups for users than default ones
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser2") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Modify acluser1 & acluser2 to be 'Doamin Admin' group member
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn("acluser1"))
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn("acluser2"))
        # Create LDAP connection with OUs crator domain admin credentials
        ldb_owner = self.get_ldb_connection("acluser1", "samba123@")
        # Create LDAP connection with second domain admin credentials that is not creator of the OUs
        ldb_notowner = self.get_ldb_connection("acluser2", "samba123@")
        # Make sure top OU is deleted (and so everything under it)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [] )
        # Change descriptor for top level OU
        self.create_ou(ldb_owner, "OU=test_add_ou1," + self.base_dn)
        self.create_ou(ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        user_sid = self.get_object_sid(self.get_user_dn("acluser2"))
        mod = "(D;CI;WPCC;;;%s)" % str(user_sid)
        self.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Test user and group creation with another domain admin's credentials
        self.create_user(ldb_notowner, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.create_group(ldb_notowner, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Make sure we HAVE created the two objects -- user and group
        # !!! We should not be able to do that, but however beacuse of ACE ordering our inherited Deny ACE
        # !!! comes after explicit (A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA) that comes from somewhere
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )

    def test_add_regular_user(self):
        """ 2 Testing OU with the regular user that has no rights granted over the OU """
        # Creating simple user
        if self.SAMBA:
            # Create domain admin that will be creator of OU parent-child structure
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
            # Create regular user that will not be creator of OU parent-child structure
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser2"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser2"))
            self.enable_account(self.get_user_dn("acluser2"))
        # Test if we have any additional groups for users than default ones
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser2") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Modify acluser1 to be 'Doamin Admin' group member
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn("acluser1"))
        # Create LDAP connection with OUs crator domain admin credentials
        ldb_owner = self.get_ldb_connection("acluser1", "samba123@")
        # Create LDAP connection with a regular user that has the right 'Crate child User objects'
        ldb_user = self.get_ldb_connection("acluser2", "samba123@")
        # Make sure top OU is deleted (and so everything under it)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [] )
        # Create a parent-child OU structure with domain admin credentials
        self.create_ou(ldb_owner, "OU=test_add_ou1," + self.base_dn)
        self.create_ou(ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Test user and group creation with regular user credentials
        try:
            self.create_user(ldb_user, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
            self.create_group(ldb_user, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        # Make sure we HAVEN'T created any of two objects -- user or group
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [])
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [])
 
# ace is not inherited - filered out...

    def test_add_granted_user(self):
        """ 3 Testing OU with the rights of regular user granted the right 'Create User child objects' """
        # Creating simple user
        if self.SAMBA:
            # Create domain admin that will be creator of OU parent-child structure
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
            # Create second domain admin that will not be creator of OU parent-child structure
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser2"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser2"))
            self.enable_account(self.get_user_dn("acluser2"))
        # Test if we have any additional groups for users than default ones
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser2") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Modify acluser1 to be 'Doamin Admin' group member
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn("acluser1"))
        # Create LDAP connection with OUs crator domain admin credentials
        ldb_owner = self.get_ldb_connection("acluser1", "samba123@")
        # Create LDAP connection with a regular user that has the right 'Crate child User objects'
        ldb_guser = self.get_ldb_connection("acluser2", "samba123@")
        # Make sure top OU is deleted (and so everything under it)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [] )
        # Change descriptor for top level OU
        self.create_ou(ldb_owner, "OU=test_add_ou1," + self.base_dn)
        user_sid = self.get_object_sid(self.get_user_dn("acluser2"))
        mod = "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        self.create_ou(ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Test user and group creation with granted user only to one of the objects
        self.create_user(ldb_guser, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        try:
            self.create_group(ldb_guser, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        # Make sure we HAVE created the one of two objects -- user
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertNotEqual( len(res), 0 )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [])

    def test_add_domainadmin_owner(self):
        """ 4 Testing OU with the rights of Doman Admin creator of the OU"""
        # Creating acluser1
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Test if we have any additional groups for user than default
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Modify acluser1 to be 'Doamin Admin' group member
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn("acluser1"))
        # Create LDAP connection with OUs crator domain admin credentials
        ldb_owner = self.get_ldb_connection("acluser1", "samba123@")
        # Make sure top OU is deleted (and so everything under it)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [] )
        self.create_ou(ldb_owner, "OU=test_add_ou1," + self.base_dn)
        self.create_ou(ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.create_user(ldb_owner, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.create_group(ldb_owner, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Make sure we have successfully created the two objects -- user and group
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )

    def test_modify_u1(self):
        """5 Modify one attribute if you have DS_WRITE_PROPERTY for it"""
        # Creating acluser1
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))

        # Test if we have any additional groups for user than default
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # First test object -- User
        print "Testing modify on User object"
        self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.create_user(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        user_sid = self.get_object_sid( self.get_user_dn("acluser1") )
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace(self.get_user_dn("test_modify_user1"), mod)
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: displayName
displayName: test_changed"""
        ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % self.get_user_dn("test_modify_user1") )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Second test object -- Group
        print "Testing modify on Group object"
        self.delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.create_group(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        user_sid = self.get_object_sid( self.get_user_dn("acluser1") )
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace("CN=test_modify_group1,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % str("CN=test_modify_group1,CN=Users," + self.base_dn) )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Second test object -- Organizational Unit
        print "Testing modify on OU object"
        self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.create_ou(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        user_sid = self.get_object_sid( self.get_user_dn("acluser1") )
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace("OU=test_modify_ou1," + self.base_dn, mod)
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % str("OU=test_modify_ou1," + self.base_dn) )
        self.assertEqual(res[0]["displayName"][0], "test_changed")

    def test_modify_u2(self):
        """6 Modify two attributes as you have DS_WRITE_PROPERTY granted only for one of them"""
        # Creating acluser1
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Test if we have any additional groups for user than default
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # First test object -- User
        print "Testing modify on User object"
        self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.create_user(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        user_sid = self.get_object_sid( self.get_user_dn("acluser1") )
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace(self.get_user_dn("test_modify_user1"), mod)
        # Modify on attribute you have rights for
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: displayName
displayName: test_changed"""
        ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % self.get_user_dn("test_modify_user1") )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Second test object -- Group
        print "Testing modify on Group object"
        self.delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.create_group(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        user_sid = self.get_object_sid( self.get_user_dn("acluser1") )
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace("CN=test_modify_group1,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % str("CN=test_modify_group1,CN=Users," + self.base_dn) )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Second test object -- Organizational Unit
        print "Testing modify on OU object"
        self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.create_ou(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        user_sid = self.get_object_sid( self.get_user_dn("acluser1") )
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace("OU=test_modify_ou1," + self.base_dn, mod)
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % str("OU=test_modify_ou1," + self.base_dn) )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

    def test_modify_u3(self):
        """7 Modify one attribute as you have no what so ever rights granted"""
        # Creating acluser1
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))

        # Test if we have any additional groups for user than default
        if self.WIN:
            res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                    % self.get_user_dn("acluser1") )
            try:
                self.assertEqual( res[0]["memberOf"][0], "" )
            except KeyError:
                pass
            else:
                self.fail()
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")

        # First test object -- User
        print "Testing modify on User object"
        self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.create_user(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        # Second test object -- Group
        print "Testing modify on Group object"
        self.delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.create_group(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        # Second test object -- Organizational Unit
        print "Testing modify on OU object"
        self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.create_ou(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

#enable these when we have search implemented
    def _test_search_u1(self):
        """See if can prohibit user to read another User object"""
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        ou_dn = "OU=test_search_ou1," + self.base_dn
        user_dn = "CN=test_search_user1," + ou_dn
        # Create clean OU
        self.delete_force(self.ldb_admin, ou_dn)
        self.create_ou(self.ldb_admin, ou_dn)
        desc = self.read_desc( ou_dn )
        desc_sddl = desc.as_sddl( self.domain_sid )
        # Parse descriptor's SDDL and remove all inherited ACEs reffering
        # to 'Registered Users' or 'Authenticated Users'
        desc_aces = re.findall("\(.*?\)", desc_sddl)
        for ace in desc_aces:
            if ("I" in ace) and (("RU" in ace) or ("AU" in ace)):
                desc_sddl = desc_sddl.replace(ace, "")
        # Add 'P' in the DACL so it breaks further inheritance
        desc_sddl = desc_sddl.replace("D:AI(", "D:PAI(")
        # Create a security descriptor object and OU with that descriptor
        desc = security.descriptor.from_sddl( desc_sddl, self.domain_sid )
        self.delete_force(self.ldb_admin, ou_dn)
        self.create_ou(self.ldb_admin, ou_dn, desc)
        # Create clean user
        self.delete_force(self.ldb_admin, user_dn)
        self.create_user(self.ldb_admin, user_dn)
        desc = self.read_desc( user_dn )
        desc_sddl = desc.as_sddl( self.domain_sid )
        # Parse security descriptor SDDL and remove all 'Read' ACEs
        # reffering to AU
        desc_aces = re.findall("\(.*?\)", desc_sddl)
        for ace in desc_aces:
            if ("AU" in ace) and ("R" in ace):
                desc_sddl = desc_sddl.replace(ace, "")
        # Create user with the edited descriptor
        desc = security.descriptor.from_sddl( desc_sddl, self.domain_sid )
        self.delete_force(self.ldb_admin, user_dn)
        self.create_user(self.ldb_admin, user_dn, desc)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        res = ldb_user.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % user_dn )
        self.assertEqual( res, [] )

    def _test_search_u2(self):
        """User's group ACEs cleared and after that granted RIGHT_DS_READ_PROPERTY to another User object"""
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        ou_dn = "OU=test_search_ou1," + self.base_dn
        user_dn = "CN=test_search_user1," + ou_dn
        # Create clean OU
        self.delete_force(self.ldb_admin, ou_dn)
        self.create_ou(self.ldb_admin, ou_dn)
        desc = self.read_desc( ou_dn )
        desc_sddl = desc.as_sddl( self.domain_sid )
        # Parse descriptor's SDDL and remove all inherited ACEs reffering
        # to 'Registered Users' or 'Authenticated Users'
        desc_aces = re.findall("\(.*?\)", desc_sddl)
        for ace in desc_aces:
            if ("I" in ace) and (("RU" in ace) or ("AU" in ace)):
                desc_sddl = desc_sddl.replace(ace, "")
        # Add 'P' in the DACL so it breaks further inheritance
        desc_sddl = desc_sddl.replace("D:AI(", "D:PAI(")
        # Create a security descriptor object and OU with that descriptor
        desc = security.descriptor.from_sddl( desc_sddl, self.domain_sid )
        self.delete_force(self.ldb_admin, ou_dn)
        self.create_ou(self.ldb_admin, ou_dn, desc)
        # Create clean user
        self.delete_force(self.ldb_admin, user_dn)
        self.create_user(self.ldb_admin, user_dn)
        # Parse security descriptor SDDL and remove all 'Read' ACEs
        # reffering to AU
        desc_aces = re.findall("\(.*?\)", desc_sddl)
        for ace in desc_aces:
            if ("AU" in ace) and ("R" in ace):
                desc_sddl = desc_sddl.replace(ace, "")
        #mod = "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)"
        mod = "(A;;RP;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        res = ldb_user.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % user_dn )
        self.assertNotEqual( res, [] )

    def test_delete_u1(self):
        """User is prohibited by default to delete another User object"""
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Create user that we try to delete
        self.delete_force(self.ldb_admin, self.get_user_dn("test_delete_user"))
        self.create_user(self.ldb_admin, self.get_user_dn("test_delete_user"))
        # Here delete User object should ALWAYS through exception
        try:
            ldb_user.delete(self.get_user_dn("test_delete_user"))
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_delete_u2(self):
        """User's group has RIGHT_DELETE to another User object"""
        user_dn = self.get_user_dn("test_delete_user1")
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Create user that we try to delete
        self.delete_force(self.ldb_admin, user_dn)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;SD;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        # Try to delete User object
        ldb_user.delete( user_dn )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )

    def test_delete_u3(self):
        """User indentified by SID has RIGHT_DELETE to another User object"""
        user_dn = self.get_user_dn("test_delete_user1")
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Create user that we try to delete
        self.delete_force(self.ldb_admin, user_dn)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;SD;;;%s)" % str( self.get_object_sid(self.get_user_dn("acluser1")) )
        self.dacl_add_ace(user_dn, mod)
        # Try to delete User object
        ldb_user.delete( user_dn )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )

    def test_rename_u1(self):
        """ 6 Regular user fails to rename 'User object' within single OU"""
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Create OU structure
        self.create_ou(self.ldb_admin, "OU=test_rename_ou1," + self.base_dn)
        self.create_user(self.ldb_admin, "CN=test_rename_user1,OU=test_rename_ou1," + self.base_dn)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        try:
            ldb_user.rename("CN=test_rename_user1,OU=test_rename_ou1," + self.base_dn, \
                    "CN=test_rename_user5,OU=test_rename_ou1," + self.base_dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_rename_u2(self):
        """ 7 Grant WRITE_PROPERTY to AU so regular user can rename 'User object' within single OU"""
        ou_dn = "OU=test_rename_ou1," + self.base_dn
        user_dn = "CN=test_rename_user1," + ou_dn
        rename_user_dn = "CN=test_rename_user5," + ou_dn
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        print "Test rename with rights granted to AU"
        # Create OU structure
        self.create_ou(self.ldb_admin, ou_dn)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;WP;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Rename 'User object' having WP to AU
        ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )
        print "Test rename with rights granted to 'User object' SID"
        # Create OU structure
        self.delete_force(self.ldb_admin, user_dn)
        self.delete_force(self.ldb_admin, rename_user_dn)
        self.delete_force(self.ldb_admin, ou_dn)
        self.create_ou(self.ldb_admin, ou_dn)
        self.create_user(self.ldb_admin, user_dn)
        sid = self.get_object_sid(self.get_user_dn("acluser1"))
        mod = "(A;;WP;;;%s)" % str(sid)
        self.dacl_add_ace(user_dn, mod)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Rename 'User object' having WP to AU
        ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u3(self):
        """ 8 Rename 'User object' cross OU with WP, SD and CC right granted on reg. user to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou2_dn
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        print "Test rename with rights granted to AU"
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;WPSD;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(ou2_dn, mod)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Rename 'User object' having SD and CC to AU
        ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )
        print "Test rename with rights granted to 'User object' SID"
        # Create OU structure
        self.delete_force(self.ldb_admin, user_dn)
        self.delete_force(self.ldb_admin, rename_user_dn)
        self.delete_force(self.ldb_admin, ou1_dn)
        self.delete_force(self.ldb_admin, ou2_dn)
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        self.create_user(self.ldb_admin, user_dn)
        sid = self.get_object_sid(self.get_user_dn("acluser1"))
        mod = "(A;;WPSD;;;%s)" % str(sid)
        self.dacl_add_ace(user_dn, mod)
        mod = "(A;;CC;;;%s)" % str(sid)
        self.dacl_add_ace(ou2_dn, mod)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Rename 'User object' having SD and CC to AU
        ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u4(self):
        """9 Rename 'User object' cross OU with WP, DC and CC right granted on OU & user to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user2," + ou2_dn
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        #mod = "(A;CI;DCWP;;;AU)"
        mod = "(A;;DC;;;AU)"
        self.dacl_add_ace(ou1_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(ou2_dn, mod)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;WP;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Rename 'User object' having SD and CC to AU
        ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u5(self):
        """10 Rename 'User object' cross OU (second level) with WP, DC and CC right granted on OU to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        ou3_dn = "OU=test_rename_ou3," + ou2_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou3_dn
        # Creating simple user to search with
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn("acluser1"))
            self.create_user(self.ldb_admin, self.get_user_dn("acluser1"))
            self.enable_account(self.get_user_dn("acluser1"))
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        self.create_ou(self.ldb_admin, ou3_dn)
        mod = "(A;CI;WPDC;;;AU)"
        self.dacl_add_ace(ou1_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(ou3_dn, mod)
        self.create_user(self.ldb_admin, user_dn)
        # Create user connectiona that we will test with
        ldb_user = self.get_ldb_connection("acluser1", "samba123@")
        # Rename 'User object' having SD and CC to AU
        ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

# Important unit running information

if not "://" in host:
    host = "ldap://%s" % host
ldb = Ldb(host, credentials=creds, session_info=system_session(), lp=lp)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(AclTests)).wasSuccessful():
    rc = 1

sys.exit(rc)
