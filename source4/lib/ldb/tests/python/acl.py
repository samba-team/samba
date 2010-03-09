#!/usr/bin/python
# -*- coding: utf-8 -*-
# This is unit with tests for LDAP access checks

import getopt
import optparse
import sys
import os
import base64
import re

sys.path.append("bin/python")

import samba.getopt as options

from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError
from ldb import ERR_NO_SUCH_OBJECT, ERR_INVALID_DN_SYNTAX, ERR_UNWILLING_TO_PERFORM
from ldb import ERR_INSUFFICIENT_ACCESS_RIGHTS

from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

from samba.auth import system_session
from samba import Ldb
from subunit.run import SubunitTestRunner
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
        self.user_pass = "samba123@"
        print "baseDN: %s" % self.base_dn
        self.SAMBA = False; self.WIN = False
        res = self.ldb_admin.search(base="",expression="", scope=SCOPE_BASE,
                                    attrs=["vendorName"])
        if res and "vendorName" in res[0].keys() and res[0]["vendorName"][0].find("Samba Team") != -1:
            self.SAMBA = True
        else:
            self.WIN = True

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
changetype: modify
add: member
member: """ + member_dn
        _ldb.modify_ldif(ldif)
    
    def create_ou(self, _ldb, ou_dn, desc=None):
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
        _ldb.add_ldif(ldif)

    def create_user(self, _ldb, user_dn, desc=None):
        ldif = """
dn: """ + user_dn + """
sAMAccountName: """ + user_dn.split(",")[0][3:] + """
objectClass: user
userPassword: """ + self.user_pass + """
url: www.example.com
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc))
        _ldb.add_ldif(ldif)

    def create_group(self, _ldb, group_dn, desc=None):
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

    def get_ldb_connection(self, target_username):
        username_save = creds.get_username(); password_save = creds.get_password()
        creds.set_username(target_username)
        creds.set_password(self.user_pass)
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

    # Test if we have any additional groups for users than default ones
    def assert_user_no_group_member(self, username):
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                         % self.get_user_dn(username) )
        try:
            self.assertEqual( res[0]["memberOf"][0], "" )
        except KeyError:
            pass
        else:
            self.fail()
    
    def create_enable_user(self, username):
        self.create_user(self.ldb_admin, self.get_user_dn(username))
        self.enable_account(self.get_user_dn(username))

#tests on ldap add operations
class AclAddTests(AclTests):
    def setUp(self):
        AclTests.setUp(self)
        # Domain admin that will be creator of OU parent-child structure
        self.usr_admin_owner = "acl_add_user1"
        # Second domain admin that will not be creator of OU parent-child structure
        self.usr_admin_not_owner = "acl_add_user2"
        # Regular user
        self.regular_user = "acl_add_user3"
        if self.SAMBA:
            self.create_enable_user(self.usr_admin_owner)
            self.create_enable_user(self.usr_admin_not_owner)
            self.create_enable_user(self.regular_user)

        if self.WIN:
            self.assert_user_no_group_member(self.usr_admin_owner)
            self.assert_user_no_group_member(self.usr_admin_not_owner)
            self.assert_user_no_group_member(self.regular_user)

        # add admins to the Domain Admins group
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn(self.usr_admin_owner))
        self.add_group_member(self.ldb_admin, "CN=Domain Admins,CN=Users," + self.base_dn, \
                self.get_user_dn(self.usr_admin_not_owner))

        self.ldb_owner = self.get_ldb_connection(self.usr_admin_owner)
        self.ldb_notowner = self.get_ldb_connection(self.usr_admin_not_owner)
        self.ldb_user = self.get_ldb_connection(self.regular_user)

    def tearDown(self):
        self.delete_force(self.ldb_admin, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_add_ou1," + self.base_dn)
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn(self.usr_admin_owner))
            self.delete_force(self.ldb_admin, self.get_user_dn(self.usr_admin_not_owner))
            self.delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))

    # Make sure top OU is deleted (and so everything under it)
    def assert_top_ou_deleted(self):
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("OU=test_add_ou1", self.base_dn) )
        self.assertEqual( res, [] )

    def test_add_u1(self):
        """Testing OU with the rights of Doman Admin not creator of the OU """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.create_ou(self.ldb_owner, "OU=test_add_ou1," + self.base_dn)
        self.create_ou(self.ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        user_sid = self.get_object_sid(self.get_user_dn(self.usr_admin_not_owner))
        mod = "(D;CI;WPCC;;;%s)" % str(user_sid)
        self.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Test user and group creation with another domain admin's credentials
        self.create_user(self.ldb_notowner, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.create_group(self.ldb_notowner, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Make sure we HAVE created the two objects -- user and group
        # !!! We should not be able to do that, but however beacuse of ACE ordering our inherited Deny ACE
        # !!! comes after explicit (A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA) that comes from somewhere
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )

    def test_add_u2(self):
        """Testing OU with the regular user that has no rights granted over the OU """
        self.assert_top_ou_deleted()
        # Create a parent-child OU structure with domain admin credentials
        self.create_ou(self.ldb_owner, "OU=test_add_ou1," + self.base_dn)
        self.create_ou(self.ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Test user and group creation with regular user credentials
        try:
            self.create_user(self.ldb_user, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
            self.create_group(self.ldb_user, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
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

    def test_add_u3(self):
        """Testing OU with the rights of regular user granted the right 'Create User child objects' """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.create_ou(self.ldb_owner, "OU=test_add_ou1," + self.base_dn)
        user_sid = self.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        self.create_ou(self.ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Test user and group creation with granted user only to one of the objects
        self.create_user(self.ldb_user, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        try:
            self.create_group(self.ldb_user, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
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

    def test_add_u4(self):
        """ 4 Testing OU with the rights of Doman Admin creator of the OU"""
        self.assert_top_ou_deleted()
        self.create_ou(self.ldb_owner, "OU=test_add_ou1," + self.base_dn)
        self.create_ou(self.ldb_owner, "OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.create_user(self.ldb_owner, "CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.create_group(self.ldb_owner, "CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Make sure we have successfully created the two objects -- user and group
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s,%s)" \
                % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn) )
        self.assertTrue( len(res) > 0 )

#tests on ldap modify operations
class AclModifyTests(AclTests):

    def setUp(self):
        AclTests.setUp(self)
        self.user_with_wp = "acl_mod_user1"

        if self.SAMBA:
            # Create regular user
            self.create_enable_user(self.user_with_wp)
        if self.WIN:
            self.assert_user_no_group_member(self.user_with_wp)

        self.ldb_user = self.get_ldb_connection(self.user_with_wp)
        self.user_sid = self.get_object_sid( self.get_user_dn(self.user_with_wp))

    def tearDown(self):
        self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn(self.user_with_wp))

    def test_modify_u1(self):
        """5 Modify one attribute if you have DS_WRITE_PROPERTY for it"""
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.user_sid)
        # First test object -- User
        print "Testing modify on User object"
        #self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.create_user(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.dacl_add_ace(self.get_user_dn("test_modify_user1"), mod)
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % self.get_user_dn("test_modify_user1") )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Second test object -- Group
        print "Testing modify on Group object"
        #self.delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.create_group(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.dacl_add_ace("CN=test_modify_group1,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % str("CN=test_modify_group1,CN=Users," + self.base_dn) )
        self.assertEqual(res[0]["displayName"][0], "test_changed")
        # Third test object -- Organizational Unit
        print "Testing modify on OU object"
        #self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.create_ou(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.dacl_add_ace("OU=test_modify_ou1," + self.base_dn, mod)
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % str("OU=test_modify_ou1," + self.base_dn) )
        self.assertEqual(res[0]["displayName"][0], "test_changed")

    def test_modify_u2(self):
        """6 Modify two attributes as you have DS_WRITE_PROPERTY granted only for one of them"""
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.user_sid)
        # First test object -- User
        print "Testing modify on User object"
        #self.delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.create_user(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.dacl_add_ace(self.get_user_dn("test_modify_user1"), mod)
        # Modify on attribute you have rights for
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
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
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Second test object -- Group
        print "Testing modify on Group object"
        self.create_group(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        self.dacl_add_ace("CN=test_modify_group1,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
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
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Second test object -- Organizational Unit
        print "Testing modify on OU object"
        self.create_ou(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.dacl_add_ace("OU=test_modify_ou1," + self.base_dn, mod)
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
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
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

    def test_modify_u3(self):
        """7 Modify one attribute as you have no what so ever rights granted"""
        # First test object -- User
        print "Testing modify on User object"
        self.create_user(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        # Second test object -- Group
        print "Testing modify on Group object"
        self.create_group(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        # Second test object -- Organizational Unit
        print "Testing modify on OU object"
        #self.delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.create_ou(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()


    def test_modify_u4(self):
        """11 Grant WP to PRINCIPAL_SELF and test modify"""
        ldif = """
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
add: adminDescription
adminDescription: blah blah blah"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        mod = "(OA;;WP;bf967919-0de6-11d0-a285-00aa003049e2;;PS)"
        self.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        # Modify on attribute you have rights for
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % self.get_user_dn(self.user_with_wp), attrs=["adminDescription"] )
        self.assertEqual(res[0]["adminDescription"][0], "blah blah blah")


#enable these when we have search implemented
class AclSearchTests(AclTests):

    def setUp(self):
        AclTests.setUp(self)
        self.regular_user = "acl_search_user1"

        if self.SAMBA:
            # Create regular user
            self.create_enable_user(self.regular_user)
        if self.WIN:
            self.assert_user_no_group_member(self.regular_user)

        self.ldb_user = self.get_ldb_connection(self.regular_user)

    def tearDown(self):
        self.delete_force(self.ldb_admin, "CN=test_search_user1,OU=test_search_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_search_ou1," + self.base_dn)
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))

    def test_search_u1(self):
        """See if can prohibit user to read another User object"""
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

        res = ldb_user.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % user_dn )
        self.assertEqual( res, [] )

    def test_search_u2(self):
        """User's group ACEs cleared and after that granted RIGHT_DS_READ_PROPERTY to another User object"""
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
        res = self.ldb_user.search( self.base_dn, expression="(distinguishedName=%s)" \
                                    % user_dn )
        self.assertNotEqual( res, [] )

#tests on ldap delete operations
class AclDeleteTests(AclTests):

    def setUp(self):
        AclTests.setUp(self)
        self.regular_user = "acl_delete_user1"

        if self.SAMBA:
            # Create regular user
            self.create_enable_user(self.regular_user)
        if self.WIN:
            self.assert_user_no_group_member(self.regular_user)

        self.ldb_user = self.get_ldb_connection(self.regular_user)

    def tearDown(self):
        self.delete_force(self.ldb_admin, self.get_user_dn("test_delete_user1"))
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))

    def test_delete_u1(self):
        """User is prohibited by default to delete another User object"""
        # Create user that we try to delete
        self.create_user(self.ldb_admin, self.get_user_dn("test_delete_user1"))
        # Here delete User object should ALWAYS through exception
        try:
            self.ldb_user.delete(self.get_user_dn("test_delete_user1"))
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_delete_u2(self):
        """User's group has RIGHT_DELETE to another User object"""
        user_dn = self.get_user_dn("test_delete_user1")
        # Create user that we try to delete
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;SD;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        # Try to delete User object
        self.ldb_user.delete( user_dn )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )

    def test_delete_u3(self):
        """User indentified by SID has RIGHT_DELETE to another User object"""
        user_dn = self.get_user_dn("test_delete_user1")
        # Create user that we try to delete
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;SD;;;%s)" % str( self.get_object_sid(self.get_user_dn(self.regular_user)))
        self.dacl_add_ace(user_dn, mod)
        # Try to delete User object
        self.ldb_user.delete( user_dn )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )

#tests on ldap rename operations
class AclRenameTests(AclTests):

    def setUp(self):
        AclTests.setUp(self)
        self.regular_user = "acl_rename_user1"

        if self.SAMBA:
            # Create regular user
            self.create_enable_user(self.regular_user)
        if self.WIN:
            self.assert_user_no_group_member(self.regular_user)

        self.ldb_user = self.get_ldb_connection(self.regular_user)

    def tearDown(self):
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
        self.delete_force(self.ldb_admin, "OU=test_rename_ou3,OU=test_rename_ou1," + self.base_dn)
        self.delete_force(self.ldb_admin, "OU=test_rename_ou1," + self.base_dn)
        if self.SAMBA:
            self.delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))

    def test_rename_u1(self):
        """Regular user fails to rename 'User object' within single OU"""
        # Create OU structure
        self.create_ou(self.ldb_admin, "OU=test_rename_ou1," + self.base_dn)
        self.create_user(self.ldb_admin, "CN=test_rename_user1,OU=test_rename_ou1," + self.base_dn)
        try:
            self.ldb_user.rename("CN=test_rename_user1,OU=test_rename_ou1," + self.base_dn, \
                    "CN=test_rename_user5,OU=test_rename_ou1," + self.base_dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_rename_u2(self):
        """Grant WRITE_PROPERTY to AU so regular user can rename 'User object' within single OU"""
        ou_dn = "OU=test_rename_ou1," + self.base_dn
        user_dn = "CN=test_rename_user1," + ou_dn
        rename_user_dn = "CN=test_rename_user5," + ou_dn
        # Create OU structure
        self.create_ou(self.ldb_admin, ou_dn)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;WP;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        # Rename 'User object' having WP to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u3(self):
        """Test rename with rights granted to 'User object' SID"""
        ou_dn = "OU=test_rename_ou1," + self.base_dn
        user_dn = "CN=test_rename_user1," + ou_dn
        rename_user_dn = "CN=test_rename_user5," + ou_dn
        # Create OU structure
        self.create_ou(self.ldb_admin, ou_dn)
        self.create_user(self.ldb_admin, user_dn)
        sid = self.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(A;;WP;;;%s)" % str(sid)
        self.dacl_add_ace(user_dn, mod)
        # Rename 'User object' having WP to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u4(self):
        """Rename 'User object' cross OU with WP, SD and CC right granted on reg. user to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou2_dn
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        self.create_user(self.ldb_admin, user_dn)
        mod = "(A;;WPSD;;;AU)"
        self.dacl_add_ace(user_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(ou2_dn, mod)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u5(self):
        """Test rename with rights granted to 'User object' SID"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou2_dn
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        self.create_user(self.ldb_admin, user_dn)
        sid = self.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(A;;WPSD;;;%s)" % str(sid)
        self.dacl_add_ace(user_dn, mod)
        mod = "(A;;CC;;;%s)" % str(sid)
        self.dacl_add_ace(ou2_dn, mod)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u6(self):
        """Rename 'User object' cross OU with WP, DC and CC right granted on OU & user to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user2," + ou2_dn
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
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u7(self):
        """Rename 'User object' cross OU (second level) with WP, DC and CC right granted on OU to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        ou3_dn = "OU=test_rename_ou3," + ou2_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou3_dn
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        self.create_ou(self.ldb_admin, ou3_dn)
        mod = "(A;CI;WPDC;;;AU)"
        self.dacl_add_ace(ou1_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.dacl_add_ace(ou3_dn, mod)
        self.create_user(self.ldb_admin, user_dn)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % user_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % rename_user_dn )
        self.assertNotEqual( res, [] )

    def test_rename_u8(self):
        """Test rename on an object with and without modify access on the RDN attribute"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + ou1_dn
        ou3_dn = "OU=test_rename_ou3," + ou1_dn
        # Create OU structure
        self.create_ou(self.ldb_admin, ou1_dn)
        self.create_ou(self.ldb_admin, ou2_dn)
        sid = self.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(OA;;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;%s)" % str(sid)
        self.dacl_add_ace(ou2_dn, mod)
        mod = "(OD;;WP;bf9679f0-0de6-11d0-a285-00aa003049e2;;%s)" % str(sid)
        self.dacl_add_ace(ou2_dn, mod)
        try:
            self.ldb_user.rename(ou2_dn, ou3_dn)
        except LdbError, (num, _):
            self.assertEquals(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This rename operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        sid = self.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(A;;WP;bf9679f0-0de6-11d0-a285-00aa003049e2;;%s)" % str(sid)
        self.dacl_add_ace(ou2_dn, mod)
        self.ldb_user.rename(ou2_dn, ou3_dn)
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % ou2_dn )
        self.assertEqual( res, [] )
        res = self.ldb_admin.search( self.base_dn, expression="(distinguishedName=%s)" \
                % ou3_dn )
        self.assertNotEqual( res, [] )

# Important unit running information

if not "://" in host:
    host = "ldap://%s" % host
ldb = Ldb(host, credentials=creds, session_info=system_session(), lp=lp)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(AclAddTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(AclModifyTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(AclDeleteTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(AclRenameTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
