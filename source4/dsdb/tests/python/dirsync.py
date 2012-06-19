#!/usr/bin/env python
#
# Unit tests for dirsync control
# Copyright (C) Matthieu Patou <mat@matws.net> 2011
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import optparse
import sys
sys.path.insert(0, "bin/python")
import samba
samba.ensure_external_module("testtools", "testtools")
samba.ensure_external_module("subunit", "subunit/python")

import samba.getopt as options
import base64

from ldb import LdbError, SCOPE_BASE
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_DELETE
from samba.dcerpc import security, misc, drsblobs
from samba.ndr import ndr_unpack, ndr_pack

from samba.auth import system_session
from samba import gensec, sd_utils
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
from samba.tests import delete_force
from subunit.run import SubunitTestRunner
import unittest

parser = optparse.OptionParser("dirsync.py [options] <host>")
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
if not "://" in host:
    ldaphost = "ldap://%s" % host
    ldapshost = "ldaps://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start+3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

#
# Tests start here
#

class DirsyncBaseTests(samba.tests.TestCase):

    def setUp(self):
        super(DirsyncBaseTests, self).setUp()
        self.ldb_admin = ldb
        self.base_dn = ldb.domain_dn()
        self.domain_sid = security.dom_sid(ldb.get_domain_sid())
        self.user_pass = "samba123@AAA"
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()
        self.sd_utils = sd_utils.SDUtils(ldb)
        #used for anonymous login
        print "baseDN: %s" % self.base_dn

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS) # kinit is too expensive to use in a tight loop
        ldb_target = SamDB(url=ldaphost, credentials=creds_tmp, lp=lp)
        return ldb_target


#tests on ldap add operations
class SimpleDirsyncTests(DirsyncBaseTests):

    def setUp(self):
        super(SimpleDirsyncTests, self).setUp()
        # Regular user
        self.dirsync_user = "test_dirsync_user"
        self.simple_user = "test_simple_user"
        self.admin_user = "test_admin_user"
        self.ouname = None

        self.ldb_admin.newuser(self.dirsync_user, self.user_pass)
        self.ldb_admin.newuser(self.simple_user, self.user_pass)
        self.ldb_admin.newuser(self.admin_user, self.user_pass)
        self.desc_sddl = self.sd_utils.get_sd_as_sddl(self.base_dn)

        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.dirsync_user))
        mod = "(A;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(self.base_dn, mod)

        # add admins to the Domain Admins group
        self.ldb_admin.add_remove_group_members("Domain Admins", [self.admin_user],
                       add_members_operation=True)

    def tearDown(self):
        super(SimpleDirsyncTests, self).tearDown()
        delete_force(self.ldb_admin, self.get_user_dn(self.dirsync_user))
        delete_force(self.ldb_admin, self.get_user_dn(self.simple_user))
        delete_force(self.ldb_admin, self.get_user_dn(self.admin_user))
        if self.ouname:
            delete_force(self.ldb_admin, self.ouname)
        self.sd_utils.modify_sd_on_dn(self.base_dn, self.desc_sddl)
        try:
            self.ldb_admin.deletegroup("testgroup")
        except Exception:
            pass

    #def test_dirsync_errors(self):


    def test_dirsync_supported(self):
        """Test the basic of the dirsync is supported"""
        self.ldb_dirsync = self.get_ldb_connection(self.dirsync_user, self.user_pass)
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.user_pass)
        res = self.ldb_admin.search(self.base_dn, expression="samaccountname=*", controls=["dirsync:1:0:1"])
        res = self.ldb_dirsync.search(self.base_dn, expression="samaccountname=*", controls=["dirsync:1:0:1"])
        try:
            self.ldb_simple.search(self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:0:1"])
        except LdbError,l:
           self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

    def test_parentGUID_referrals(self):
        res2 = self.ldb_admin.search(self.base_dn, scope=SCOPE_BASE, attrs=["objectGUID"])

        res = self.ldb_admin.search(self.base_dn,
                                        expression="name=Configuration",
                                        controls=["dirsync:1:0:1"])
        self.assertEqual(res2[0].get("objectGUID"), res[0].get("parentGUID"))

    def test_ok_not_rootdc(self):
        """Test if it's ok to do dirsync on another NC that is not the root DC"""
        self.ldb_admin.search(self.ldb_admin.get_config_basedn(),
                                    expression="samaccountname=*",
                                    controls=["dirsync:1:0:1"])

    def test_dirsync_errors(self):
        """Test if dirsync returns the correct LDAP errors in case of pb"""
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.user_pass)
        self.ldb_dirsync = self.get_ldb_connection(self.dirsync_user, self.user_pass)
        try:
            self.ldb_simple.search(self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:0:1"])
        except LdbError,l:
            print l
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_simple.search("CN=Users,%s" % self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:0:1"])
        except LdbError,l:
            print l
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_simple.search("CN=Users,%s" % self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:1:1"])
        except LdbError,l:
            print l
            self.assertTrue(str(l).find("LDAP_UNWILLING_TO_PERFORM") != -1)

        try:
            self.ldb_dirsync.search("CN=Users,%s" % self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:0:1"])
        except LdbError,l:
            print l
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_admin.search("CN=Users,%s" % self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:0:1"])
        except LdbError,l:
            print l
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_admin.search("CN=Users,%s" % self.base_dn,
                expression="samaccountname=*",
                controls=["dirsync:1:1:1"])
        except LdbError,l:
            print l
            self.assertTrue(str(l).find("LDAP_UNWILLING_TO_PERFORM") != -1)




    def test_dirsync_attributes(self):
        """Check behavior with some attributes """
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=*",
                                    controls=["dirsync:1:0:1"])
        # Check that nTSecurityDescriptor is returned as it's the case when doing dirsync
        self.assertTrue(res.msgs[0].get("ntsecuritydescriptor") != None)
        # Check that non replicated attributes are not returned
        self.assertTrue(res.msgs[0].get("badPwdCount") == None)
        # Check that non forward link are not returned
        self.assertTrue(res.msgs[0].get("memberof") == None)

        # Asking for instanceType will return also objectGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["instanceType"],
                                    controls=["dirsync:1:0:1"])
        self.assertTrue(res.msgs[0].get("objectGUID") != None)
        self.assertTrue(res.msgs[0].get("instanceType") != None)

        # We don't return an entry if asked for objectGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["objectGUID"],
                                    controls=["dirsync:1:0:1"])
        self.assertEquals(len(res.msgs), 0)

        # a request on the root of a NC didn't return parentGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["name"],
                                    controls=["dirsync:1:0:1"])
        self.assertTrue(res.msgs[0].get("objectGUID") != None)
        self.assertTrue(res.msgs[0].get("name") != None)
        self.assertTrue(res.msgs[0].get("parentGUID") == None)
        self.assertTrue(res.msgs[0].get("instanceType") != None)

         # Asking for name will return also objectGUID and parentGUID
        # and instanceType and of course name
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["name"],
                                    controls=["dirsync:1:0:1"])
        self.assertTrue(res.msgs[0].get("objectGUID") != None)
        self.assertTrue(res.msgs[0].get("name") != None)
        self.assertTrue(res.msgs[0].get("parentGUID") != None)
        self.assertTrue(res.msgs[0].get("instanceType") != None)

        # Asking for dn will not return not only DN but more like if attrs=*
        # parentGUID should be returned
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["dn"],
                                    controls=["dirsync:1:0:1"])
        count = len(res.msgs[0])
        res2 = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    controls=["dirsync:1:0:1"])
        count2 = len(res2.msgs[0])
        self.assertEqual(count, count2)

        # Asking for cn will return nothing on objects that have CN as RDN
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["cn"],
                                    controls=["dirsync:1:0:1"])
        self.assertEqual(len(res.msgs), 0)
        # Asking for parentGUID will return nothing too
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["parentGUID"],
                                    controls=["dirsync:1:0:1"])
        self.assertEqual(len(res.msgs), 0)
        ouname="OU=testou,%s" % self.base_dn
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)
        delta = Message()
        delta.dn = Dn(self.ldb_admin, str(ouname))
        delta["cn"] = MessageElement("test ou",
                                        FLAG_MOD_ADD,
                                        "cn" )
        self.ldb_admin.modify(delta)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="name=testou",
                                    attrs=["cn"],
                                    controls=["dirsync:1:0:1"])

        self.assertEqual(len(res.msgs), 1)
        self.assertEqual(len(res.msgs[0]), 3)
        delete_force(self.ldb_admin, ouname)

    def test_dirsync_with_controls(self):
        """Check that dirsync return correct informations when dealing with the NC"""
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["name"],
                                    controls=["dirsync:1:0:10000", "extended_dn:1", "show_deleted:1"])

    def test_dirsync_basenc(self):
        """Check that dirsync return correct informations when dealing with the NC"""
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["name"],
                                    controls=["dirsync:1:0:10000"])
        self.assertEqual(len(res.msgs), 1)
        self.assertEqual(len(res.msgs[0]), 3)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["ntSecurityDescriptor"],
                                    controls=["dirsync:1:0:10000"])
        self.assertEqual(len(res.msgs), 1)
        self.assertEqual(len(res.msgs[0]), 3)

    def test_dirsync_othernc(self):
        """Check that dirsync return information for entries that are normaly referrals (ie. other NCs)"""
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(objectclass=configuration)",
                                    attrs=["name"],
                                    controls=["dirsync:1:0:10000"])
        self.assertEqual(len(res.msgs), 1)
        self.assertEqual(len(res.msgs[0]), 4)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(objectclass=configuration)",
                                    attrs=["ntSecurityDescriptor"],
                                    controls=["dirsync:1:0:10000"])
        self.assertEqual(len(res.msgs), 1)
        self.assertEqual(len(res.msgs[0]), 3)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(objectclass=domaindns)",
                                    attrs=["ntSecurityDescriptor"],
                                    controls=["dirsync:1:0:10000"])
        nb = len(res.msgs)

        # only sub nc returns a result when asked for objectGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(objectclass=domaindns)",
                                    attrs=["objectGUID"],
                                    controls=["dirsync:1:0:0"])
        self.assertEqual(len(res.msgs), nb - 1)
        if nb > 1:
            self.assertTrue(res.msgs[0].get("objectGUID") != None)
        else:
            res = self.ldb_admin.search(self.base_dn,
                                        expression="(objectclass=configuration)",
                                        attrs=["objectGUID"],
                                        controls=["dirsync:1:0:0"])


    def test_dirsync_send_delta(self):
        """Check that dirsync return correct delta when sending the last cookie"""
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(samaccountname=test*)(!(isDeleted=*)))",
                                    controls=["dirsync:1:0:10000"])
        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "10000"
        control = str(":".join(ctl))
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(samaccountname=test*)(!(isDeleted=*)))",
                                    controls=[control])
        self.assertEqual(len(res), 0)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=["dirsync:1:0:100000"])

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "10000"
        control2 = str(":".join(ctl))

        # Let's create an OU
        ouname="OU=testou2,%s" % self.base_dn
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=[control2])
        self.assertEqual(len(res), 1)
        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "10000"
        control3 = str(":".join(ctl))

        delta = Message()
        delta.dn = Dn(self.ldb_admin, str(ouname))

        delta["cn"] = MessageElement("test ou",
                                        FLAG_MOD_ADD,
                                        "cn" )
        self.ldb_admin.modify(delta)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=[control3])

        self.assertEqual(len(res.msgs), 1)
        # 3 attributes: instanceType, cn and objectGUID
        self.assertEqual(len(res.msgs[0]), 3)

        delta = Message()
        delta.dn = Dn(self.ldb_admin, str(ouname))
        delta["cn"] = MessageElement([],
                                        FLAG_MOD_DELETE,
                                        "cn" )
        self.ldb_admin.modify(delta)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=[control3])

        self.assertEqual(len(res.msgs), 1)
        # So we won't have much attribute returned but instanceType and GUID
        # are.
        # 3 attributes: instanceType and objectGUID and cn but empty
        self.assertEqual(len(res.msgs[0]), 3)
        ouname = "OU=newouname,%s" % self.base_dn
        self.ldb_admin.rename(str(res[0].dn), str(Dn(self.ldb_admin, ouname)))
        self.ouname = ouname
        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "10000"
        control4 = str(":".join(ctl))
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=[control3])

        self.assertTrue(res[0].get("parentGUID") != None)
        self.assertTrue(res[0].get("name") != None)
        delete_force(self.ldb_admin, ouname)

    def test_dirsync_linkedattributes(self):
        """Check that dirsync returnd deleted objects too"""
        # Let's search for members
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.user_pass)
        res = self.ldb_simple.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=["dirsync:1:1:1"])

        self.assertTrue(len(res[0].get("member")) > 0)
        size = len(res[0].get("member"))

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "1"
        ctl[3] = "10000"
        control1 = str(":".join(ctl))
        self.ldb_admin.add_remove_group_members("Administrators", [self.simple_user],
                       add_members_operation=True)

        res = self.ldb_simple.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control1])

        self.assertEqual(len(res[0].get("member")), size + 1)
        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "1"
        ctl[3] = "10000"
        control1 = str(":".join(ctl))

        # remove the user from the group
        self.ldb_admin.add_remove_group_members("Administrators", [self.simple_user],
                       add_members_operation=False)

        res = self.ldb_simple.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control1])

        self.assertEqual(len(res[0].get("member")), size )

        self.ldb_admin.newgroup("testgroup")
        self.ldb_admin.add_remove_group_members("testgroup", [self.simple_user],
                       add_members_operation=True)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=testgroup)",
                                    controls=["dirsync:1:0:1"])

        self.assertEqual(len(res[0].get("member")), 1)
        self.assertTrue(res[0].get("member") != "" )

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "1"
        control1 = str(":".join(ctl))

        # Check that reasking the same question but with an updated cookie
        # didn't return any results.
        print control1
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=testgroup)",
                                    controls=[control1])
        self.assertEqual(len(res), 0)

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "1"
        ctl[3] = "10000"
        control1 = str(":".join(ctl))

        self.ldb_admin.add_remove_group_members("testgroup", [self.simple_user],
                       add_members_operation=False)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=testgroup)",
                                    attrs=["member"],
                                    controls=[control1])

        self.ldb_admin.deletegroup("testgroup")
        self.assertEqual(len(res[0].get("member")), 0)



    def test_dirsync_deleted_items(self):
        """Check that dirsync returnd deleted objects too"""
        # Let's create an OU
        ouname="OU=testou3,%s" % self.base_dn
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=["dirsync:1:0:1"])
        guid = None
        for e in res:
            if str(e["name"]) == "testou3":
                guid = str(ndr_unpack(misc.GUID,e.get("objectGUID")[0]))

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "10000"
        control1 = str(":".join(ctl))

        # So now delete the object and check that
        # we can see the object but deleted when admin
        delete_force(self.ldb_admin, ouname)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(objectClass=organizationalUnit)",
                                    controls=[control1])
        self.assertEqual(len(res), 1)
        guid2 = str(ndr_unpack(misc.GUID,res[0].get("objectGUID")[0]))
        self.assertEqual(guid2, guid)
        self.assertTrue(res[0].get("isDeleted"))
        self.assertTrue(res[0].get("name") != None)

    def test_cookie_from_others(self):
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=["dirsync:1:0:1"])
        ctl = str(res.controls[0]).split(":")
        cookie = ndr_unpack(drsblobs.ldapControlDirSyncCookie, base64.b64decode(str(ctl[4])))
        cookie.blob.guid1 = misc.GUID("128a99bf-abcd-1234-abcd-1fb625e530db")
        controls=["dirsync:1:0:0:%s" % base64.b64encode(ndr_pack(cookie))]
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=controls)

class ExtendedDirsyncTests(SimpleDirsyncTests):
    def test_dirsync_linkedattributes(self):
        flag_incr_linked = 2147483648
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.user_pass)
        res = self.ldb_admin.search(self.base_dn,
                                    attrs=["member"],
                                    expression="(name=Administrators)",
                                    controls=["dirsync:1:%d:1" % flag_incr_linked])

        self.assertTrue(res[0].get("member;range=1-1") != None )
        self.assertTrue(len(res[0].get("member;range=1-1")) > 0)
        size = len(res[0].get("member;range=1-1"))

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "%d" % flag_incr_linked
        ctl[3] = "10000"
        control1 = str(":".join(ctl))
        self.ldb_admin.add_remove_group_members("Administrators", [self.simple_user],
                       add_members_operation=True)
        self.ldb_admin.add_remove_group_members("Administrators", [self.dirsync_user],
                       add_members_operation=True)


        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control1])

        self.assertEqual(len(res[0].get("member;range=1-1")), 2)
        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "%d" % flag_incr_linked
        ctl[3] = "10000"
        control1 = str(":".join(ctl))

        # remove the user from the group
        self.ldb_admin.add_remove_group_members("Administrators", [self.simple_user],
                       add_members_operation=False)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control1])

        self.assertEqual(res[0].get("member;range=1-1"), None )
        self.assertEqual(len(res[0].get("member;range=0-0")), 1)

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "%d" % flag_incr_linked
        ctl[3] = "10000"
        control2 = str(":".join(ctl))

        self.ldb_admin.add_remove_group_members("Administrators", [self.dirsync_user],
                       add_members_operation=False)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control2])

        self.assertEqual(res[0].get("member;range=1-1"), None )
        self.assertEqual(len(res[0].get("member;range=0-0")), 1)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control1])

        self.assertEqual(res[0].get("member;range=1-1"), None )
        self.assertEqual(len(res[0].get("member;range=0-0")), 2)

    def test_dirsync_deleted_items(self):
        """Check that dirsync returnd deleted objects too"""
        # Let's create an OU
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.user_pass)
        ouname="OU=testou3,%s" % self.base_dn
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)

        # Specify LDAP_DIRSYNC_OBJECT_SECURITY
        res = self.ldb_simple.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=["dirsync:1:1:1"])

        guid = None
        for e in res:
            if str(e["name"]) == "testou3":
                guid = str(ndr_unpack(misc.GUID,e.get("objectGUID")[0]))

        self.assertTrue(guid != None)
        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "1"
        ctl[3] = "10000"
        control1 = str(":".join(ctl))

        # So now delete the object and check that
        # we can see the object but deleted when admin
        # we just see the objectGUID when simple user
        delete_force(self.ldb_admin, ouname)

        res = self.ldb_simple.search(self.base_dn,
                                    expression="(objectClass=organizationalUnit)",
                                    controls=[control1])
        self.assertEqual(len(res), 1)
        guid2 = str(ndr_unpack(misc.GUID,res[0].get("objectGUID")[0]))
        self.assertEqual(guid2, guid)
        self.assertEqual(str(res[0].dn), "")


ldb = SamDB(ldapshost, credentials=creds, session_info=system_session(lp), lp=lp)

runner = SubunitTestRunner()
rc = 0
#
if not runner.run(unittest.makeSuite(SimpleDirsyncTests)).wasSuccessful():
    rc = 1
if not runner.run(unittest.makeSuite(ExtendedDirsyncTests)).wasSuccessful():
    rc = 1

sys.exit(rc)
