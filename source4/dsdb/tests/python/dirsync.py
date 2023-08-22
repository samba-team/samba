#!/usr/bin/env python3
#
# Unit tests for dirsync control
# Copyright (C) Matthieu Patou <mat@matws.net> 2011
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2014
# Copyright (C) Catalyst.Net Ltd
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
from samba.tests.subunitrun import TestProgram, SubunitOptions

import samba.getopt as options
import base64

import ldb
from ldb import LdbError, SCOPE_BASE
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_DELETE, FLAG_MOD_REPLACE
from samba.dsdb import SEARCH_FLAG_CONFIDENTIAL, SEARCH_FLAG_RODC_ATTRIBUTE
from samba.dcerpc import security, misc, drsblobs
from samba.ndr import ndr_unpack, ndr_pack

from samba.auth import system_session
from samba import gensec, sd_utils
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
from samba.tests import delete_force

parser = optparse.OptionParser("dirsync.py [options] <host>")
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

host = args.pop()
if "://" not in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start + 3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

#
# Tests start here
#


class DirsyncBaseTests(samba.tests.TestCase):

    def setUp(self):
        super().setUp()
        self.ldb_admin = SamDB(ldaphost, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb_admin.domain_dn()
        self.domain_sid = security.dom_sid(self.ldb_admin.get_domain_sid())
        self.user_pass = samba.generate_random_password(12, 16)
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()
        self.sd_utils = sd_utils.SDUtils(self.ldb_admin)
        # used for anonymous login
        print("baseDN: %s" % self.base_dn)

        userou = "OU=dirsync-test"
        self.ou = f"{userou},{self.base_dn}"
        samba.tests.delete_force(self.ldb_admin, self.ou, controls=['tree_delete:1'])
        self.ldb_admin.create_ou(self.ou)
        self.addCleanup(samba.tests.delete_force, self.ldb_admin, self.ou, controls=['tree_delete:1'])

        # Regular user
        self.dirsync_user = "test_dirsync_user"
        self.simple_user = "test_simple_user"
        self.admin_user = "test_admin_user"
        self.dirsync_pass = self.user_pass
        self.simple_pass = self.user_pass
        self.admin_pass = self.user_pass

        self.ldb_admin.newuser(self.dirsync_user, self.dirsync_pass, userou=userou)
        self.ldb_admin.newuser(self.simple_user, self.simple_pass, userou=userou)
        self.ldb_admin.newuser(self.admin_user, self.admin_pass, userou=userou)
        self.desc_sddl = self.sd_utils.get_sd_as_sddl(self.base_dn)

        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.dirsync_user))
        mod = "(OA;;CR;%s;;%s)" % (security.GUID_DRS_GET_CHANGES,
                                   str(user_sid))
        self.sd_utils.dacl_add_ace(self.base_dn, mod)
        self.addCleanup(self.sd_utils.dacl_delete_aces, self.base_dn, mod)

        # add admins to the Domain Admins group
        self.ldb_admin.add_remove_group_members("Domain Admins", [self.admin_user],
                                                add_members_operation=True)

    def get_user_dn(self, name):
        return ldb.Dn(self.ldb_admin, "CN={0},{1}".format(name, self.ou))

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS)  # kinit is too expensive to use in a tight loop
        ldb_target = SamDB(url=ldaphost, credentials=creds_tmp, lp=lp)
        return ldb_target

# tests on ldap add operations
class SimpleDirsyncTests(DirsyncBaseTests):

    # def test_dirsync_errors(self):

    def test_dirsync_supported(self):
        """Test the basic of the dirsync is supported"""
        self.ldb_dirsync = self.get_ldb_connection(self.dirsync_user, self.user_pass)
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = self.ldb_admin.search(self.base_dn, expression="samaccountname=*", controls=["dirsync:1:0:1"])
        res = self.ldb_dirsync.search(self.base_dn, expression="samaccountname=*", controls=["dirsync:1:0:1"])
        try:
            self.ldb_simple.search(self.base_dn,
                                   expression="samaccountname=*",
                                   controls=["dirsync:1:0:1"])
        except LdbError as l:
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
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self.ldb_dirsync = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        try:
            self.ldb_simple.search(self.base_dn,
                                   expression="samaccountname=*",
                                   controls=["dirsync:1:0:1"])
        except LdbError as l:
            print(l)
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_simple.search("CN=Users,%s" % self.base_dn,
                                   expression="samaccountname=*",
                                   controls=["dirsync:1:0:1"])
        except LdbError as l:
            print(l)
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_simple.search("CN=Users,%s" % self.base_dn,
                                   expression="samaccountname=*",
                                   controls=["dirsync:1:1:1"])
        except LdbError as l:
            print(l)
            self.assertTrue(str(l).find("LDAP_UNWILLING_TO_PERFORM") != -1)

        try:
            self.ldb_dirsync.search("CN=Users,%s" % self.base_dn,
                                    expression="samaccountname=*",
                                    controls=["dirsync:1:0:1"])
        except LdbError as l:
            print(l)
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_admin.search("CN=Users,%s" % self.base_dn,
                                  expression="samaccountname=*",
                                  controls=["dirsync:1:0:1"])
        except LdbError as l:
            print(l)
            self.assertTrue(str(l).find("LDAP_INSUFFICIENT_ACCESS_RIGHTS") != -1)

        try:
            self.ldb_admin.search("CN=Users,%s" % self.base_dn,
                                  expression="samaccountname=*",
                                  controls=["dirsync:1:1:1"])
        except LdbError as l:
            print(l)
            self.assertTrue(str(l).find("LDAP_UNWILLING_TO_PERFORM") != -1)

    def test_dirsync_attributes(self):
        """Check behavior with some attributes """
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=*",
                                    controls=["dirsync:1:0:1"])
        # Check that nTSecurityDescriptor is returned as it's the case when doing dirsync
        self.assertTrue(res.msgs[0].get("ntsecuritydescriptor") is not None)
        # Check that non replicated attributes are not returned
        self.assertTrue(res.msgs[0].get("badPwdCount") is None)
        # Check that non forward link are not returned
        self.assertTrue(res.msgs[0].get("memberof") is None)

        # Asking for instanceType will return also objectGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["instanceType"],
                                    controls=["dirsync:1:0:1"])
        self.assertTrue(res.msgs[0].get("objectGUID") is not None)
        self.assertTrue(res.msgs[0].get("instanceType") is not None)

        # We don't return an entry if asked for objectGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["objectGUID"],
                                    controls=["dirsync:1:0:1"])
        self.assertEqual(len(res.msgs), 0)

        # a request on the root of a NC didn't return parentGUID
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["name"],
                                    controls=["dirsync:1:0:1"])
        self.assertTrue(res.msgs[0].get("objectGUID") is not None)
        self.assertTrue(res.msgs[0].get("name") is not None)
        self.assertTrue(res.msgs[0].get("parentGUID") is None)
        self.assertTrue(res.msgs[0].get("instanceType") is not None)

        # Asking for name will return also objectGUID and parentGUID
        # and instanceType and of course name
        res = self.ldb_admin.search(self.base_dn,
                                    expression="samaccountname=Administrator",
                                    attrs=["name"],
                                    controls=["dirsync:1:0:1"])
        self.assertTrue(res.msgs[0].get("objectGUID") is not None)
        self.assertTrue(res.msgs[0].get("name") is not None)
        self.assertTrue(res.msgs[0].get("parentGUID") is not None)
        self.assertTrue(res.msgs[0].get("instanceType") is not None)

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
        ouname = "OU=testou,%s" % self.ou
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)
        delta = Message()
        delta.dn = Dn(self.ldb_admin, ouname)
        delta["cn"] = MessageElement("test ou",
                                     FLAG_MOD_ADD,
                                     "cn")
        self.ldb_admin.modify(delta)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="name=testou",
                                    attrs=["cn"],
                                    controls=["dirsync:1:0:1"])

        self.assertEqual(len(res.msgs), 1)
        self.assertEqual(len(res.msgs[0]), 3)
        delete_force(self.ldb_admin, ouname)

    def test_dirsync_with_controls(self):
        """Check that dirsync return correct information when dealing with the NC"""
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str(self.base_dn),
                                    attrs=["name"],
                                    controls=["dirsync:1:0:10000", "extended_dn:1", "show_deleted:1"])

    def test_dirsync_basenc(self):
        """Check that dirsync return correct information when dealing with the NC"""
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
        """Check that dirsync return information for entries that are normally referrals (ie. other NCs)"""
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
            self.assertTrue(res.msgs[0].get("objectGUID") is not None)
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
        ouname = "OU=testou2,%s" % self.base_dn
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
                                     "cn")
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
                                     "cn")
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
                                    controls=[control4])

        self.assertTrue(res[0].get("parentGUID") is not None)
        self.assertTrue(res[0].get("name") is not None)
        delete_force(self.ldb_admin, ouname)

    def test_dirsync_linkedattributes_OBJECT_SECURITY(self):
        """Check that dirsync returned deleted objects too"""
        # Let's search for members
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
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

        self.assertEqual(len(res[0].get("member")), size)

        self.ldb_admin.newgroup("testgroup")
        self.addCleanup(self.ldb_admin.deletegroup, "testgroup")
        self.ldb_admin.add_remove_group_members("testgroup", [self.simple_user],
                                                add_members_operation=True)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=testgroup)",
                                    controls=["dirsync:1:0:1"])

        self.assertEqual(len(res[0].get("member")), 1)
        self.assertTrue(res[0].get("member") != "")

        ctl = str(res.controls[0]).split(":")
        ctl[1] = "1"
        ctl[2] = "0"
        ctl[3] = "1"
        control1 = str(":".join(ctl))

        # Check that reasking the same question but with an updated cookie
        # didn't return any results.
        print(control1)
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

        self.assertEqual(len(res[0].get("member")), 0)

    def test_dirsync_deleted_items(self):
        """Check that dirsync returned deleted objects too"""
        # Let's create an OU
        ouname = "OU=testou3,%s" % self.base_dn
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=["dirsync:1:0:1"])
        guid = None
        for e in res:
            if str(e["name"]) == "testou3":
                guid = str(ndr_unpack(misc.GUID, e.get("objectGUID")[0]))

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
        guid2 = str(ndr_unpack(misc.GUID, res[0].get("objectGUID")[0]))
        self.assertEqual(guid2, guid)
        self.assertTrue(res[0].get("isDeleted"))
        self.assertTrue(res[0].get("name") is not None)

    def test_cookie_from_others(self):
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=["dirsync:1:0:1"])
        ctl = str(res.controls[0]).split(":")
        cookie = ndr_unpack(drsblobs.ldapControlDirSyncCookie, base64.b64decode(str(ctl[4])))
        cookie.blob.guid1 = misc.GUID("128a99bf-abcd-1234-abcd-1fb625e530db")
        controls = ["dirsync:1:0:0:%s" % base64.b64encode(ndr_pack(cookie)).decode('utf8')]
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                    controls=controls)

    def test_dirsync_linkedattributes_range(self):
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = self.ldb_admin.search(self.base_dn,
                                    attrs=["member;range=1-1"],
                                    expression="(name=Administrators)",
                                    controls=["dirsync:1:0:0"])

        self.assertTrue(len(res) > 0)
        self.assertTrue(res[0].get("member;range=1-1") is None)
        self.assertTrue(res[0].get("member") is not None)
        self.assertTrue(len(res[0].get("member")) > 0)

    def test_dirsync_linkedattributes_range_user(self):
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        try:
            res = self.ldb_simple.search(self.base_dn,
                                         attrs=["member;range=1-1"],
                                         expression="(name=Administrators)",
                                        controls=["dirsync:1:0:0"])
        except LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_dirsync_linkedattributes(self):
        flag_incr_linked = 2147483648
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = self.ldb_admin.search(self.base_dn,
                                    attrs=["member"],
                                    expression="(name=Administrators)",
                                    controls=["dirsync:1:%d:1" % flag_incr_linked])

        self.assertTrue(res[0].get("member;range=1-1") is not None)
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

        self.assertEqual(res[0].get("member;range=1-1"), None)
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

        self.assertEqual(res[0].get("member;range=1-1"), None)
        self.assertEqual(len(res[0].get("member;range=0-0")), 1)

        res = self.ldb_admin.search(self.base_dn,
                                    expression="(name=Administrators)",
                                    controls=[control1])

        self.assertEqual(res[0].get("member;range=1-1"), None)
        self.assertEqual(len(res[0].get("member;range=0-0")), 2)

    def test_dirsync_extended_dn(self):
        """Check that dirsync works together with the extended_dn control"""
        # Let's search for members
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = self.ldb_simple.search(self.base_dn,
                                     expression="(name=Administrators)",
                                     controls=["dirsync:1:1:1"])

        self.assertTrue(len(res[0].get("member")) > 0)
        size = len(res[0].get("member"))

        resEX1 = self.ldb_simple.search(self.base_dn,
                                        expression="(name=Administrators)",
                                        controls=["dirsync:1:1:1","extended_dn:1:1"])
        self.assertTrue(len(resEX1[0].get("member")) > 0)
        sizeEX1 = len(resEX1[0].get("member"))
        self.assertEqual(sizeEX1, size)
        self.assertIn(res[0]["member"][0], resEX1[0]["member"][0])
        self.assertIn(b"<GUID=", resEX1[0]["member"][0])
        self.assertIn(b">;<SID=S-1-5-21-", resEX1[0]["member"][0])

        resEX0 = self.ldb_simple.search(self.base_dn,
                                        expression="(name=Administrators)",
                                        controls=["dirsync:1:1:1","extended_dn:1:0"])
        self.assertTrue(len(resEX0[0].get("member")) > 0)
        sizeEX0 = len(resEX0[0].get("member"))
        self.assertEqual(sizeEX0, size)
        self.assertIn(res[0]["member"][0], resEX0[0]["member"][0])
        self.assertIn(b"<GUID=", resEX0[0]["member"][0])
        self.assertIn(b">;<SID=010500000000000515", resEX0[0]["member"][0])

    def test_dirsync_deleted_items_OBJECT_SECURITY(self):
        """Check that dirsync returned deleted objects too"""
        # Let's create an OU
        self.ldb_simple = self.get_ldb_connection(self.simple_user, self.simple_pass)
        ouname = "OU=testou3,%s" % self.base_dn
        self.ouname = ouname
        self.ldb_admin.create_ou(ouname)

        # Specify LDAP_DIRSYNC_OBJECT_SECURITY
        res = self.ldb_simple.search(self.base_dn,
                                     expression="(&(objectClass=organizationalUnit)(!(isDeleted=*)))",
                                     controls=["dirsync:1:1:1"])

        guid = None
        for e in res:
            if str(e["name"]) == "testou3":
                guid = str(ndr_unpack(misc.GUID, e.get("objectGUID")[0]))

        self.assertTrue(guid is not None)
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
        guid2 = str(ndr_unpack(misc.GUID, res[0].get("objectGUID")[0]))
        self.assertEqual(guid2, guid)
        self.assertEqual(str(res[0].dn), "")

class SpecialDirsyncTests(DirsyncBaseTests):

    def setUp(self):
        super().setUp()

        self.schema_dn = self.ldb_admin.get_schema_basedn()

        # the tests work by setting the 'Confidential' or 'RODC Filtered' bit in the searchFlags
        # for an existing schema attribute. This only works against Windows if
        # the systemFlags does not have FLAG_SCHEMA_BASE_OBJECT set for the
        # schema attribute being modified. There are only a few attributes that
        # meet this criteria (most of which only apply to 'user' objects)
        self.conf_attr = "homePostalAddress"
        attr_cn = "CN=Address-Home"
        # schemaIdGuid for homePostalAddress (used for ACE tests)
        self.attr_dn = f"{attr_cn},{self.schema_dn}"

        userou = "OU=conf-attr-test"
        self.ou = "{0},{1}".format(userou, self.base_dn)
        samba.tests.delete_force(self.ldb_admin, self.ou, controls=['tree_delete:1'])
        self.ldb_admin.create_ou(self.ou)
        self.addCleanup(samba.tests.delete_force, self.ldb_admin, self.ou, controls=['tree_delete:1'])

        # add a test object with this attribute set
        self.conf_value = "abcdef"
        self.conf_user = "conf-user"
        self.ldb_admin.newuser(self.conf_user, self.user_pass, userou=userou)
        self.conf_dn = self.get_user_dn(self.conf_user)
        self.add_attr(self.conf_dn, self.conf_attr, self.conf_value)

        # sanity-check the flag is not already set (this'll cause problems if
        # previous test run didn't clean up properly)

        search_flags = int(self.get_attr_search_flags(self.attr_dn))
        if search_flags & SEARCH_FLAG_CONFIDENTIAL|SEARCH_FLAG_RODC_ATTRIBUTE:
            self.set_attr_search_flags(self.attr_dn, str(search_flags &~ (SEARCH_FLAG_CONFIDENTIAL|SEARCH_FLAG_RODC_ATTRIBUTE)))
        search_flags = int(self.get_attr_search_flags(self.attr_dn))
        self.assertEqual(0, search_flags & (SEARCH_FLAG_CONFIDENTIAL|SEARCH_FLAG_RODC_ATTRIBUTE),
                         f"{self.conf_attr} searchFlags did not reset to omit SEARCH_FLAG_CONFIDENTIAL and SEARCH_FLAG_RODC_ATTRIBUTE ({search_flags})")

        # work out the original 'searchFlags' value before we overwrite it
        old_value = self.get_attr_search_flags(self.attr_dn)

        self.set_attr_search_flags(self.attr_dn, str(self.flag_under_test))

        # reset the value after the test completes
        self.addCleanup(self.set_attr_search_flags, self.attr_dn, old_value)

    def add_attr(self, dn, attr, value):
        m = Message()
        m.dn = dn
        m[attr] = MessageElement(value, FLAG_MOD_ADD, attr)
        self.ldb_admin.modify(m)

    def set_attr_search_flags(self, attr_dn, flags):
        """Modifies the searchFlags for an object in the schema"""
        m = Message()
        m.dn = Dn(self.ldb_admin, attr_dn)
        m['searchFlags'] = MessageElement(flags, FLAG_MOD_REPLACE,
                                          'searchFlags')
        self.ldb_admin.modify(m)

        # note we have to update the schema for this change to take effect (on
        # Windows, at least)
        self.ldb_admin.set_schema_update_now()

    def get_attr_search_flags(self, attr_dn):
        res = self.ldb_admin.search(attr_dn, scope=SCOPE_BASE,
                                    attrs=['searchFlags'])
        return res[0]['searchFlags'][0]

    def find_under_current_ou(self, res):
        for msg in res:
            if msg.dn == self.conf_dn:
                return msg
        self.fail(f"Failed to find object {self.conf_dn} in {len(res)} results")


class ConfidentialDirsyncTests(SpecialDirsyncTests):

    def setUp(self):
        self.flag_under_test = SEARCH_FLAG_CONFIDENTIAL
        super().setUp()

    def test_unicodePwd_normal(self):
        res = self.ldb_admin.search(self.base_dn,
                                    attrs=["unicodePwd", "supplementalCredentials", "samAccountName"],
                                    expression=f"(samAccountName={self.conf_user})")

        msg = res[0]

        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        self.assertTrue(msg.get("unicodePwd") is None)
        self.assertTrue(msg.get("supplementalCredentials") is None)

    def _test_dirsync_unicodePwd(self, ldb_conn, control=None, insist_on_empty_element=False):
        res = ldb_conn.search(self.base_dn,
                         attrs=["unicodePwd", "supplementalCredentials", "samAccountName"],
                         expression=f"(samAccountName={self.conf_user})",
                         controls=[control])

        msg = self.find_under_current_ou(res)

        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        if insist_on_empty_element:
            self.assertTrue(msg.get("unicodePwd") is not None)
            self.assertEqual(len(msg.get("unicodePwd")), 0)
            self.assertTrue(msg.get("supplementalCredentials") is not None)
            self.assertEqual(len(msg.get("supplementalCredentials")), 0)
        else:
            self.assertTrue(msg.get("unicodePwd") is None
                            or len(msg.get("unicodePwd")) == 0)
            self.assertTrue(msg.get("supplementalCredentials") is None
                            or len(msg.get("supplementalCredentials")) == 0)

    def test_dirsync_unicodePwd_OBJ_SEC(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_unicodePwd(ldb_conn, control="dirsync:1:1:0")

    def test_dirsync_unicodePwd_OBJ_SEC_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_unicodePwd(ldb_conn, control="dirsync:1:1:0", insist_on_empty_element=True)

    def test_dirsync_unicodePwd_with_GET_CHANGES_OBJ_SEC(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_unicodePwd(ldb_conn, control="dirsync:1:1:0")

    def test_dirsync_unicodePwd_with_GET_CHANGES_OBJ_SEC_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_unicodePwd(ldb_conn, control="dirsync:1:1:0", insist_on_empty_element=True)

    def test_dirsync_unicodePwd_with_GET_CHANGES(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_unicodePwd(ldb_conn, control="dirsync:1:0:0")

    def test_dirsync_unicodePwd_with_GET_CHANGES_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_unicodePwd(ldb_conn, control="dirsync:1:0:0", insist_on_empty_element=True)

    def test_normal(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = ldb_conn.search(self.base_dn,
                         attrs=[self.conf_attr, "samAccountName"],
                         expression=f"(samAccountName={self.conf_user})")

        msg = res[0]
        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        self.assertTrue(msg.get(self.conf_attr) is None)

    def _test_dirsync_OBJECT_SECURITY(self, ldb_conn, insist_on_empty_element=False):
        res = ldb_conn.search(self.base_dn,
                              attrs=[self.conf_attr, "samAccountName"],
                              expression=f"(samAccountName={self.conf_user})",
                              controls=["dirsync:1:1:0"])

        msg = self.find_under_current_ou(res)
        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        if insist_on_empty_element:
            self.assertTrue(msg.get(self.conf_attr) is not None)
            self.assertEqual(len(msg.get(self.conf_attr)), 0)
        else:
            self.assertTrue(msg.get(self.conf_attr) is None
                            or len(msg.get(self.conf_attr)) == 0)

    def test_dirsync_OBJECT_SECURITY(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn)

    def test_dirsync_OBJECT_SECURITY_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn, insist_on_empty_element=True)

    def test_dirsync_with_GET_CHANGES(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        res = ldb_conn.search(self.base_dn,
                         attrs=[self.conf_attr, "samAccountName"],
                         expression=f"(samAccountName={self.conf_user})",
                         controls=["dirsync:1:0:0"])

        msg = self.find_under_current_ou(res)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        self.assertTrue(msg.get(self.conf_attr))
        self.assertEqual(len(msg.get(self.conf_attr)), 1)

    def test_dirsync_with_GET_CHANGES_OBJECT_SECURITY(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn)

    def test_dirsync_with_GET_CHANGES_OBJECT_SECURITY_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn, insist_on_empty_element=True)

class FilteredDirsyncTests(SpecialDirsyncTests):

    def setUp(self):
        self.flag_under_test = SEARCH_FLAG_RODC_ATTRIBUTE
        super().setUp()

    def test_attr(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = ldb_conn.search(self.base_dn,
                         attrs=[self.conf_attr, "samAccountName"],
                         expression=f"(samAccountName={self.conf_user})")

        msg = res[0]
        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        self.assertTrue(msg.get(self.conf_attr))
        self.assertEqual(len(msg.get(self.conf_attr)), 1)

    def _test_dirsync_OBJECT_SECURITY(self, ldb_conn):
        res = ldb_conn.search(self.base_dn,
                         attrs=[self.conf_attr, "samAccountName"],
                         expression=f"(samAccountName={self.conf_user})",
                         controls=["dirsync:1:1:0"])

        msg = self.find_under_current_ou(res)
        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        self.assertTrue(msg.get(self.conf_attr))
        self.assertEqual(len(msg.get(self.conf_attr)), 1)

    def test_dirsync_OBJECT_SECURITY(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn)

    def test_dirsync_OBJECT_SECURITY_with_GET_CHANGES(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn)

    def _test_dirsync_with_GET_CHANGES(self, insist_on_empty_element=False):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        res = ldb_conn.search(self.base_dn,
                         expression=f"(samAccountName={self.conf_user})",
                         controls=["dirsync:1:0:0"])

        msg = self.find_under_current_ou(res)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        if insist_on_empty_element:
            self.assertTrue(msg.get(self.conf_attr) is not None)
            self.assertEqual(len(msg.get(self.conf_attr)), 0)
        else:
            self.assertTrue(msg.get(self.conf_attr) is None
                            or len(msg.get(self.conf_attr)) == 0)

    def test_dirsync_with_GET_CHANGES(self):
        self._test_dirsync_with_GET_CHANGES()

    def test_dirsync_with_GET_CHANGES_insist_on_empty_element(self):
        self._test_dirsync_with_GET_CHANGES(insist_on_empty_element=True)

    def test_dirsync_with_GET_CHANGES_attr(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        try:
            res = ldb_conn.search(self.base_dn,
                                  attrs=[self.conf_attr, "samAccountName"],
                                  expression=f"(samAccountName={self.conf_user})",
                                  controls=["dirsync:1:0:0"])
            self.fail("ldb.search() should have failed with LDAP_INSUFFICIENT_ACCESS_RIGHTS")
        except ldb.LdbError as e:
            (errno, errstr) = e.args
            self.assertEqual(errno, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS)

class ConfidentialFilteredDirsyncTests(SpecialDirsyncTests):

    def setUp(self):
        self.flag_under_test = SEARCH_FLAG_RODC_ATTRIBUTE|SEARCH_FLAG_CONFIDENTIAL
        super().setUp()

    def test_attr(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        res = ldb_conn.search(self.base_dn,
                         attrs=["unicodePwd", "supplementalCredentials", "samAccountName"],
                         expression=f"(samAccountName={self.conf_user})")

        msg = res[0]
        self.assertTrue(msg.get("samAccountName"))
        self.assertTrue(msg.get(self.conf_attr) is None)

    def _test_dirsync_OBJECT_SECURITY(self, ldb_conn, insist_on_empty_element=False):
        res = ldb_conn.search(self.base_dn,
                              attrs=[self.conf_attr, "samAccountName"],
                              expression=f"(samAccountName={self.conf_user})",
                              controls=["dirsync:1:1:0"])

        msg = self.find_under_current_ou(res)
        self.assertTrue("samAccountName" in msg)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        if insist_on_empty_element:
            self.assertTrue(msg.get(self.conf_attr) is not None)
            self.assertEqual(len(msg.get(self.conf_attr)), 0)
        else:
            self.assertTrue(msg.get(self.conf_attr) is None
                            or len(msg.get(self.conf_attr)) == 0)

    def test_dirsync_OBJECT_SECURITY(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn)

    def test_dirsync_OBJECT_SECURITY_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.simple_user, self.simple_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn, insist_on_empty_element=True)

    def test_dirsync_OBJECT_SECURITY_with_GET_CHANGES(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn)

    def test_dirsync_OBJECT_SECURITY_with_GET_CHANGES_insist_on_empty_element(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        self._test_dirsync_OBJECT_SECURITY(ldb_conn, insist_on_empty_element=True)

    def _test_dirsync_with_GET_CHANGES(self, insist_on_empty_element=False):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        res = ldb_conn.search(self.base_dn,
                         expression=f"(samAccountName={self.conf_user})",
                         controls=["dirsync:1:0:0"])

        msg = self.find_under_current_ou(res)
        # This form ensures this is a case insensitive comparison
        self.assertTrue(msg.get("samAccountName"))
        if insist_on_empty_element:
            self.assertTrue(msg.get(self.conf_attr) is not None)
            self.assertEqual(len(msg.get(self.conf_attr)), 0)
        else:
            self.assertTrue(msg.get(self.conf_attr) is None
                            or len(msg.get(self.conf_attr)) == 0)

    def test_dirsync_with_GET_CHANGES(self):
        self._test_dirsync_with_GET_CHANGES()

    def test_dirsync_with_GET_CHANGES_insist_on_empty_element(self):
        self._test_dirsync_with_GET_CHANGES(insist_on_empty_element=True)

    def test_dirsync_with_GET_CHANGES_attr(self):
        ldb_conn = self.get_ldb_connection(self.dirsync_user, self.dirsync_pass)
        try:
            res = ldb_conn.search(self.base_dn,
                                  attrs=[self.conf_attr, "samAccountName"],
                                  expression=f"(samAccountName={self.conf_user})",
                                  controls=["dirsync:1:0:0"])
            self.fail("ldb.search() should have failed with LDAP_INSUFFICIENT_ACCESS_RIGHTS")
        except ldb.LdbError as e:
            (errno, errstr) = e.args
            self.assertEqual(errno, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS)


if not getattr(opts, "listtests", False):
    lp = sambaopts.get_loadparm()
    samba.tests.cmdline_credentials = credopts.get_credentials(lp)


TestProgram(module=__name__, opts=subunitopts)
