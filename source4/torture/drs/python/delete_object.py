#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2010
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
#

#
# Usage:
#  export DC1=dc1_dns_name
#  export DC2=dc2_dns_name
#  export SUBUNITRUN=$samba4srcdir/scripting/bin/subunitrun
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN delete_object -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

from __future__ import print_function
import time


from ldb import (
    SCOPE_SUBTREE,
)

import drs_base
import ldb


class DrsDeleteObjectTestCase(drs_base.DrsBaseTestCase):

    def setUp(self):
        super(DrsDeleteObjectTestCase, self).setUp()
        # disable automatic replication temporary
        self._disable_all_repl(self.dnsname_dc1)
        self._disable_all_repl(self.dnsname_dc2)
        # make sure DCs are synchronized before the test
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

    def tearDown(self):
        self._enable_all_repl(self.dnsname_dc1)
        self._enable_all_repl(self.dnsname_dc2)
        super(DrsDeleteObjectTestCase, self).tearDown()

    def _make_username(self):
        return "DrsDelObjUser_" + time.strftime("%s", time.gmtime())

    # now also used to check the group
    def _check_obj(self, sam_ldb, obj_orig, is_deleted):
        # search the user by guid as it may be deleted
        guid_str = self._GUID_string(obj_orig["objectGUID"][0])
        expression = "(objectGUID=%s)" % guid_str
        res = sam_ldb.search(base=self.domain_dn,
                             expression=expression,
                             controls=["show_deleted:1"])
        self.assertEqual(len(res), 1)
        user_cur = res[0]
        # Deleted Object base DN
        dodn = self._deleted_objects_dn(sam_ldb)
        # now check properties of the user
        cn_orig = str(obj_orig["cn"][0])
        cn_cur  = str(user_cur["cn"][0])
        name_orig = str(obj_orig["name"][0])
        name_cur  = str(user_cur["name"][0])
        if is_deleted:
            self.assertEqual(str(user_cur["isDeleted"][0]), "TRUE")
            self.assertFalse("objectCategory" in user_cur)
            self.assertFalse("sAMAccountType" in user_cur)
            self.assertFalse("description" in user_cur)
            self.assertFalse("memberOf" in user_cur)
            self.assertFalse("member" in user_cur)
            self.assertTrue(dodn in str(user_cur["dn"]),
                            "User %s is deleted but it is not located under %s (found at %s)!" % (name_orig, dodn, user_cur["dn"]))
            self.assertEqual(name_cur, name_orig + "\nDEL:" + guid_str)
            self.assertEqual(name_cur, user_cur.dn.get_rdn_value())
            self.assertEqual(cn_cur, cn_orig + "\nDEL:" + guid_str)
            self.assertEqual(name_cur, cn_cur)
        else:
            self.assertFalse("isDeleted" in user_cur)
            self.assertEqual(name_cur, name_orig)
            self.assertEqual(name_cur, user_cur.dn.get_rdn_value())
            self.assertEqual(cn_cur, cn_orig)
            self.assertEqual(name_cur, cn_cur)
            self.assertEqual(obj_orig["dn"], user_cur["dn"])
            self.assertTrue(dodn not in str(user_cur["dn"]))
        return user_cur

    def test_ReplicateDeletedObject1(self):
        """Verifies how a deleted-object is replicated between two DCs.
           This test should verify that:
            - deleted-object is replicated properly
            - We verify that after replication,
              object's state to conform to a tombstone-object state
            - This test replicates the object modifications to
              the server with the user deleted first

           TODO:  It will also be great if check replPropertyMetaData.
           TODO:  Check for deleted-object state, depending on DC's features
                  when recycle-bin is enabled
           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username, password="P@sswOrd!")
        ldb_res = self.ldb_dc1.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEqual(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # delete user on DC1
        self.ldb_dc1.delete(user_dn)
        # check user info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=False)

        # The user should not have a description or memberOf yet
        self.assertFalse("description" in user_cur)
        self.assertFalse("memberOf" in user_cur)

        self.ldb_dc2.newgroup("group_%s" % username)

        self.ldb_dc2.newgroup("group2_%s" % username)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertTrue("sAMAccountName" in ldb_res[0])
        group_orig = ldb_res[0]
        group_dn = ldb_res[0]["dn"]

        # modify user on DC2 to have a description and be a member of the group
        m = ldb.Message()
        m.dn = user_dn
        m["description"] = ldb.MessageElement("a description",
                                              ldb.FLAG_MOD_ADD, "description")
        self.ldb_dc2.modify(m)
        m = ldb.Message()
        m.dn = group_dn
        m["member"] = ldb.MessageElement(str(user_dn),
                                         ldb.FLAG_MOD_ADD, "member")
        self.ldb_dc2.modify(m)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group2_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertTrue("sAMAccountName" in ldb_res[0])
        group2_dn = ldb_res[0]["dn"]
        group2_orig = ldb_res[0]

        m = ldb.Message()
        m.dn = group2_dn
        m["member"] = ldb.MessageElement(str(group_dn),
                                         ldb.FLAG_MOD_ADD, "member")
        self.ldb_dc2.modify(m)

        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=False)

        # The user should not have a description yet
        self.assertTrue("description" in user_cur)
        self.assertTrue("memberOf" in user_cur)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)

        # This group is a member of another group
        self.assertTrue("memberOf" in ldb_res[0])

        # The user was deleted on DC1, but check the modify we just did on DC2
        self.assertTrue("member" in ldb_res[0])

        # trigger replication from DC2 to DC1
        # to check if deleted object gets restored
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be valid user
        self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=False)

        ldb_res = self.ldb_dc1.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)

        # This group is a member of another group
        self.assertTrue("memberOf" in ldb_res[0])

        # The user was deleted on DC1, but the modify we did on DC2, check it never replicated in
        self.assertFalse("member" in ldb_res[0])

        # trigger replication from DC1 to DC2
        # to check if deleted object is replicated
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=True)

        # delete group on DC1
        self.ldb_dc1.delete(group_dn)

        # trigger replication from DC1 to DC2
        # to check if deleted object is replicated
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check group info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=group_orig, is_deleted=True)
        # check group info on DC2 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=group_orig, is_deleted=True)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group2_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertFalse("member" in ldb_res[0])

        # delete group on DC1
        self.ldb_dc1.delete(group2_dn)

        # trigger replication from DC1 to DC2
        # to check if deleted object is replicated
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check group info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=group2_orig, is_deleted=True)
        # check group info on DC2 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=group2_orig, is_deleted=True)

    def test_ReplicateDeletedObject2(self):
        """Verifies how a deleted-object is replicated between two DCs.
           This test should verify that:
            - deleted-object is replicated properly
            - We verify that after replication,
              object's state to conform to a tombstone-object state
            - This test replicates the delete to the server with the
              object modifications first

           TODO:  It will also be great if check replPropertyMetaData.
           TODO:  Check for deleted-object state, depending on DC's features
                  when recycle-bin is enabled
           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username, password="P@sswOrd!")
        ldb_res = self.ldb_dc1.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEqual(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # delete user on DC1
        self.ldb_dc1.delete(user_dn)
        # check user info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=False)

        # The user should not have a description or memberOf yet
        self.assertFalse("description" in user_cur)
        self.assertFalse("memberOf" in user_cur)

        self.ldb_dc2.newgroup("group_%s" % username)

        self.ldb_dc2.newgroup("group2_%s" % username)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertTrue("sAMAccountName" in ldb_res[0])
        group_orig = ldb_res[0]
        group_dn = ldb_res[0]["dn"]

        # modify user on DC2 to have a description and be a member of the group
        m = ldb.Message()
        m.dn = user_dn
        m["description"] = ldb.MessageElement("a description",
                                              ldb.FLAG_MOD_ADD, "description")
        self.ldb_dc2.modify(m)
        m = ldb.Message()
        m.dn = group_dn
        m["member"] = ldb.MessageElement(str(user_dn),
                                         ldb.FLAG_MOD_ADD, "member")
        self.ldb_dc2.modify(m)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group2_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertTrue("sAMAccountName" in ldb_res[0])
        group2_dn = ldb_res[0]["dn"]
        group2_orig = ldb_res[0]

        m = ldb.Message()
        m.dn = group2_dn
        m["member"] = ldb.MessageElement(str(group_dn),
                                         ldb.FLAG_MOD_ADD, "member")
        self.ldb_dc2.modify(m)

        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=False)

        # The user should not have a description yet
        self.assertTrue("description" in user_cur)
        self.assertTrue("memberOf" in user_cur)

        # trigger replication from DC1 to DC2
        # to check if deleted object gets restored
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=True)

        ldb_res = self.ldb_dc2.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertTrue("memberOf" in ldb_res[0])
        self.assertFalse("member" in ldb_res[0])

        # trigger replication from DC2 to DC1
        # to check if deleted object is replicated
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC1 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=True)
        # check user info on DC2 - should be deleted
        self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=True)

        ldb_res = self.ldb_dc1.search(base=self.domain_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=group_%s)" % username)
        self.assertTrue(len(ldb_res) == 1)
        self.assertTrue("memberOf" in ldb_res[0])
        self.assertFalse("member" in ldb_res[0])

        # delete group on DC1
        self.ldb_dc1.delete(group_dn)
        self.ldb_dc1.delete(group2_dn)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
