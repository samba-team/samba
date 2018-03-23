#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2010
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2016
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN repl_move -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

from __future__ import print_function
import time
import uuid

from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs
from samba.dcerpc import misc
from samba.drs_utils import drs_DsBind

from ldb import (
    SCOPE_BASE,
    SCOPE_SUBTREE,
    )

import drs_base, ldb
from samba.dcerpc.drsuapi import *

class DrsMoveObjectTestCase(drs_base.DrsBaseTestCase):

    def _ds_bind(self, server_name):
        binding_str = "ncacn_ip_tcp:%s[print,seal]" % server_name

        drs = drsuapi(binding_str, self.get_loadparm(), self.get_credentials())
        (drs_handle, supported_extensions) = drs_DsBind(drs)
        return (drs, drs_handle)

    def setUp(self):
        super(DrsMoveObjectTestCase, self).setUp()
        # disable automatic replication temporary
        self._disable_all_repl(self.dnsname_dc1)
        self._disable_all_repl(self.dnsname_dc2)

        # make sure DCs are synchronized before the test
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        self.ou1_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU1")
        self.ou1_dn.add_base(self.ldb_dc1.get_default_basedn())
        ou1 = {}
        ou1["dn"] = self.ou1_dn
        ou1["objectclass"] = "organizationalUnit"
        ou1["ou"] = self.ou1_dn.get_component_value(0)
        self.ldb_dc1.add(ou1)

        self.ou2_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU2")
        self.ou2_dn.add_base(self.ldb_dc1.get_default_basedn())
        ou2 = {}
        ou2["dn"] = self.ou2_dn
        ou2["objectclass"] = "organizationalUnit"
        ou2["ou"] = self.ou2_dn.get_component_value(0)
        self.ldb_dc1.add(ou2)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        self.dc1_guid = self.ldb_dc1.get_invocation_id()
        self.dc2_guid = self.ldb_dc2.get_invocation_id()

        self.drs_dc1 = self._ds_bind(self.dnsname_dc1)
        self.drs_dc2 = self._ds_bind(self.dnsname_dc2)

    def tearDown(self):
        try:
            self.ldb_dc1.delete(self.ou1_dn, ["tree_delete:1"])
        except ldb.LdbError as e:
            (enum, string) = e.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                pass

        self.ldb_dc1.delete(self.ou2_dn, ["tree_delete:1"])
        self._enable_all_repl(self.dnsname_dc1)
        self._enable_all_repl(self.dnsname_dc2)
        super(DrsMoveObjectTestCase, self).tearDown()

    def _make_username(self):
        return "DrsMoveU_" + time.strftime("%s", time.gmtime())

    def _check_metadata(self, user_dn, sam_ldb, drs, metadata, expected):
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob, str(metadata[0]))

        self.assertEqual(len(repl.ctr.array), len(expected))

        i = 0
        for o in repl.ctr.array:
            e = expected[i]
            (attid, orig_dsa, version) = e
            self.assertEquals(attid, o.attid,
                              "(LDAP) Wrong attid "
                              "for expected value %d, wanted 0x%08x got 0x%08x"
                              % (i, attid, o.attid))
            self.assertEquals(o.originating_invocation_id,
                              misc.GUID(orig_dsa),
                              "(LDAP) Wrong originating_invocation_id "
                              "for expected value %d, attid 0x%08x, wanted %s got %s"
                              % (i, o.attid,
                                 misc.GUID(orig_dsa),
                                 o.originating_invocation_id))
            # Allow version to be skipped when it does not matter
            if version is not None:
                self.assertEquals(o.version, version,
                                  "(LDAP) Wrong version for expected value %d, "
                                  "attid 0x%08x, "
                                  "wanted %d got %d"
                                  % (i, o.attid,
                                     version, o.version))
            i = i + 1

        if drs == None:
            return

        req8 = DsGetNCChangesRequest8()

        req8.source_dsa_invocation_id = misc.GUID(sam_ldb.get_invocation_id())
        req8.naming_context = DsReplicaObjectIdentifier()
        req8.naming_context.dn = str(user_dn)
        req8.highwatermark = DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn = 0
        req8.highwatermark.reserved_usn = 0
        req8.highwatermark.highest_usn = 0
        req8.uptodateness_vector = None
        req8.replica_flags = DRSUAPI_DRS_SYNC_FORCED
        req8.max_object_count = 1
        req8.max_ndr_size = 402116
        req8.extended_op = DRSUAPI_EXOP_REPL_OBJ
        req8.fsmo_info = 0
        req8.partial_attribute_set = None
        req8.partial_attribute_set_ex = None
        req8.mapping_ctr.num_mappings = 0
        req8.mapping_ctr.mappings = None

        (drs_conn, drs_handle) = drs

        (level, drs_ctr) = drs_conn.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6)
        self.assertEqual(drs_ctr.object_count, 1)

        self.assertEqual(len(drs_ctr.first_object.meta_data_ctr.meta_data), len(expected) - 1)
        att_idx = 0
        for o in drs_ctr.first_object.meta_data_ctr.meta_data:
            i = 0
            drs_attid = drs_ctr.first_object.object.attribute_ctr.attributes[att_idx]
            e = expected[i];
            (attid, orig_dsa, version) = e

            # Skip the RDN from the expected set, it is not sent over DRS
            if (user_dn.get_rdn_name().upper() == "CN" \
                and attid == DRSUAPI_ATTID_cn) \
                or (user_dn.get_rdn_name().upper() == "OU" \
                    and attid == DRSUAPI_ATTID_ou):
                i = i + 1
                e = expected[i];
                (attid, orig_dsa, version) = e

            self.assertEquals(attid, drs_attid.attid,
                              "(DRS) Wrong attid "
                              "for expected value %d, wanted 0x%08x got 0x%08x"
                              % (i, attid, drs_attid.attid))

            self.assertEquals(o.originating_invocation_id,
                              misc.GUID(orig_dsa),
                              "(DRS) Wrong originating_invocation_id "
                              "for expected value %d, attid 0x%08x, wanted %s got %s"
                              % (i, attid,
                                 misc.GUID(orig_dsa),
                                 o.originating_invocation_id))
            # Allow version to be skipped when it does not matter
            if version is not None:
                self.assertEquals(o.version, version,
                                  "(DRS) Wrong version for expected value %d, "
                                  "attid 0x%08x, "
                                  "wanted %d got %d"
                                  % (i, attid, version, o.version))
                break
            i = i + 1
            att_idx = att_idx + 1

    # now also used to check the group
    def _check_obj(self, sam_ldb, obj_orig, is_deleted, expected_metadata=None, drs=None):
        # search the user by guid as it may be deleted
        guid_str = self._GUID_string(obj_orig["objectGUID"][0])
        res = sam_ldb.search(base='<GUID=%s>' % guid_str,
                             controls=["show_deleted:1"],
                             attrs=["*", "parentGUID",
                                    "replPropertyMetaData"])
        self.assertEquals(len(res), 1)
        user_cur = res[0]
        rdn_orig = obj_orig[user_cur.dn.get_rdn_name()][0]
        rdn_cur  = user_cur[user_cur.dn.get_rdn_name()][0]
        name_orig = obj_orig["name"][0]
        name_cur  = user_cur["name"][0]
        dn_orig = obj_orig["dn"]
        dn_cur  = user_cur["dn"]
        # now check properties of the user
        if is_deleted:
            self.assertTrue("isDeleted" in user_cur)
            self.assertEquals(rdn_cur.split('\n')[0], rdn_orig)
            self.assertEquals(name_cur.split('\n')[0], name_orig)
            self.assertEquals(dn_cur.get_rdn_value().split('\n')[0],
                              dn_orig.get_rdn_value())
            self.assertEqual(name_cur, rdn_cur)
        else:
            self.assertFalse("isDeleted" in user_cur)
            self.assertEquals(rdn_cur, rdn_orig)
            self.assertEquals(name_cur, name_orig)
            self.assertEquals(dn_cur, dn_orig)
            self.assertEqual(name_cur, rdn_cur)
            parent_cur  = user_cur["parentGUID"][0]
            try:
                parent_orig = obj_orig["parentGUID"][0]
                self.assertEqual(parent_orig, parent_cur)
            except KeyError:
                pass
        self.assertEqual(name_cur, user_cur.dn.get_rdn_value())

        if expected_metadata is not None:
            self._check_metadata(dn_cur, sam_ldb, drs, user_cur["replPropertyMetaData"],
                                 expected_metadata)

        return user_cur


    def test_ReplicateMoveObject1(self):
        """Verifies how a moved container with a user inside is replicated between two DCs.
           This test should verify that:
            - the OU is replicated properly
            - the OU is renamed
            - We verify that after replication,
              that the user has the correct DN (under OU2)
            - the OU is deleted
            - the OU is modified on DC2
            - We verify that after replication,
              that the user has the correct DN (deleted) and has not description

           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        initial_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                        obj_orig=user_orig, is_deleted=False,
                        expected_metadata=initial_metadata)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        moved_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC1 after rename - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=moved_metadata)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        moved_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=moved_metadata_dc2)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))
        deleted_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_moved_orig, is_deleted=True, expected_metadata=deleted_metadata)

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = new_dn
        msg["description"] = ldb.MessageElement("User Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        modified_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 1),
            (DRSUAPI_ATTID_description, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=modified_metadata)


        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        deleted_modified_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 2),
            (DRSUAPI_ATTID_description, self.dc2_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC2 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_modified_metadata_dc2)
        self.assertFalse("description" in user_cur)

        # trigger replication from DC2 to DC1, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        deleted_modified_metadata_dc1 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_description, self.dc2_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_modified_metadata_dc1)
        self.assertFalse("description" in user_cur)


    def test_ReplicateMoveObject2(self):
        """Verifies how a moved container with a user inside is not
           replicated between two DCs as no replication is triggered
           This test should verify that:
            - the OU is not replicated
            - the user is not replicated

           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        initial_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                        obj_orig=user_orig, is_deleted=False,
                        expected_metadata=initial_metadata)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_moved_orig = ldb_res[0]

        moved_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC1 after rename - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=moved_metadata)

        # check user info on DC2 - should not be there, we have not done replication
        ldb_res = self.ldb_dc2.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 0)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        deleted_metadata_dc1 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)
        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        deleted_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC2 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc2)

        # trigger replication from DC2 to DC1, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)


    def test_ReplicateMoveObject3(self):
        """Verifies how a moved container with a user inside is replicated between two DCs.
           This test should verify that:
            - the OU is created on DC1
            - the OU is renamed on DC1
            - We verify that after replication,
              that the user has the correct DN (under OU2).

           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        initial_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                        obj_orig=user_orig, is_deleted=False,
                        expected_metadata=initial_metadata)


        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        moved_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC1 after rename - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=moved_metadata)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))
        deleted_metadata_dc1 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        deleted_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC2 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc2)


    def test_ReplicateMoveObject3b(self):
        """Verifies how a moved container with a user inside is replicated between two DCs.
           This test should verify that:
            - the OU is created on DC1
            - the OU is renamed on DC1
            - We verify that after replication,
              that the user has the correct DN (under OU2).

           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        initial_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                        obj_orig=user_orig, is_deleted=False,
                        expected_metadata=initial_metadata)


        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC2 (Which has never seen the object) to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        moved_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC1 after rename - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=moved_metadata)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))
        deleted_metadata_dc1 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        deleted_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC2 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc2)


    def test_ReplicateMoveObject4(self):
        """Verifies how a moved container with a user inside is replicated between two DCs.
           This test should verify that:
            - the OU is replicated properly
            - the user is modified on DC2
            - the OU is renamed on DC1
            - We verify that after replication DC1 -> DC2,
              that the user has the correct DN (under OU2), and the description

           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        initial_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                        obj_orig=user_orig, is_deleted=False,
                        expected_metadata=initial_metadata)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        initial_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC2 - should still be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_orig, is_deleted=False,
                                   expected_metadata=initial_metadata_dc2)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        moved_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC1 after rename - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=moved_metadata)

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = user_dn
        msg["description"] = ldb.MessageElement("User Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        modified_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 1),
            (DRSUAPI_ATTID_description, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_orig,
                                   is_deleted=False,
                                   expected_metadata=modified_metadata)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        modified_renamed_metadata = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 2),
            (DRSUAPI_ATTID_description, self.dc2_guid, 1),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 1),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 1),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 1),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 1),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 1)]

        # check user info on DC2 - should still be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=modified_renamed_metadata)

        self.assertTrue("description" in user_cur)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))
        deleted_metadata_dc1 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC2 - should still be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=False,
                                   expected_metadata=modified_renamed_metadata)

        self.assertTrue("description" in user_cur)

        deleted_metadata_dc1 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc1_guid, 2),
            (DRSUAPI_ATTID_description, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]


        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, drs=self.drs_dc1,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc1)

        self.assertFalse("description" in user_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        deleted_metadata_dc2 = [
            (DRSUAPI_ATTID_objectClass, self.dc1_guid, 1),
            (DRSUAPI_ATTID_cn, self.dc2_guid, 3),
            (DRSUAPI_ATTID_description, self.dc1_guid, 2),
            (DRSUAPI_ATTID_instanceType, self.dc1_guid, 1),
            (DRSUAPI_ATTID_whenCreated, self.dc1_guid, 1),
            (DRSUAPI_ATTID_isDeleted, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntSecurityDescriptor, self.dc1_guid, 1),
            (DRSUAPI_ATTID_name, self.dc1_guid, 3),
            (DRSUAPI_ATTID_userAccountControl, self.dc1_guid, None),
            (DRSUAPI_ATTID_codePage, self.dc1_guid, 2),
            (DRSUAPI_ATTID_countryCode, self.dc1_guid, 2),
            (DRSUAPI_ATTID_dBCSPwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_logonHours, self.dc1_guid, 1),
            (DRSUAPI_ATTID_unicodePwd, self.dc1_guid, 1),
            (DRSUAPI_ATTID_ntPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_pwdLastSet, self.dc1_guid, 2),
            (DRSUAPI_ATTID_primaryGroupID, self.dc1_guid, 2),
            (DRSUAPI_ATTID_objectSid, self.dc1_guid, 1),
            (DRSUAPI_ATTID_accountExpires, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lmPwdHistory, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountName, self.dc1_guid, 1),
            (DRSUAPI_ATTID_sAMAccountType, self.dc1_guid, 2),
            (DRSUAPI_ATTID_userPrincipalName, self.dc1_guid, 2),
            (DRSUAPI_ATTID_lastKnownParent, self.dc1_guid, 1),
            (DRSUAPI_ATTID_objectCategory, self.dc1_guid, 2),
            (DRSUAPI_ATTID_isRecycled, self.dc1_guid, 1)]

        # check user info on DC2 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, drs=self.drs_dc2,
                                   obj_orig=user_moved_orig,
                                   is_deleted=True,
                                   expected_metadata=deleted_metadata_dc2)

        self.assertFalse("description" in user_cur)

    def test_ReplicateMoveObject5(self):
        """Verifies how a moved container with a user inside is replicated between two DCs.
           This test should verify that:
            - the OU is replicated properly
            - the user is modified on DC2
            - the OU is renamed on DC1
            - We verify that after replication DC2 -> DC1,
              that the user has the correct DN (under OU2), and the description

           """
        # work-out unique username to test with
        username = self._make_username()

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = user_dn
        msg["description"] = ldb.MessageElement("User Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC1 - should still be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_moved_orig, is_deleted=False)
        self.assertTrue("description" in user_cur)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)
        self.assertTrue("description" in user_cur)

        # delete user on DC2
        self.ldb_dc2.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))
        # trigger replication from DC2 to DC1 for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_moved_orig, is_deleted=True)
        self.assertFalse("description" in user_cur)


    def test_ReplicateMoveObject6(self):
        """Verifies how a moved container is replicated between two DCs.
           This test should verify that:
            - the OU1 is replicated properly
            - the OU1 is modified on DC2
            - the OU1 is renamed on DC1
            - We verify that after replication DC1 -> DC2,
              that the OU1 has the correct DN (under OU2), and the description

           """
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        ou_orig = ldb_res[0]
        ou_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (self.ou1_dn, self._GUID_string(ou_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        new_dn = ldb.Dn(self.ldb_dc1, "OU=%s" % self.ou1_dn.get_component_value(0))
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(ou_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=new_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        ou_moved_orig = ldb_res[0]
        ou_moved_dn   = ldb_res[0]["dn"]

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = ou_dn
        msg["description"] = ldb.MessageElement("OU Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_moved_orig, is_deleted=False)
        self.assertTrue("description" in ou_cur)

        # delete OU on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(ou_orig["objectGUID"][0]))
        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)


    def test_ReplicateMoveObject7(self):
        """Verifies how a moved container is replicated between two DCs.
           This test should verify that:
            - the OU1 is replicated properly
            - the OU1 is modified on DC2
            - the OU1 is renamed on DC1 to be under OU2
            - We verify that after replication DC2 -> DC1,
              that the OU1 has the correct DN (under OU2), and the description

           """
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        ou_orig = ldb_res[0]
        ou_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (self.ou1_dn, self._GUID_string(ou_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        new_dn = ldb.Dn(self.ldb_dc1, "OU=%s" % self.ou1_dn.get_component_value(0))
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(ou_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=new_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        ou_moved_orig = ldb_res[0]
        ou_moved_dn   = ldb_res[0]["dn"]

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = ou_dn
        msg["description"] = ldb.MessageElement("OU Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC1 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_moved_orig, is_deleted=False)
        self.assertTrue("description" in ou_cur)

        # delete OU on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(ou_orig["objectGUID"][0]))
        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)


    def test_ReplicateMoveObject8(self):
        """Verifies how a moved container is replicated between two DCs.
           This test should verify that:
            - the OU1 is replicated properly
            - the OU1 is modified on DC2
            - the OU1 is renamed on DC1 to OU1-renamed
            - We verify that after replication DC1 -> DC2,
              that the OU1 has the correct DN (OU1-renamed), and the description

           """
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        ou_orig = ldb_res[0]
        ou_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (self.ou1_dn, self._GUID_string(ou_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        new_dn = ldb.Dn(self.ldb_dc1, "OU=%s-renamed" % self.ou1_dn.get_component_value(0))
        new_dn.add_base(self.ou1_dn.parent())
        self.ldb_dc1.rename(ou_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=new_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        ou_moved_orig = ldb_res[0]
        ou_moved_dn   = ldb_res[0]["dn"]

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = ou_dn
        msg["description"] = ldb.MessageElement("OU Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_moved_orig, is_deleted=False)
        self.assertTrue("description" in ou_cur)

        # delete OU on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(ou_orig["objectGUID"][0]))
        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)


    def test_ReplicateMoveObject9(self):
        """Verifies how a moved container is replicated between two DCs.
           This test should verify that:
            - the OU1 is replicated properly
            - the OU1 is modified on DC2
            - the OU1 is renamed on DC1 to be under OU2
            - the OU1 is renamed on DC1 to OU1-renamed
            - We verify that after replication DC1 -> DC2,
              that the OU1 has the correct DN (OU1-renamed), and the description

           """
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        ou_orig = ldb_res[0]
        ou_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (self.ou1_dn, self._GUID_string(ou_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        new_dn = ldb.Dn(self.ldb_dc1, "OU=%s-renamed" % self.ou1_dn.get_component_value(0))
        new_dn.add_base(self.ou1_dn.parent())
        self.ldb_dc1.rename(ou_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=new_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        ou_moved_orig = ldb_res[0]
        ou_moved_dn   = ldb_res[0]["dn"]

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = ou_dn
        msg["description"] = ldb.MessageElement("OU Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC1 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_moved_orig, is_deleted=False)
        self.assertTrue("description" in ou_cur)

        # delete OU on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(ou_orig["objectGUID"][0]))
        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check user info on DC2 - should be deleted user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_moved_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)


    def test_ReplicateMoveObject10(self):
        """Verifies how a moved container is replicated between two DCs.
           This test should verify that:
            - the OU1 is replicated properly
            - the OU1 is modified on DC2
            - the OU1 is deleted on DC1
            - We verify that after replication DC1 -> DC2,
              that the OU1 is deleted, and the description has gone away

           """
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        ou_orig = ldb_res[0]
        ou_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (self.ou1_dn, self._GUID_string(ou_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = ou_dn
        msg["description"] = ldb.MessageElement("OU Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # delete OU on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(ou_orig["objectGUID"][0]))
        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be deleted OU
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        # check user info on DC2 - should be deleted OU
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)


    def test_ReplicateMoveObject11(self):
        """Verifies how a moved container is replicated between two DCs.
           This test should verify that:
            - the OU1 is replicated properly
            - the OU1 is modified on DC2
            - the OU1 is deleted on DC1
            - We verify that after replication DC2 -> DC1,
              that the OU1 is deleted, and the description has gone away

           """
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_BASE,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        ou_orig = ldb_res[0]
        ou_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (self.ou1_dn, self._GUID_string(ou_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should still be valid user
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=False)

        # Modify description on DC2.  This triggers a replication, but
        # not of 'name' and so a bug in Samba regarding the DN.
        msg = ldb.Message()
        msg.dn = ou_dn
        msg["description"] = ldb.MessageElement("OU Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # delete OU on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(ou_orig["objectGUID"][0]))
        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC2 - should be deleted OU
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=ou_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # check user info on DC2 - should be deleted OU
        ou_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=ou_orig, is_deleted=True)
        self.assertFalse("description" in ou_cur)



class DrsMoveBetweenTreeOfObjectTestCase(drs_base.DrsBaseTestCase):

    def setUp(self):
        super(DrsMoveBetweenTreeOfObjectTestCase, self).setUp()
        # disable automatic replication temporary
        self._disable_all_repl(self.dnsname_dc1)
        self._disable_all_repl(self.dnsname_dc2)

        # make sure DCs are synchronized before the test
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)

        self.ou1_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU1")
        self.ou1_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou1 = {}
        self.ou1["dn"] = self.ou1_dn
        self.ou1["objectclass"] = "organizationalUnit"
        self.ou1["ou"] = self.ou1_dn.get_component_value(0)

        self.ou2_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU2,OU=DrsOU1")
        self.ou2_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou2 = {}
        self.ou2["dn"] = self.ou2_dn
        self.ou2["objectclass"] = "organizationalUnit"
        self.ou2["ou"] = self.ou2_dn.get_component_value(0)

        self.ou2b_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU2B,OU=DrsOU1")
        self.ou2b_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou2b = {}
        self.ou2b["dn"] = self.ou2b_dn
        self.ou2b["objectclass"] = "organizationalUnit"
        self.ou2b["ou"] = self.ou2b_dn.get_component_value(0)

        self.ou2c_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU2C,OU=DrsOU1")
        self.ou2c_dn.add_base(self.ldb_dc1.get_default_basedn())

        self.ou3_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU3,OU=DrsOU2,OU=DrsOU1")
        self.ou3_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou3 = {}
        self.ou3["dn"] = self.ou3_dn
        self.ou3["objectclass"] = "organizationalUnit"
        self.ou3["ou"] = self.ou3_dn.get_component_value(0)

        self.ou4_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU4,OU=DrsOU3,OU=DrsOU2,OU=DrsOU1")
        self.ou4_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou4 = {}
        self.ou4["dn"] = self.ou4_dn
        self.ou4["objectclass"] = "organizationalUnit"
        self.ou4["ou"] = self.ou4_dn.get_component_value(0)

        self.ou5_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU5,OU=DrsOU4,OU=DrsOU3,OU=DrsOU2,OU=DrsOU1")
        self.ou5_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou5 = {}
        self.ou5["dn"] = self.ou5_dn
        self.ou5["objectclass"] = "organizationalUnit"
        self.ou5["ou"] = self.ou5_dn.get_component_value(0)

        self.ou6_dn = ldb.Dn(self.ldb_dc1, "OU=DrsOU6,OU=DrsOU5,OU=DrsOU4,OU=DrsOU3,OU=DrsOU2,OU=DrsOU1")
        self.ou6_dn.add_base(self.ldb_dc1.get_default_basedn())
        self.ou6 = {}
        self.ou6["dn"] = self.ou6_dn
        self.ou6["objectclass"] = "organizationalUnit"
        self.ou6["ou"] = self.ou6_dn.get_component_value(0)


    def tearDown(self):
        self.ldb_dc1.delete(self.ou1_dn, ["tree_delete:1"])
        self._enable_all_repl(self.dnsname_dc1)
        self._enable_all_repl(self.dnsname_dc2)
        super(DrsMoveBetweenTreeOfObjectTestCase, self).tearDown()

    def _make_username(self):
        return "DrsTreeU_" + time.strftime("%s", time.gmtime())

    # now also used to check the group
    def _check_obj(self, sam_ldb, obj_orig, is_deleted):
        # search the user by guid as it may be deleted
        guid_str = self._GUID_string(obj_orig["objectGUID"][0])
        res = sam_ldb.search(base='<GUID=%s>' % guid_str,
                             controls=["show_deleted:1"],
                             attrs=["*", "parentGUID"])
        self.assertEquals(len(res), 1)
        user_cur = res[0]
        cn_orig = obj_orig["cn"][0]
        cn_cur  = user_cur["cn"][0]
        name_orig = obj_orig["name"][0]
        name_cur  = user_cur["name"][0]
        dn_orig = obj_orig["dn"]
        dn_cur  = user_cur["dn"]
        # now check properties of the user
        if is_deleted:
            self.assertTrue("isDeleted" in user_cur)
            self.assertEquals(cn_cur.split('\n')[0], cn_orig)
            self.assertEquals(name_cur.split('\n')[0], name_orig)
            self.assertEquals(dn_cur.get_rdn_value().split('\n')[0],
                              dn_orig.get_rdn_value())
            self.assertEqual(name_cur, cn_cur)
        else:
            self.assertFalse("isDeleted" in user_cur)
            self.assertEquals(cn_cur, cn_orig)
            self.assertEquals(name_cur, name_orig)
            self.assertEquals(dn_cur, dn_orig)
            self.assertEqual(name_cur, cn_cur)
        self.assertEqual(name_cur, user_cur.dn.get_rdn_value())

        return user_cur


    def test_ReplicateMoveInTree1(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - a complex OU tree can be replicated correctly
            - the user is in the correct spot (renamed into) within the tree
              on both DCs
           """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        self.ldb_dc1.add(self.ou2)
        self.ldb_dc1.add(self.ou3)
        self.ldb_dc1.add(self.ou4)
        self.ldb_dc1.add(self.ou5)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou5_dn)
        self.ldb_dc1.rename(user_dn, new_dn)
        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)


    def test_ReplicateMoveInTree2(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - a complex OU tree can be replicated correctly
            - the user is in the correct spot (renamed into) within the tree
              on both DCs
            - that a rename back works correctly, and is replicated
           """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        self.ldb_dc1.add(self.ou2)
        self.ldb_dc1.add(self.ou2b)
        self.ldb_dc1.add(self.ou3)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou3_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        new_dn3 = ldb.Dn(self.ldb_dc1, "OU=%s" % self.ou3_dn.get_component_value(0))
        new_dn3.add_base(self.ou2b_dn)
        self.ldb_dc1.rename(self.ou3_dn, new_dn3)

        ldb_res = self.ldb_dc1.search(base=new_dn3,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)

        # Rename on DC1
        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou1_dn)
        self.ldb_dc1.rename(user_moved_dn, new_dn)

        # Modify description on DC2
        msg = ldb.Message()
        msg.dn = user_moved_dn
        msg["description"] = ldb.MessageElement("User Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)
        self.assertTrue("description" in user_cur)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC2 to DC1
        self._net_drs_replicate(DC=self.dnsname_dc1, fromDC=self.dnsname_dc2, forced=True)
        # check user info on DC1 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_moved_orig, is_deleted=True)
        self.assertFalse("description" in user_cur)

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be deleted user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=True)
        self.assertFalse("description" in user_cur)


    def test_ReplicateMoveInTree3(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - a complex OU tree can be replicated correctly
            - the user is in the correct spot (renamed into) within the tree
              on both DCs
            - that a rename back works correctly, and is replicated
           """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        self.ldb_dc1.add(self.ou2)
        self.ldb_dc1.add(self.ou2b)
        self.ldb_dc1.add(self.ou3)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou3_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        new_dn3 = ldb.Dn(self.ldb_dc1, "OU=%s" % self.ou3_dn.get_component_value(0))
        new_dn3.add_base(self.ou2b_dn)
        self.ldb_dc1.rename(self.ou3_dn, new_dn3)

        ldb_res = self.ldb_dc1.search(base=new_dn3,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_moved_dn, new_dn)

        self.ldb_dc1.rename(self.ou2_dn, self.ou2c_dn)
        self.ldb_dc1.rename(self.ou2b_dn, self.ou2_dn)
        self.ldb_dc1.rename(self.ou2c_dn, self.ou2b_dn)

        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)

        self.assertEquals(user_cur["parentGUID"], user_moved_orig["parentGUID"])

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)


    def test_ReplicateMoveInTree3b(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - a complex OU tree can be replicated correctly
            - the user is in the correct spot (renamed into) within the tree
              on both DCs
            - that a rename back works correctly, and is replicated
            - that a complex rename suffle, combined with unrelated changes to the object,
              is replicated correctly.  The aim here is the send the objects out-of-order
              when sorted by usnChanged.
            - confirm that the OU tree and (in particular the user DN) is identical between
              the DCs once this has been replicated.
        """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        self.ldb_dc1.add(self.ou2)
        self.ldb_dc1.add(self.ou2b)
        self.ldb_dc1.add(self.ou3)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)

        msg = ldb.Message()
        msg.dn = new_dn
        msg["description"] = ldb.MessageElement("User Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        # The sleep(1) calls here ensure that the name objects get a
        # new 1-sec based timestamp, and so we select how the conflict
        # resolution resolves.
        self.ldb_dc1.rename(self.ou2_dn, self.ou2c_dn)
        time.sleep(1)
        self.ldb_dc1.rename(self.ou2b_dn, self.ou2_dn)
        time.sleep(1)
        self.ldb_dc1.rename(self.ou2c_dn, self.ou2b_dn)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]), new_dn)

        msg = ldb.Message()
        msg.dn = self.ou2_dn
        msg["description"] = ldb.MessageElement("OU2 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        msg = ldb.Message()
        msg.dn = self.ou2b_dn
        msg["description"] = ldb.MessageElement("OU2b Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)
        self.assertEquals(user_cur["parentGUID"][0], user_moved_orig["parentGUID"][0])

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)


    def test_ReplicateMoveInTree4(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - an OU and user can be replicated correctly, even after a rename
            - The creation and rename of the OU has been combined with unrelated changes to the object,
              The aim here is the send the objects out-of-order when sorted by usnChanged.
            - That is, the OU will be sorted by usnChanged after the user that is within that OU.
            - That will cause the client to need to get the OU first, by use of the GET_ANC flag
        """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # check user info on DC1
        print("Testing for %s with GUID %s" % (username, self._GUID_string(user_orig["objectGUID"][0])))
        self._check_obj(sam_ldb=self.ldb_dc1, obj_orig=user_orig, is_deleted=False)

        self.ldb_dc1.add(self.ou2)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        msg = ldb.Message()
        msg.dn = self.ou2_dn
        msg["description"] = ldb.MessageElement("OU2 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        ldb_res = self.ldb_dc1.search(base=self.ou2_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username)
        self.assertEquals(len(ldb_res), 1)

        user_moved_orig = ldb_res[0]
        user_moved_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved_orig, is_deleted=False)

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)


    def test_ReplicateAddInOU(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - an OU and user can be replicated correctly
            - The creation of the OU has been combined with unrelated changes to the object,
              The aim here is the send the objects out-of-order when sorted by usnChanged.
            - That is, the OU will be sorted by usnChanged after the user that is within that OU.
            - That will cause the client to need to get the OU first, by use of the GET_ANC flag
        """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        msg = ldb.Message()
        msg.dn = self.ou1_dn
        msg["description"] = ldb.MessageElement("OU1 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_orig, is_deleted=False)

        self.assertEquals(user_cur["parentGUID"], user_orig["parentGUID"])

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)


    def test_ReplicateAddInMovedOU(self):
        """Verifies how an object is replicated between two DCs.
           This test should verify that:
            - an OU and user can be replicated correctly
            - The creation of the OU has been combined with unrelated changes to the object,
              The aim here is the send the objects out-of-order when sorted by usnChanged.
            - That is, the OU will be sorted by usnChanged after the user that is within that OU.
            - That will cause the client to need to get the OU first, by use of the GET_ANC flag
        """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)
        self.ldb_dc1.add(self.ou2)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        self.ldb_dc1.rename(self.ou2_dn, self.ou2b_dn)

        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_moved = ldb_res[0]
        user_moved_dn = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be valid user
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved, is_deleted=False)

        self.assertEquals(user_cur["parentGUID"], user_moved["parentGUID"])

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)


    def test_ReplicateAddInConflictOU_time(self):
        """Verifies how an object is replicated between two DCs, when created in an ambigious location
           This test should verify that:
            - Without replication, two conflicting objects can be created
            - force the conflict resolution algorithm so we know which copy will win
              (by sleeping while creating the objects, therefore increasing that timestamp on 'name')
            - confirm that the user object, created on DC1, ends up in the right place on DC2
            - therefore confirm that the conflict algorithm worked correctly, and that parentGUID was used.

        """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # Now create two, conflicting objects.  This gives the user
        # object something to be under on both DCs.

        # We sleep between the two adds so that DC1 adds second, and
        # so wins the conflict resoution due to a later creation time
        # (modification timestamp on the name attribute).
        self.ldb_dc2.add(self.ou2)
        time.sleep(1)
        self.ldb_dc1.add(self.ou2)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        # Now that we have renamed the user (and so bumpted the
        # usnChanged), bump the value on the OUs.
        msg = ldb.Message()
        msg.dn = self.ou2_dn
        msg["description"] = ldb.MessageElement("OU2 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        msg = ldb.Message()
        msg.dn = self.ou2_dn
        msg["description"] = ldb.MessageElement("OU2 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_moved = ldb_res[0]
        user_moved_dn = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be under the OU2 from DC1
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved, is_deleted=False)

        self.assertEquals(user_cur["parentGUID"], user_moved["parentGUID"])

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

    def test_ReplicateAddInConflictOU2(self):
        """Verifies how an object is replicated between two DCs, when created in an ambigious location
           This test should verify that:
            - Without replication, two conflicting objects can be created
            - force the conflict resolution algorithm so we know which copy will win
              (by changing the description twice, therefore increasing that version count)
            - confirm that the user object, created on DC1, ends up in the right place on DC2
            - therefore confirm that the conflict algorithm worked correctly, and that parentGUID was used.
        """
        # work-out unique username to test with
        username = self._make_username()

        self.ldb_dc1.add(self.ou1)

        # create user on DC1
        self.ldb_dc1.newuser(username=username,
                             userou="ou=%s" % self.ou1_dn.get_component_value(0),
                             password=None, setpassword=False)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_orig = ldb_res[0]
        user_dn   = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)

        # Now create two, conflicting objects.  This gives the user
        # object something to be under on both DCs.  We create it on
        # DC1 1sec later so that it will win the conflict resolution.

        self.ldb_dc2.add(self.ou2)
        time.sleep(1)
        self.ldb_dc1.add(self.ou2)

        new_dn = ldb.Dn(self.ldb_dc1, "CN=%s" % username)
        new_dn.add_base(self.ou2_dn)
        self.ldb_dc1.rename(user_dn, new_dn)

        # Now that we have renamed the user (and so bumpted the
        # usnChanged), bump the value on the OUs.
        msg = ldb.Message()
        msg.dn = self.ou2_dn
        msg["description"] = ldb.MessageElement("OU2 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc1.modify(msg)

        msg = ldb.Message()
        msg.dn = self.ou2_dn
        msg["description"] = ldb.MessageElement("OU2 Description", ldb.FLAG_MOD_REPLACE, "description")
        self.ldb_dc2.modify(msg)

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        ldb_res = self.ldb_dc1.search(base=self.ou1_dn,
                                      scope=SCOPE_SUBTREE,
                                      expression="(samAccountName=%s)" % username,
                                      attrs=["*", "parentGUID"])
        self.assertEquals(len(ldb_res), 1)
        user_moved = ldb_res[0]
        user_moved_dn = ldb_res[0]["dn"]

        # trigger replication from DC1 to DC2
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
        # check user info on DC2 - should be under the OU2 from DC1
        user_cur = self._check_obj(sam_ldb=self.ldb_dc2, obj_orig=user_moved, is_deleted=False)

        self.assertEquals(user_cur["parentGUID"], user_moved["parentGUID"])

        # delete user on DC1
        self.ldb_dc1.delete('<GUID=%s>' % self._GUID_string(user_orig["objectGUID"][0]))

        # trigger replication from DC1 to DC2, for cleanup
        self._net_drs_replicate(DC=self.dnsname_dc2, fromDC=self.dnsname_dc1, forced=True)
