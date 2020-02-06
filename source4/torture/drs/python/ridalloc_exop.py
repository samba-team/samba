#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tests various RID allocation scenarios
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2016
# Copyright (C) Catalyst IT Ltd. 2016
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN ridalloc_exop -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests

import ldb
from ldb import SCOPE_BASE

from samba.dcerpc import drsuapi, misc
from samba.drs_utils import drs_DsBind
from samba.samdb import SamDB

import shutil
import tempfile
import os
from samba.auth import system_session, admin_session
from samba.dbchecker import dbcheck
from samba.ndr import ndr_pack
from samba.dcerpc import security


class DrsReplicaSyncTestCase(drs_base.DrsBaseTestCase):
    """Intended as a semi-black box test case for DsGetNCChanges
       implementation for extended operations. It should be testing
       how DsGetNCChanges handles different input params (mostly invalid).
       Final goal is to make DsGetNCChanges as binary compatible to
       Windows implementation as possible"""

    def setUp(self):
        super(DrsReplicaSyncTestCase, self).setUp()

    def tearDown(self):
        super(DrsReplicaSyncTestCase, self).tearDown()

    def _determine_fSMORoleOwner(self, fsmo_obj_dn):
        """Returns (owner, not_owner) pair where:
             owner: dns name for FSMO owner
             not_owner: dns name for DC not owning the FSMO"""
        # collect info to return later
        fsmo_info_1 = {"dns_name": self.dnsname_dc1,
                       "invocation_id": self.ldb_dc1.get_invocation_id(),
                       "ntds_guid": self.ldb_dc1.get_ntds_GUID(),
                       "server_dn": self.ldb_dc1.get_serverName()}
        fsmo_info_2 = {"dns_name": self.dnsname_dc2,
                       "invocation_id": self.ldb_dc2.get_invocation_id(),
                       "ntds_guid": self.ldb_dc2.get_ntds_GUID(),
                       "server_dn": self.ldb_dc2.get_serverName()}

        msgs = self.ldb_dc1.search(scope=ldb.SCOPE_BASE, base=fsmo_info_1["server_dn"], attrs=["serverReference"])
        fsmo_info_1["server_acct_dn"] = ldb.Dn(self.ldb_dc1, msgs[0]["serverReference"][0].decode('utf8'))
        fsmo_info_1["rid_set_dn"] = ldb.Dn(self.ldb_dc1, "CN=RID Set") + fsmo_info_1["server_acct_dn"]

        msgs = self.ldb_dc2.search(scope=ldb.SCOPE_BASE, base=fsmo_info_2["server_dn"], attrs=["serverReference"])
        fsmo_info_2["server_acct_dn"] = ldb.Dn(self.ldb_dc2, msgs[0]["serverReference"][0].decode('utf8'))
        fsmo_info_2["rid_set_dn"] = ldb.Dn(self.ldb_dc2, "CN=RID Set") + fsmo_info_2["server_acct_dn"]

        # determine the owner dc
        res = self.ldb_dc1.search(fsmo_obj_dn,
                                  scope=SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1, "Only one fSMORoleOwner value expected for %s!" % fsmo_obj_dn
        fsmo_owner = res[0]["fSMORoleOwner"][0]
        if fsmo_owner == self.info_dc1["dsServiceName"][0]:
            return (fsmo_info_1, fsmo_info_2)
        return (fsmo_info_2, fsmo_info_1)

    def _check_exop_failed(self, ctr6, expected_failure):
        self.assertEqual(ctr6.extended_ret, expected_failure)
        #self.assertEqual(ctr6.object_count, 0)
        #self.assertEqual(ctr6.first_object, None)
        self.assertEqual(ctr6.more_data, False)
        self.assertEqual(ctr6.nc_object_count, 0)
        self.assertEqual(ctr6.nc_linked_attributes_count, 0)
        self.assertEqual(ctr6.linked_attributes_count, 0)
        self.assertEqual(ctr6.linked_attributes, [])
        self.assertEqual(ctr6.drs_error[0], 0)

    def test_InvalidDestDSA_ridalloc(self):
        """Test RID allocation with invalid destination DSA guid"""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa="9c637462-5b8c-4467-aef2-bdb1f57bc4ef",
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self._check_exop_failed(ctr, drsuapi.DRSUAPI_EXOP_ERR_UNKNOWN_CALLER)
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))

    def test_do_ridalloc(self):
        """Test doing a RID allocation with a valid destination DSA guid"""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa=fsmo_not_owner["ntds_guid"],
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))
        ctr6 = ctr
        self.assertEqual(ctr6.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_SUCCESS)
        self.assertEqual(ctr6.object_count, 3)
        self.assertNotEqual(ctr6.first_object, None)
        self.assertEqual(ldb.Dn(self.ldb_dc1, ctr6.first_object.object.identifier.dn), fsmo_dn)
        self.assertNotEqual(ctr6.first_object.next_object, None)
        self.assertNotEqual(ctr6.first_object.next_object.next_object, None)
        second_object = ctr6.first_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, second_object.identifier.dn), fsmo_not_owner["rid_set_dn"])
        third_object = ctr6.first_object.next_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, third_object.identifier.dn), fsmo_not_owner["server_acct_dn"])

        self.assertEqual(ctr6.more_data, False)
        self.assertEqual(ctr6.nc_object_count, 0)
        self.assertEqual(ctr6.nc_linked_attributes_count, 0)
        self.assertEqual(ctr6.drs_error[0], 0)
        # We don't check the linked_attributes_count as if the domain
        # has an RODC, it can gain links on the server account object

    def test_do_ridalloc_get_anc(self):
        """Test doing a RID allocation with a valid destination DSA guid and GET_ANC flag"""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa=fsmo_not_owner["ntds_guid"],
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC,
                               replica_flags=drsuapi.DRSUAPI_DRS_GET_ANC)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))
        ctr6 = ctr
        self.assertEqual(ctr6.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_SUCCESS)
        self.assertEqual(ctr6.object_count, 3)
        self.assertNotEqual(ctr6.first_object, None)
        self.assertEqual(ldb.Dn(self.ldb_dc1, ctr6.first_object.object.identifier.dn), fsmo_dn)
        self.assertNotEqual(ctr6.first_object.next_object, None)
        self.assertNotEqual(ctr6.first_object.next_object.next_object, None)
        second_object = ctr6.first_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, second_object.identifier.dn), fsmo_not_owner["rid_set_dn"])
        third_object = ctr6.first_object.next_object.next_object.object
        self.assertEqual(ldb.Dn(self.ldb_dc1, third_object.identifier.dn), fsmo_not_owner["server_acct_dn"])
        self.assertEqual(ctr6.more_data, False)
        self.assertEqual(ctr6.nc_object_count, 0)
        self.assertEqual(ctr6.nc_linked_attributes_count, 0)
        self.assertEqual(ctr6.drs_error[0], 0)
        # We don't check the linked_attributes_count as if the domain
        # has an RODC, it can gain links on the server account object

    def test_edit_rid_master(self):
        """Test doing a RID allocation after changing the RID master from the original one.
           This should set rIDNextRID to 0 on the new RID master."""
        # 1. a. Transfer role to non-RID master
        #    b. Check that it succeeds correctly
        #
        # 2. a. Call the RID alloc against the former master.
        #    b. Check that it succeeds.
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        # 1. Swap RID master role
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb_dc1, "")
        m["becomeRidMaster"] = ldb.MessageElement("1", ldb.FLAG_MOD_REPLACE,
                                                  "becomeRidMaster")

        # Make sure that ldb_dc1 == RID Master

        server_dn = str(ldb.Dn(self.ldb_dc1, self.ldb_dc1.get_dsServiceName()).parent())

        # self.ldb_dc1 == LOCALDC
        if server_dn == fsmo_owner['server_dn']:
            # ldb_dc1 == VAMPIREDC
            ldb_dc1, ldb_dc2 = self.ldb_dc2, self.ldb_dc1
        else:
            # Otherwise switch the two
            ldb_dc1, ldb_dc2 = self.ldb_dc1, self.ldb_dc2

        try:
            # ldb_dc1 is now RID MASTER (as VAMPIREDC)
            ldb_dc1.modify(m)
        except ldb.LdbError as e1:
            (num, msg) = e1.args
            self.fail("Failed to reassign RID Master " + msg)

        try:
            # 2. Perform a RID alloc
            req8 = self._exop_req8(dest_dsa=fsmo_owner["ntds_guid"],
                                   invocation_id=fsmo_not_owner["invocation_id"],
                                   nc_dn_str=fsmo_dn,
                                   exop=drsuapi.DRSUAPI_EXOP_FSMO_RID_ALLOC)

            (drs, drs_handle) = self._ds_bind(fsmo_not_owner["dns_name"])
            # 3. Make sure the allocation succeeds
            try:
                (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
            except RuntimeError as e:
                self.fail("RID allocation failed: " + str(e))

            fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())

            self.assertEqual(level, 6, "Expected level 6 response!")
            self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_not_owner["ntds_guid"]))
            self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_not_owner["invocation_id"]))
            ctr6 = ctr
            self.assertEqual(ctr6.extended_ret, drsuapi.DRSUAPI_EXOP_ERR_SUCCESS)
            self.assertEqual(ctr6.object_count, 3)
            self.assertNotEqual(ctr6.first_object, None)
            self.assertEqual(ldb.Dn(ldb_dc2, ctr6.first_object.object.identifier.dn), fsmo_dn)
            self.assertNotEqual(ctr6.first_object.next_object, None)
            self.assertNotEqual(ctr6.first_object.next_object.next_object, None)
            second_object = ctr6.first_object.next_object.object
            self.assertEqual(ldb.Dn(self.ldb_dc1, second_object.identifier.dn), fsmo_owner["rid_set_dn"])
            third_object = ctr6.first_object.next_object.next_object.object
            self.assertEqual(ldb.Dn(self.ldb_dc1, third_object.identifier.dn), fsmo_owner["server_acct_dn"])
        finally:
            # Swap the RID master back for other tests
            m = ldb.Message()
            m.dn = ldb.Dn(ldb_dc2, "")
            m["becomeRidMaster"] = ldb.MessageElement("1", ldb.FLAG_MOD_REPLACE, "becomeRidMaster")
            try:
                ldb_dc2.modify(m)
            except ldb.LdbError as e:
                (num, msg) = e.args
                self.fail("Failed to restore RID Master " + msg)

    def test_offline_samba_tool_seized_ridalloc(self):
        """Perform a join against the non-RID manager and then seize the RID Manager role"""

        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_not_owner['dns_name'], "RIDALLOCTEST1")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            smbconf = os.path.join(targetdir, "etc/smb.conf")

            lp = self.get_loadparm()
            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=system_session(lp), lp=lp)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # Assert that no RID Set has been set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertFalse("rIDSetReferences" in res[0])

            (result, out, err) = self.runsubcmd("fsmo", "seize", "--role", "rid", "-H", ldb_url, "-s", smbconf, "--force")
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])
        finally:
            shutil.rmtree(targetdir, ignore_errors=True)
            self._test_force_demote(fsmo_not_owner['dns_name'], "RIDALLOCTEST1")

    def _test_join(self, server, netbios_name):
        tmpdir = os.path.join(self.tempdir, "targetdir")
        creds = self.get_credentials()
        (result, out, err) = self.runsubcmd("domain", "join",
                                            creds.get_realm(),
                                            "dc", "-U%s%%%s" % (creds.get_username(),
                                                                creds.get_password()),
                                            '--targetdir=%s' % tmpdir,
                                            '--server=%s' % server,
                                            "--option=netbios name = %s" % netbios_name)
        self.assertCmdSuccess(result, out, err)
        return tmpdir

    def _test_force_demote(self, server, netbios_name):
        creds = self.get_credentials()
        (result, out, err) = self.runsubcmd("domain", "demote",
                                            "-U%s%%%s" % (creds.get_username(),
                                                          creds.get_password()),
                                            '--server=%s' % server,
                                            "--remove-other-dead-server=%s" % netbios_name)
        self.assertCmdSuccess(result, out, err)

    def test_offline_manual_seized_ridalloc_with_dbcheck(self):
        """Peform the same actions as test_offline_samba_tool_seized_ridalloc,
        but do not create the RID set. Confirm that dbcheck correctly creates
        the RID Set.

        Also check
        """
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_not_owner['dns_name'], "RIDALLOCTEST2")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            lp = self.get_loadparm()

            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=system_session(lp), lp=lp)

            serviceName = new_ldb.get_dsServiceName()
            m = ldb.Message()
            m.dn = fsmo_dn
            m["fSMORoleOwner"] = ldb.MessageElement(serviceName,
                                                    ldb.FLAG_MOD_REPLACE,
                                                    "fSMORoleOwner")
            new_ldb.modify(m)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # Assert that no RID Set has been set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertFalse("rIDSetReferences" in res[0])

            smbconf = os.path.join(targetdir, "etc/smb.conf")

            chk = dbcheck(new_ldb, verbose=False, fix=True, yes=True, quiet=True)

            self.assertEqual(chk.check_database(DN=server_ref_dn, scope=ldb.SCOPE_BASE), 1, "Should have fixed one error (missing RID Set)")

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])
        finally:
            self._test_force_demote(fsmo_not_owner['dns_name'], "RIDALLOCTEST2")
            shutil.rmtree(targetdir, ignore_errors=True)

    def test_offline_manual_seized_ridalloc_add_user(self):
        """Peform the same actions as test_offline_samba_tool_seized_ridalloc,
        but do not create the RID set. Confirm that user-add correctly creates
        the RID Set."""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_not_owner['dns_name'], "RIDALLOCTEST3")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            lp = self.get_loadparm()

            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=system_session(lp), lp=lp)

            serviceName = new_ldb.get_dsServiceName()
            m = ldb.Message()
            m.dn = fsmo_dn
            m["fSMORoleOwner"] = ldb.MessageElement(serviceName,
                                                    ldb.FLAG_MOD_REPLACE,
                                                    "fSMORoleOwner")
            new_ldb.modify(m)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # Assert that no RID Set has been set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertFalse("rIDSetReferences" in res[0])

            smbconf = os.path.join(targetdir, "etc/smb.conf")

            new_ldb.newuser("ridalloctestuser", "P@ssword!")

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])

        finally:
            self._test_force_demote(fsmo_not_owner['dns_name'], "RIDALLOCTEST3")
            shutil.rmtree(targetdir, ignore_errors=True)

    def test_offline_manual_seized_ridalloc_add_user_as_admin(self):
        """Peform the same actions as test_offline_samba_tool_seized_ridalloc,
        but do not create the RID set. Confirm that user-add correctly creates
        the RID Set."""
        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_not_owner['dns_name'], "RIDALLOCTEST4")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            lp = self.get_loadparm()

            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=admin_session(lp, self.ldb_dc1.get_domain_sid()), lp=lp)

            serviceName = new_ldb.get_dsServiceName()
            m = ldb.Message()
            m.dn = fsmo_dn
            m["fSMORoleOwner"] = ldb.MessageElement(serviceName,
                                                    ldb.FLAG_MOD_REPLACE,
                                                    "fSMORoleOwner")
            new_ldb.modify(m)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # Assert that no RID Set has been set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertFalse("rIDSetReferences" in res[0])

            smbconf = os.path.join(targetdir, "etc/smb.conf")

            # Create a user to allocate a RID Set for itself (the RID master)
            new_ldb.newuser("ridalloctestuser", "P@ssword!")

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])

        finally:
            self._test_force_demote(fsmo_not_owner['dns_name'], "RIDALLOCTEST4")
            shutil.rmtree(targetdir, ignore_errors=True)

    def test_join_time_ridalloc(self):
        """Perform a join against the RID manager and assert we have a RID Set"""

        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_owner['dns_name'], "RIDALLOCTEST5")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            smbconf = os.path.join(targetdir, "etc/smb.conf")

            lp = self.get_loadparm()
            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=system_session(lp), lp=lp)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])
        finally:
            self._test_force_demote(fsmo_owner['dns_name'], "RIDALLOCTEST5")
            shutil.rmtree(targetdir, ignore_errors=True)

    def test_rid_set_dbcheck(self):
        """Perform a join against the RID manager and assert we have a RID Set.
        Using dbcheck, we assert that we can detect out of range users."""

        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_owner['dns_name'], "RIDALLOCTEST6")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            smbconf = os.path.join(targetdir, "etc/smb.conf")

            lp = self.get_loadparm()
            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=system_session(lp), lp=lp)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])
            rid_set_dn = ldb.Dn(new_ldb, res[0]["rIDSetReferences"][0].decode('utf8'))

            # 4. Add a new user (triggers RID set work)
            new_ldb.newuser("ridalloctestuser", "P@ssword!")

            # 5. Now fetch the RID SET
            rid_set_res = new_ldb.search(base=rid_set_dn,
                                         scope=ldb.SCOPE_BASE, attrs=['rIDNextRid',
                                                                      'rIDAllocationPool'])
            next_pool = int(rid_set_res[0]["rIDAllocationPool"][0])
            last_rid = (0xFFFFFFFF00000000 & next_pool) >> 32

            # 6. Add user above the ridNextRid and at mid-range.
            #
            # We can do this with safety because this is an offline DB that will be
            # destroyed.
            m = ldb.Message()
            m.dn = ldb.Dn(new_ldb, "CN=ridsettestuser1,CN=Users")
            m.dn.add_base(new_ldb.get_default_basedn())
            m['objectClass'] = ldb.MessageElement('user', ldb.FLAG_MOD_ADD, 'objectClass')
            m['objectSid'] = ldb.MessageElement(ndr_pack(security.dom_sid(str(new_ldb.get_domain_sid()) + "-%d" % (last_rid - 10))),
                                                ldb.FLAG_MOD_ADD,
                                                'objectSid')
            new_ldb.add(m, controls=["relax:0"])

            # 7. Check the RID Set
            chk = dbcheck(new_ldb, verbose=False, fix=True, yes=True, quiet=True)

            # Should have one error (wrong rIDNextRID)
            self.assertEqual(chk.check_database(DN=rid_set_dn, scope=ldb.SCOPE_BASE), 1)

            # 8. Assert we get didn't show any other errors
            chk = dbcheck(new_ldb, verbose=False, fix=False, quiet=True)

            rid_set_res = new_ldb.search(base=rid_set_dn,
                                         scope=ldb.SCOPE_BASE, attrs=['rIDNextRid',
                                                                      'rIDAllocationPool'])
            last_allocated_rid = int(rid_set_res[0]["rIDNextRid"][0])
            self.assertEqual(last_allocated_rid, last_rid - 10)

            # 9. Assert that the range wasn't thrown away

            next_pool = int(rid_set_res[0]["rIDAllocationPool"][0])
            self.assertEqual(last_rid, (0xFFFFFFFF00000000 & next_pool) >> 32, "rid pool should have changed")
        finally:
            self._test_force_demote(fsmo_owner['dns_name'], "RIDALLOCTEST6")
            shutil.rmtree(targetdir, ignore_errors=True)

    def test_rid_set_dbcheck_after_seize(self):
        """Perform a join against the RID manager and assert we have a RID Set.
        We seize the RID master role, then using dbcheck, we assert that we can
        detect out of range users (and then bump the RID set as required)."""

        fsmo_dn = ldb.Dn(self.ldb_dc1, "CN=RID Manager$,CN=System," + self.ldb_dc1.domain_dn())
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        targetdir = self._test_join(fsmo_owner['dns_name'], "RIDALLOCTEST7")
        try:
            # Connect to the database
            ldb_url = "tdb://%s" % os.path.join(targetdir, "private/sam.ldb")
            smbconf = os.path.join(targetdir, "etc/smb.conf")

            lp = self.get_loadparm()
            new_ldb = SamDB(ldb_url, credentials=self.get_credentials(),
                            session_info=system_session(lp), lp=lp)

            # 1. Get server name
            res = new_ldb.search(base=ldb.Dn(new_ldb, new_ldb.get_serverName()),
                                 scope=ldb.SCOPE_BASE, attrs=["serverReference"])
            # 2. Get server reference
            server_ref_dn = ldb.Dn(new_ldb, res[0]['serverReference'][0].decode('utf8'))

            # 3. Assert we get the RID Set
            res = new_ldb.search(base=server_ref_dn,
                                 scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])

            self.assertTrue("rIDSetReferences" in res[0])
            rid_set_dn = ldb.Dn(new_ldb, res[0]["rIDSetReferences"][0].decode('utf8'))
            # 4. Seize the RID Manager role
            (result, out, err) = self.runsubcmd("fsmo", "seize", "--role", "rid", "-H", ldb_url, "-s", smbconf, "--force")
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")

            # 5. Add a new user (triggers RID set work)
            new_ldb.newuser("ridalloctestuser", "P@ssword!")

            # 6. Now fetch the RID SET
            rid_set_res = new_ldb.search(base=rid_set_dn,
                                         scope=ldb.SCOPE_BASE, attrs=['rIDNextRid',
                                                                      'rIDAllocationPool'])
            next_pool = int(rid_set_res[0]["rIDAllocationPool"][0])
            last_rid = (0xFFFFFFFF00000000 & next_pool) >> 32

            # 7. Add user above the ridNextRid and at almost the end of the range.
            #
            m = ldb.Message()
            m.dn = ldb.Dn(new_ldb, "CN=ridsettestuser2,CN=Users")
            m.dn.add_base(new_ldb.get_default_basedn())
            m['objectClass'] = ldb.MessageElement('user', ldb.FLAG_MOD_ADD, 'objectClass')
            m['objectSid'] = ldb.MessageElement(ndr_pack(security.dom_sid(str(new_ldb.get_domain_sid()) + "-%d" % (last_rid - 3))),
                                                ldb.FLAG_MOD_ADD,
                                                'objectSid')
            new_ldb.add(m, controls=["relax:0"])

            # 8. Add user above the ridNextRid and at the end of the range
            m = ldb.Message()
            m.dn = ldb.Dn(new_ldb, "CN=ridsettestuser3,CN=Users")
            m.dn.add_base(new_ldb.get_default_basedn())
            m['objectClass'] = ldb.MessageElement('user', ldb.FLAG_MOD_ADD, 'objectClass')
            m['objectSid'] = ldb.MessageElement(ndr_pack(security.dom_sid(str(new_ldb.get_domain_sid()) + "-%d" % last_rid)),
                                                ldb.FLAG_MOD_ADD,
                                                'objectSid')
            new_ldb.add(m, controls=["relax:0"])

            chk = dbcheck(new_ldb, verbose=False, fix=True, yes=True, quiet=True)

            # Should have fixed two errors (wrong ridNextRid)
            self.assertEqual(chk.check_database(DN=rid_set_dn, scope=ldb.SCOPE_BASE), 2)

            # 9. Assert we get didn't show any other errors
            chk = dbcheck(new_ldb, verbose=False, fix=False, quiet=True)

            # 10. Add another user (checks RID rollover)
            # We have seized the role, so we can do that.
            new_ldb.newuser("ridalloctestuser3", "P@ssword!")

            rid_set_res = new_ldb.search(base=rid_set_dn,
                                         scope=ldb.SCOPE_BASE, attrs=['rIDNextRid',
                                                                      'rIDAllocationPool'])
            next_pool = int(rid_set_res[0]["rIDAllocationPool"][0])
            self.assertNotEqual(last_rid, (0xFFFFFFFF00000000 & next_pool) >> 32, "rid pool should have changed")
        finally:
            self._test_force_demote(fsmo_owner['dns_name'], "RIDALLOCTEST7")
            shutil.rmtree(targetdir, ignore_errors=True)
