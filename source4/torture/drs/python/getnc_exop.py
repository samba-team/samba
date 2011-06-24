#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Tests various schema replication scenarios
#
# Copyright (C) Kamen Mazdrashki <kamenim@samba.org> 2011
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
#  PYTHONPATH="$PYTHONPATH:$samba4srcdir/torture/drs/python" $SUBUNITRUN getnc_exop -U"$DOMAIN/$DC_USERNAME"%"$DC_PASSWORD"
#

import drs_base
import samba.tests

from ldb import SCOPE_BASE

from samba.dcerpc import drsuapi, misc, drsblobs
from samba.drs_utils import drs_DsBind


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

    def _exop_req8(self, dest_dsa, invocation_id, nc_dn_str, exop):
        req8 = drsuapi.DsGetNCChangesRequest8()
    
        req8.destination_dsa_guid = misc.GUID(dest_dsa)
        req8.source_dsa_invocation_id = misc.GUID(invocation_id)
        req8.naming_context = drsuapi.DsReplicaObjectIdentifier()
        req8.naming_context.dn = unicode(nc_dn_str)
        req8.highwatermark = drsuapi.DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn = 0
        req8.highwatermark.reserved_usn = 0
        req8.highwatermark.highest_usn = 0
        req8.uptodateness_vector = None
        req8.replica_flags = 0
        req8.max_object_count = 0
        req8.max_ndr_size = 402116
        req8.extended_op = exop
        req8.fsmo_info = 0
        req8.partial_attribute_set = None
        req8.partial_attribute_set_ex = None
        req8.mapping_ctr.num_mappings = 0
        req8.mapping_ctr.mappings = None
    
        return req8

    def _ds_bind(self, server_name):
        binding_str = "ncacn_ip_tcp:%s[print,seal]" % server_name

        drs = drsuapi.drsuapi(binding_str, self.get_loadparm(), self.get_credentials())
        (drs_handle, supported_extensions) = drs_DsBind(drs)
        return (drs, drs_handle)

    def _determine_fSMORoleOwner(self, fsmo_obj_dn):
        """Returns (owner, not_owner) pair where:
             owner: dns name for FSMO owner
             not_owner: dns name for DC not owning the FSMO"""
        # collect info to return later
        fsmo_info_1 = {"dns_name": self.dnsname_dc1,
                       "invocation_id": self.ldb_dc1.get_invocation_id(),
                       "ntds_guid": self.ldb_dc1.get_ntds_GUID()}
        fsmo_info_2 = {"dns_name": self.dnsname_dc2,
                       "invocation_id": self.ldb_dc2.get_invocation_id(),
                       "ntds_guid": self.ldb_dc2.get_ntds_GUID()}
        # determine the owner dc
        res = self.ldb_dc1.search(fsmo_obj_dn,
                                  scope=SCOPE_BASE, attrs=["fSMORoleOwner"])
        assert len(res) == 1, "Only one fSMORoleOwner value expected for %s!"%fsmo_obj_dn
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
        self.assertEqual(ctr6.linked_attributes, None)
        self.assertEqual(ctr6.drs_error[0], 0)

    def test_FSMONotOwner(self):
        """Test role transfer with against DC not owner of the role"""
        fsmo_dn = self.ldb_dc1.get_schema_basedn()
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)
        
        req8 = self._exop_req8(dest_dsa=fsmo_owner["ntds_guid"],
                               invocation_id=fsmo_not_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_REQ_ROLE)

        (drs, drs_handle) = self._ds_bind(fsmo_not_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self._check_exop_failed(ctr, drsuapi.DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER)
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_not_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_not_owner["invocation_id"]))

    def test_InvalidDestDSA(self):
        """Test role transfer with invalid destination DSA guid"""
        fsmo_dn = self.ldb_dc1.get_schema_basedn()
        (fsmo_owner, fsmo_not_owner) = self._determine_fSMORoleOwner(fsmo_dn)

        req8 = self._exop_req8(dest_dsa="9c637462-5b8c-4467-aef2-bdb1f57bc4ef",
                               invocation_id=fsmo_owner["invocation_id"],
                               nc_dn_str=fsmo_dn,
                               exop=drsuapi.DRSUAPI_EXOP_FSMO_REQ_ROLE)

        (drs, drs_handle) = self._ds_bind(fsmo_owner["dns_name"])
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
        self.assertEqual(level, 6, "Expected level 6 response!")
        self._check_exop_failed(ctr, drsuapi.DRSUAPI_EXOP_ERR_UNKNOWN_CALLER)
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(fsmo_owner["ntds_guid"]))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(fsmo_owner["invocation_id"]))
