#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Unix SMB/CIFS implementation.
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

from __future__ import print_function
import sys
import time
import os
import ldb

sys.path.insert(0, "bin/python")
import samba.tests
from samba.tests.samba_tool.base import SambaToolCmdTest
from samba import dsdb
from samba.dcerpc import drsuapi, misc, drsblobs, security
from samba.ndr import ndr_unpack, ndr_pack
from samba.drs_utils import drs_DsBind
from samba import gensec
from ldb import (
    SCOPE_BASE,
    Message,
    FLAG_MOD_REPLACE,
)
from samba.compat import cmp_fn
from samba.compat import get_string


class DrsBaseTestCase(SambaToolCmdTest):
    """Base class implementation for all DRS python tests.
       It is intended to provide common initialization and
       and functionality used by all DRS tests in drs/python
       test package. For instance, DC1 and DC2 are always used
       to pass URLs for DCs to test against"""

    def setUp(self):
        super(DrsBaseTestCase, self).setUp()
        creds = self.get_credentials()
        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

        # connect to DCs
        self.url_dc1 = samba.tests.env_get_var_value("DC1")
        (self.ldb_dc1, self.info_dc1) = samba.tests.connect_samdb_ex(self.url_dc1,
                                                                     ldap_only=True)
        self.url_dc2 = samba.tests.env_get_var_value("DC2")
        (self.ldb_dc2, self.info_dc2) = samba.tests.connect_samdb_ex(self.url_dc2,
                                                                     ldap_only=True)
        self.test_ldb_dc = self.ldb_dc1

        # cache some of RootDSE props
        self.schema_dn = str(self.info_dc1["schemaNamingContext"][0])
        self.domain_dn = str(self.info_dc1["defaultNamingContext"][0])
        self.config_dn = str(self.info_dc1["configurationNamingContext"][0])
        self.forest_level = int(self.info_dc1["forestFunctionality"][0])

        # we will need DCs DNS names for 'samba-tool drs' command
        self.dnsname_dc1 = str(self.info_dc1["dnsHostName"][0])
        self.dnsname_dc2 = str(self.info_dc2["dnsHostName"][0])

        # for debugging the test code
        self._debug = False

    def tearDown(self):
        super(DrsBaseTestCase, self).tearDown()

    def set_test_ldb_dc(self, ldb_dc):
        """Sets which DC's LDB we perform operations on during the test"""
        self.test_ldb_dc = ldb_dc

    def _GUID_string(self, guid):
        return get_string(self.test_ldb_dc.schema_format_value("objectGUID", guid))

    def _ldap_schemaUpdateNow(self, sam_db):
        rec = {"dn": "",
               "schemaUpdateNow": "1"}
        m = Message.from_dict(sam_db, rec, FLAG_MOD_REPLACE)
        sam_db.modify(m)

    def _deleted_objects_dn(self, sam_ldb):
        wkdn = "<WKGUID=18E2EA80684F11D2B9AA00C04F79F805,%s>" % self.domain_dn
        res = sam_ldb.search(base=wkdn,
                             scope=SCOPE_BASE,
                             controls=["show_deleted:1"])
        self.assertEqual(len(res), 1)
        return str(res[0]["dn"])

    def _lost_and_found_dn(self, sam_ldb, nc):
        wkdn = "<WKGUID=%s,%s>" % (dsdb.DS_GUID_LOSTANDFOUND_CONTAINER, nc)
        res = sam_ldb.search(base=wkdn,
                             scope=SCOPE_BASE)
        self.assertEqual(len(res), 1)
        return str(res[0]["dn"])

    def _make_obj_name(self, prefix):
        return prefix + time.strftime("%s", time.gmtime())

    def _samba_tool_cmd_list(self, drs_command):
        # make command line credentials string

        # If test runs on windows then it can provide its own auth string
        if hasattr(self, 'cmdline_auth'):
            cmdline_auth = self.cmdline_auth
        else:
            ccache_name = self.get_creds_ccache_name()

            # Tunnel the command line credentials down to the
            # subcommand to avoid a new kinit
            cmdline_auth = "--krb5-ccache=%s" % ccache_name

        # bin/samba-tool drs <drs_command> <cmdline_auth>
        return ["drs", drs_command, cmdline_auth]

    def _net_drs_replicate(self, DC, fromDC, nc_dn=None, forced=True,
                           local=False, full_sync=False, single=False):
        if nc_dn is None:
            nc_dn = self.domain_dn
        # make base command line
        samba_tool_cmdline = self._samba_tool_cmd_list("replicate")
        # bin/samba-tool drs replicate <Dest_DC_NAME> <Src_DC_NAME> <Naming Context>
        samba_tool_cmdline += [DC, fromDC, nc_dn]

        if forced:
            samba_tool_cmdline += ["--sync-forced"]
        if local:
            samba_tool_cmdline += ["--local"]
        if full_sync:
            samba_tool_cmdline += ["--full-sync"]
        if single:
            samba_tool_cmdline += ["--single-object"]

        (result, out, err) = self.runsubcmd(*samba_tool_cmdline)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")

    def _enable_inbound_repl(self, DC):
        # make base command line
        samba_tool_cmd = self._samba_tool_cmd_list("options")
        # disable replication
        samba_tool_cmd += [DC, "--dsa-option=-DISABLE_INBOUND_REPL"]
        (result, out, err) = self.runsubcmd(*samba_tool_cmd)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")

    def _disable_inbound_repl(self, DC):
        # make base command line
        samba_tool_cmd = self._samba_tool_cmd_list("options")
        # disable replication
        samba_tool_cmd += [DC, "--dsa-option=+DISABLE_INBOUND_REPL"]
        (result, out, err) = self.runsubcmd(*samba_tool_cmd)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")

    def _enable_all_repl(self, DC):
        self._enable_inbound_repl(DC)
        # make base command line
        samba_tool_cmd = self._samba_tool_cmd_list("options")
        # enable replication
        samba_tool_cmd += [DC, "--dsa-option=-DISABLE_OUTBOUND_REPL"]
        (result, out, err) = self.runsubcmd(*samba_tool_cmd)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")

    def _disable_all_repl(self, DC):
        self._disable_inbound_repl(DC)
        # make base command line
        samba_tool_cmd = self._samba_tool_cmd_list("options")
        # disable replication
        samba_tool_cmd += [DC, "--dsa-option=+DISABLE_OUTBOUND_REPL"]
        (result, out, err) = self.runsubcmd(*samba_tool_cmd)
        self.assertCmdSuccess(result, out, err)
        self.assertEqual(err, "", "Shouldn't be any error messages")

    def _get_highest_hwm_utdv(self, ldb_conn):
        res = ldb_conn.search("", scope=ldb.SCOPE_BASE, attrs=["highestCommittedUSN"])
        hwm = drsuapi.DsReplicaHighWaterMark()
        hwm.tmp_highest_usn = int(res[0]["highestCommittedUSN"][0])
        hwm.reserved_usn = 0
        hwm.highest_usn = hwm.tmp_highest_usn

        utdv = drsuapi.DsReplicaCursorCtrEx()
        cursors = []
        c1 = drsuapi.DsReplicaCursor()
        c1.source_dsa_invocation_id = misc.GUID(ldb_conn.get_invocation_id())
        c1.highest_usn = hwm.highest_usn
        cursors.append(c1)
        utdv.count = len(cursors)
        utdv.cursors = cursors
        return (hwm, utdv)

    def _get_identifier(self, ldb_conn, dn):
        res = ldb_conn.search(dn, scope=ldb.SCOPE_BASE,
                              attrs=["objectGUID", "objectSid"])
        id = drsuapi.DsReplicaObjectIdentifier()
        id.guid = ndr_unpack(misc.GUID, res[0]['objectGUID'][0])
        if "objectSid" in res[0]:
            id.sid = ndr_unpack(security.dom_sid, res[0]['objectSid'][0])
        id.dn = str(res[0].dn)
        return id

    def _get_ctr6_links(self, ctr6):
        """
        Unpacks the linked attributes from a DsGetNCChanges response
        and returns them as a list.
        """
        ctr6_links = []
        for lidx in range(0, ctr6.linked_attributes_count):
            l = ctr6.linked_attributes[lidx]
            try:
                target = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3,
                                    l.value.blob)
            except:
                target = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3Binary,
                                    l.value.blob)
            al = AbstractLink(l.attid, l.flags,
                              l.identifier.guid,
                              target.guid, target.dn)
            ctr6_links.append(al)

        return ctr6_links

    def _get_ctr6_object_guids(self, ctr6):
        """Returns all the object GUIDs in a GetNCChanges response"""
        guid_list = []

        obj = ctr6.first_object
        for i in range(0, ctr6.object_count):
            guid_list.append(str(obj.object.identifier.guid))
            obj = obj.next_object

        return guid_list

    def _ctr6_debug(self, ctr6):
        """
        Displays basic info contained in a DsGetNCChanges response.
        Having this debug code allows us to see the difference in behaviour
        between Samba and Windows easier. Turn on the self._debug flag to see it.
        """

        if self._debug:
            print("------------ recvd CTR6 -------------")

            next_object = ctr6.first_object
            for i in range(0, ctr6.object_count):
                print("Obj %d: %s %s" % (i, next_object.object.identifier.dn[:25],
                                         next_object.object.identifier.guid))
                next_object = next_object.next_object

            print("Linked Attributes: %d" % ctr6.linked_attributes_count)
            for lidx in range(0, ctr6.linked_attributes_count):
                l = ctr6.linked_attributes[lidx]
                try:
                    target = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3,
                                        l.value.blob)
                except:
                    target = ndr_unpack(drsuapi.DsReplicaObjectIdentifier3Binary,
                                        l.value.blob)

                print("Link Tgt %s... <-- Src %s"
                      % (target.dn[:25], l.identifier.guid))
                state = "Del"
                if l.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE:
                    state = "Act"
                print("  v%u %s changed %u" % (l.meta_data.version, state,
                                               l.meta_data.originating_change_time))

            print("HWM:     %d" % (ctr6.new_highwatermark.highest_usn))
            print("Tmp HWM: %d" % (ctr6.new_highwatermark.tmp_highest_usn))
            print("More data: %d" % (ctr6.more_data))

    def _get_replication(self, replica_flags,
                         drs_error=drsuapi.DRSUAPI_EXOP_ERR_NONE, drs=None, drs_handle=None,
                         highwatermark=None, uptodateness_vector=None,
                         more_flags=0, max_objects=133, exop=0,
                         dest_dsa=drsuapi.DRSUAPI_DS_BIND_GUID_W2K3,
                         source_dsa=None, invocation_id=None, nc_dn_str=None):
        """
        Builds a DsGetNCChanges request based on the information provided
        and returns the response received from the DC.
        """
        if source_dsa is None:
            source_dsa = self.test_ldb_dc.get_ntds_GUID()
        if invocation_id is None:
            invocation_id = self.test_ldb_dc.get_invocation_id()
        if nc_dn_str is None:
            nc_dn_str = self.test_ldb_dc.domain_dn()

        if highwatermark is None:
            if self.default_hwm is None:
                (highwatermark, _) = self._get_highest_hwm_utdv(self.test_ldb_dc)
            else:
                highwatermark = self.default_hwm

        if drs is None:
            drs = self.drs
        if drs_handle is None:
            drs_handle = self.drs_handle

        req10 = self._getnc_req10(dest_dsa=dest_dsa,
                                  invocation_id=invocation_id,
                                  nc_dn_str=nc_dn_str,
                                  exop=exop,
                                  max_objects=max_objects,
                                  replica_flags=replica_flags,
                                  more_flags=more_flags)
        req10.highwatermark = highwatermark
        if uptodateness_vector is not None:
            uptodateness_vector_v1 = drsuapi.DsReplicaCursorCtrEx()
            cursors = []
            for i in range(0, uptodateness_vector.count):
                c = uptodateness_vector.cursors[i]
                c1 = drsuapi.DsReplicaCursor()
                c1.source_dsa_invocation_id = c.source_dsa_invocation_id
                c1.highest_usn = c.highest_usn
                cursors.append(c1)
            uptodateness_vector_v1.count = len(cursors)
            uptodateness_vector_v1.cursors = cursors
            req10.uptodateness_vector = uptodateness_vector_v1
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 10, req10)
        self._ctr6_debug(ctr)

        self.assertEqual(level, 6, "expected level 6 response!")
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(source_dsa))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(invocation_id))
        self.assertEqual(ctr.extended_ret, drs_error)

        return ctr

    def _check_replication(self, expected_dns, replica_flags, expected_links=[],
                           drs_error=drsuapi.DRSUAPI_EXOP_ERR_NONE, drs=None, drs_handle=None,
                           highwatermark=None, uptodateness_vector=None,
                           more_flags=0, more_data=False,
                           dn_ordered=True, links_ordered=True,
                           max_objects=133, exop=0,
                           dest_dsa=drsuapi.DRSUAPI_DS_BIND_GUID_W2K3,
                           source_dsa=None, invocation_id=None, nc_dn_str=None,
                           nc_object_count=0, nc_linked_attributes_count=0):
        """
        Makes sure that replication returns the specific error given.
        """

        # send a DsGetNCChanges to the DC
        ctr6 = self._get_replication(replica_flags,
                                     drs_error, drs, drs_handle,
                                     highwatermark, uptodateness_vector,
                                     more_flags, max_objects, exop, dest_dsa,
                                     source_dsa, invocation_id, nc_dn_str)

        # check the response is what we expect
        self._check_ctr6(ctr6, expected_dns, expected_links,
                         nc_object_count=nc_object_count, more_data=more_data,
                         dn_ordered=dn_ordered)
        return (ctr6.new_highwatermark, ctr6.uptodateness_vector)

    def _get_ctr6_dn_list(self, ctr6):
        """
        Returns the DNs contained in a DsGetNCChanges response.
        """
        dn_list = []
        next_object = ctr6.first_object
        for i in range(0, ctr6.object_count):
            dn_list.append(next_object.object.identifier.dn)
            next_object = next_object.next_object
        self.assertEqual(next_object, None)

        return dn_list

    def _check_ctr6(self, ctr6, expected_dns=[], expected_links=[],
                    dn_ordered=True, links_ordered=True,
                    more_data=False, nc_object_count=0,
                    nc_linked_attributes_count=0, drs_error=0):
        """
        Check that a ctr6 matches the specified parameters.
        """
        ctr6_raw_dns = self._get_ctr6_dn_list(ctr6)

        # filter out changes to the RID Set objects, as these can happen
        # intermittently and mess up the test assertions
        ctr6_dns = []
        for dn in ctr6_raw_dns:
            if "CN=RID Set," in dn or "CN=RID Manager$," in dn:
                print("Removing {0} from GetNCChanges reply".format(dn))
            else:
                ctr6_dns.append(dn)

        self.assertEqual(len(ctr6_dns), len(expected_dns),
                         "Received unexpected objects (%s)" % ctr6_dns)
        self.assertEqual(ctr6.object_count, len(ctr6_raw_dns))
        self.assertEqual(ctr6.linked_attributes_count, len(expected_links))
        self.assertEqual(ctr6.more_data, more_data)
        self.assertEqual(ctr6.nc_object_count, nc_object_count)
        self.assertEqual(ctr6.nc_linked_attributes_count, nc_linked_attributes_count)
        self.assertEqual(ctr6.drs_error[0], drs_error)

        i = 0
        for dn in expected_dns:
            # Expect them back in the exact same order as specified.
            if dn_ordered:
                self.assertNotEqual(ctr6_dns[i], None)
                self.assertEqual(ctr6_dns[i], dn)
                i = i + 1
            # Don't care what order
            else:
                self.assertTrue(dn in ctr6_dns, "Couldn't find DN '%s' anywhere in ctr6 response." % dn)

        # Extract the links from the response
        ctr6_links = self._get_ctr6_links(ctr6)
        expected_links.sort()

        lidx = 0
        for el in expected_links:
            if links_ordered:
                self.assertEqual(el, ctr6_links[lidx])
                lidx += 1
            else:
                self.assertTrue(el in ctr6_links, "Couldn't find link '%s' anywhere in ctr6 response." % el)

    def _exop_req8(self, dest_dsa, invocation_id, nc_dn_str, exop,
                   replica_flags=0, max_objects=0, partial_attribute_set=None,
                   partial_attribute_set_ex=None, mapping_ctr=None):
        req8 = drsuapi.DsGetNCChangesRequest8()

        req8.destination_dsa_guid = misc.GUID(dest_dsa) if dest_dsa else misc.GUID()
        req8.source_dsa_invocation_id = misc.GUID(invocation_id)
        req8.naming_context = drsuapi.DsReplicaObjectIdentifier()
        req8.naming_context.dn = str(nc_dn_str)
        req8.highwatermark = drsuapi.DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn = 0
        req8.highwatermark.reserved_usn = 0
        req8.highwatermark.highest_usn = 0
        req8.uptodateness_vector = None
        req8.replica_flags = replica_flags
        req8.max_object_count = max_objects
        req8.max_ndr_size = 402116
        req8.extended_op = exop
        req8.fsmo_info = 0
        req8.partial_attribute_set = partial_attribute_set
        req8.partial_attribute_set_ex = partial_attribute_set_ex
        if mapping_ctr:
            req8.mapping_ctr = mapping_ctr
        else:
            req8.mapping_ctr.num_mappings = 0
            req8.mapping_ctr.mappings = None

        return req8

    def _getnc_req10(self, dest_dsa, invocation_id, nc_dn_str, exop,
                     replica_flags=0, max_objects=0, partial_attribute_set=None,
                     partial_attribute_set_ex=None, mapping_ctr=None,
                     more_flags=0):
        req10 = drsuapi.DsGetNCChangesRequest10()

        req10.destination_dsa_guid = misc.GUID(dest_dsa) if dest_dsa else misc.GUID()
        req10.source_dsa_invocation_id = misc.GUID(invocation_id)
        req10.naming_context = drsuapi.DsReplicaObjectIdentifier()
        req10.naming_context.dn = str(nc_dn_str)
        req10.highwatermark = drsuapi.DsReplicaHighWaterMark()
        req10.highwatermark.tmp_highest_usn = 0
        req10.highwatermark.reserved_usn = 0
        req10.highwatermark.highest_usn = 0
        req10.uptodateness_vector = None
        req10.replica_flags = replica_flags
        req10.max_object_count = max_objects
        req10.max_ndr_size = 402116
        req10.extended_op = exop
        req10.fsmo_info = 0
        req10.partial_attribute_set = partial_attribute_set
        req10.partial_attribute_set_ex = partial_attribute_set_ex
        if mapping_ctr:
            req10.mapping_ctr = mapping_ctr
        else:
            req10.mapping_ctr.num_mappings = 0
            req10.mapping_ctr.mappings = None
        req10.more_flags = more_flags

        return req10

    def _ds_bind(self, server_name, creds=None):
        binding_str = "ncacn_ip_tcp:%s[seal]" % server_name

        if creds is None:
            creds = self.get_credentials()
        drs = drsuapi.drsuapi(binding_str, self.get_loadparm(), creds)
        (drs_handle, supported_extensions) = drs_DsBind(drs)
        return (drs, drs_handle)

    def get_partial_attribute_set(self, attids=[drsuapi.DRSUAPI_ATTID_objectClass]):
        partial_attribute_set = drsuapi.DsPartialAttributeSet()
        partial_attribute_set.attids = attids
        partial_attribute_set.num_attids = len(attids)
        return partial_attribute_set


class AbstractLink:
    def __init__(self, attid, flags, identifier, targetGUID,
                 targetDN=""):
        self.attid = attid
        self.flags = flags
        self.identifier = str(identifier)
        self.selfGUID_blob = ndr_pack(identifier)
        self.targetGUID = str(targetGUID)
        self.targetGUID_blob = ndr_pack(targetGUID)
        self.targetDN = targetDN

    def __repr__(self):
        return "AbstractLink(0x%08x, 0x%08x, %s, %s)" % (
                self.attid, self.flags, self.identifier, self.targetGUID)

    def __internal_cmp__(self, other, verbose=False):
        """See CompareLinks() in MS-DRSR section 4.1.10.5.17"""
        if not isinstance(other, AbstractLink):
            if verbose:
                print("AbstractLink.__internal_cmp__(%r, %r) => wrong type" % (self, other))
            return NotImplemented

        c = cmp_fn(self.selfGUID_blob, other.selfGUID_blob)
        if c != 0:
            if verbose:
                print("AbstractLink.__internal_cmp__(%r, %r) => %d different identifier" % (self, other, c))
            return c

        c = other.attid - self.attid
        if c != 0:
            if verbose:
                print("AbstractLink.__internal_cmp__(%r, %r) => %d different attid" % (self, other, c))
            return c

        self_active = self.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE
        other_active = other.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE

        c = self_active - other_active
        if c != 0:
            if verbose:
                print("AbstractLink.__internal_cmp__(%r, %r) => %d different FLAG_ACTIVE" % (self, other, c))
            return c

        c = cmp_fn(self.targetGUID_blob, other.targetGUID_blob)
        if c != 0:
            if verbose:
                print("AbstractLink.__internal_cmp__(%r, %r) => %d different target" % (self, other, c))
            return c

        c = self.flags - other.flags
        if c != 0:
            if verbose:
                print("AbstractLink.__internal_cmp__(%r, %r) => %d different flags" % (self, other, c))
            return c

        return 0

    def __lt__(self, other):
        c = self.__internal_cmp__(other)
        if c == NotImplemented:
            return NotImplemented
        if c < 0:
            return True
        return False

    def __le__(self, other):
        c = self.__internal_cmp__(other)
        if c == NotImplemented:
            return NotImplemented
        if c <= 0:
            return True
        return False

    def __eq__(self, other):
        c = self.__internal_cmp__(other, verbose=True)
        if c == NotImplemented:
            return NotImplemented
        if c == 0:
            return True
        return False

    def __ne__(self, other):
        c = self.__internal_cmp__(other)
        if c == NotImplemented:
            return NotImplemented
        if c != 0:
            return True
        return False

    def __gt__(self, other):
        c = self.__internal_cmp__(other)
        if c == NotImplemented:
            return NotImplemented
        if c > 0:
            return True
        return False

    def __ge__(self, other):
        c = self.__internal_cmp__(other)
        if c == NotImplemented:
            return NotImplemented
        if c >= 0:
            return True
        return False

    def __hash__(self):
        return hash((self.attid, self.flags, self.identifier, self.targetGUID))
