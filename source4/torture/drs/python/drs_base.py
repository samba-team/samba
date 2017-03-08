#!/usr/bin/env python
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

from ldb import (
    SCOPE_BASE,
    Message,
    FLAG_MOD_REPLACE,
    )


class DrsBaseTestCase(SambaToolCmdTest):
    """Base class implementation for all DRS python tests.
       It is intended to provide common initialization and
       and functionality used by all DRS tests in drs/python
       test package. For instance, DC1 and DC2 are always used
       to pass URLs for DCs to test against"""

    def setUp(self):
        super(DrsBaseTestCase, self).setUp()

        # connect to DCs
        url_dc = samba.tests.env_get_var_value("DC1")
        (self.ldb_dc1, self.info_dc1) = samba.tests.connect_samdb_ex(url_dc,
                                                                     ldap_only=True)
        url_dc = samba.tests.env_get_var_value("DC2")
        (self.ldb_dc2, self.info_dc2) = samba.tests.connect_samdb_ex(url_dc,
                                                                     ldap_only=True)

        # cache some of RootDSE props
        self.schema_dn = self.info_dc1["schemaNamingContext"][0]
        self.domain_dn = self.info_dc1["defaultNamingContext"][0]
        self.config_dn = self.info_dc1["configurationNamingContext"][0]
        self.forest_level = int(self.info_dc1["forestFunctionality"][0])

        # we will need DCs DNS names for 'samba-tool drs' command
        self.dnsname_dc1 = self.info_dc1["dnsHostName"][0]
        self.dnsname_dc2 = self.info_dc2["dnsHostName"][0]

    def tearDown(self):
        super(DrsBaseTestCase, self).tearDown()

    def _GUID_string(self, guid):
        return self.ldb_dc1.schema_format_value("objectGUID", guid)

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
        self.assertEquals(len(res), 1)
        return str(res[0]["dn"])

    def _lost_and_found_dn(self, sam_ldb, nc):
        wkdn = "<WKGUID=%s,%s>" % (dsdb.DS_GUID_LOSTANDFOUND_CONTAINER, nc)
        res = sam_ldb.search(base=wkdn,
                             scope=SCOPE_BASE)
        self.assertEquals(len(res), 1)
        return str(res[0]["dn"])

    def _make_obj_name(self, prefix):
        return prefix + time.strftime("%s", time.gmtime())

    def _samba_tool_cmdline(self, drs_command):
        # find out where is net command
        samba_tool_cmd = os.path.abspath("./bin/samba-tool")
        # make command line credentials string
        creds = self.get_credentials()
        cmdline_auth = "-U%s/%s%%%s" % (creds.get_domain(),
                                        creds.get_username(), creds.get_password())
        # bin/samba-tool drs <drs_command> <cmdline_auth>
        return "%s drs %s %s" % (samba_tool_cmd, drs_command, cmdline_auth)

    def _net_drs_replicate(self, DC, fromDC, nc_dn=None, forced=True, local=False, full_sync=False):
        if nc_dn is None:
            nc_dn = self.domain_dn
        # make base command line
        samba_tool_cmdline = self._samba_tool_cmdline("replicate")
        if forced:
            samba_tool_cmdline += " --sync-forced"
        if local:
            samba_tool_cmdline += " --local"
        if full_sync:
            samba_tool_cmdline += " --full-sync"
        # bin/samba-tool drs replicate <Dest_DC_NAME> <Src_DC_NAME> <Naming Context>
        cmd_line = "%s %s %s %s" % (samba_tool_cmdline, DC, fromDC, nc_dn)
        return self.check_output(cmd_line)

    def _enable_inbound_repl(self, DC):
        # make base command line
        samba_tool_cmd = self._samba_tool_cmdline("options")
        # disable replication
        self.check_run("%s %s --dsa-option=-DISABLE_INBOUND_REPL" %(samba_tool_cmd, DC))

    def _disable_inbound_repl(self, DC):
        # make base command line
        samba_tool_cmd = self._samba_tool_cmdline("options")
        # disable replication
        self.check_run("%s %s --dsa-option=+DISABLE_INBOUND_REPL" %(samba_tool_cmd, DC))

    def _enable_all_repl(self, DC):
        # make base command line
        samba_tool_cmd = self._samba_tool_cmdline("options")
        # disable replication
        self.check_run("%s %s --dsa-option=-DISABLE_INBOUND_REPL" %(samba_tool_cmd, DC))
        self.check_run("%s %s --dsa-option=-DISABLE_OUTBOUND_REPL" %(samba_tool_cmd, DC))

    def _disable_all_repl(self, DC):
        # make base command line
        samba_tool_cmd = self._samba_tool_cmdline("options")
        # disable replication
        self.check_run("%s %s --dsa-option=+DISABLE_INBOUND_REPL" %(samba_tool_cmd, DC))
        self.check_run("%s %s --dsa-option=+DISABLE_OUTBOUND_REPL" %(samba_tool_cmd, DC))

    def _get_highest_hwm_utdv(self, ldb_conn):
        res = ldb_conn.search("", scope=ldb.SCOPE_BASE, attrs=["highestCommittedUSN"])
        hwm = drsuapi.DsReplicaHighWaterMark()
        hwm.tmp_highest_usn = long(res[0]["highestCommittedUSN"][0])
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

    def _get_indentifier(self, ldb_conn, dn):
        res = ldb_conn.search(dn, scope=ldb.SCOPE_BASE,
                attrs=["objectGUID", "objectSid"])
        id = drsuapi.DsReplicaObjectIdentifier()
        id.guid = ndr_unpack(misc.GUID, res[0]['objectGUID'][0])
        if "objectSid" in res[0]:
            id.sid = ndr_unpack(security.dom_sid, res[0]['objectSid'][0])
        id.dn = str(res[0].dn)
        return id

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
        if source_dsa is None:
            source_dsa = self.ldb_dc1.get_ntds_GUID()
        if invocation_id is None:
            invocation_id = self.ldb_dc1.get_invocation_id()
        if nc_dn_str is None:
            nc_dn_str = self.ldb_dc1.domain_dn()

        if highwatermark is None:
            if self.default_hwm is None:
                (highwatermark, _) = self._get_highest_hwm_utdv(self.ldb_dc1)
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
                                  replica_flags=replica_flags)
        req10.highwatermark = highwatermark
        if uptodateness_vector is not None:
            uptodateness_vector_v1 = drsuapi.DsReplicaCursorCtrEx()
            cursors = []
            for i in xrange(0, uptodateness_vector.count):
                c = uptodateness_vector.cursors[i]
                c1 = drsuapi.DsReplicaCursor()
                c1.source_dsa_invocation_id = c.source_dsa_invocation_id
                c1.highest_usn = c.highest_usn
                cursors.append(c1)
            uptodateness_vector_v1.count = len(cursors)
            uptodateness_vector_v1.cursors = cursors
            req10.uptodateness_vector = uptodateness_vector_v1
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 10, req10)

        self.assertEqual(level, 6, "expected level 6 response!")
        self.assertEqual(ctr.source_dsa_guid, misc.GUID(source_dsa))
        self.assertEqual(ctr.source_dsa_invocation_id, misc.GUID(invocation_id))
        ctr6 = ctr
        self.assertEqual(ctr6.extended_ret, drs_error)
        self._check_ctr6(ctr6, expected_dns, expected_links,
                         nc_object_count=nc_object_count)
        return (ctr6.new_highwatermark, ctr6.uptodateness_vector)

    def _check_ctr6(self, ctr6, expected_dns=[], expected_links=[],
                    dn_ordered=True, links_ordered=True,
                    more_data=False, nc_object_count=0,
                    nc_linked_attributes_count=0, drs_error=0):
        """
        Check that a ctr6 matches the specified parameters.
        """
        self.assertEqual(ctr6.object_count, len(expected_dns))
        self.assertEqual(ctr6.linked_attributes_count, len(expected_links))
        self.assertEqual(ctr6.more_data, more_data)
        self.assertEqual(ctr6.nc_object_count, nc_object_count)
        self.assertEqual(ctr6.nc_linked_attributes_count, nc_linked_attributes_count)
        self.assertEqual(ctr6.drs_error[0], drs_error)

        ctr6_dns = []
        next_object = ctr6.first_object
        for i in range(0, ctr6.object_count):
            ctr6_dns.append(next_object.object.identifier.dn)
            next_object = next_object.next_object
        self.assertEqual(next_object, None)

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

        ctr6_links = []
        expected_links.sort()
        lidx = 0
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
                              target.guid)
            ctr6_links.append(al)

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
        req8.naming_context.dn = unicode(nc_dn_str)
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
        req10.naming_context.dn = unicode(nc_dn_str)
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


class AbstractLink:
    def __init__(self, attid, flags, identifier, targetGUID):
        self.attid = attid
        self.flags = flags
        self.identifier = str(identifier)
        self.selfGUID_blob = ndr_pack(identifier)
        self.targetGUID = str(targetGUID)
        self.targetGUID_blob = ndr_pack(targetGUID)

    def __repr__(self):
        return "AbstractLink(0x%08x, 0x%08x, %s, %s)" % (
                self.attid, self.flags, self.identifier, self.targetGUID)

    def __internal_cmp__(self, other, verbose=False):
        """See CompareLinks() in MS-DRSR section 4.1.10.5.17"""
        if not isinstance(other, AbstractLink):
            if verbose:
                print "AbstractLink.__internal_cmp__(%r, %r) => wrong type" % (self, other)
            return NotImplemented

        c = cmp(self.selfGUID_blob, other.selfGUID_blob)
        if c != 0:
            if verbose:
                print "AbstractLink.__internal_cmp__(%r, %r) => %d different identifier" % (self, other, c)
            return c

        c = other.attid - self.attid
        if c != 0:
            if verbose:
                print "AbstractLink.__internal_cmp__(%r, %r) => %d different attid" % (self, other, c)
            return c

        self_active = self.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE
        other_active = other.flags & drsuapi.DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE

        c = self_active - other_active
        if c != 0:
            if verbose:
                print "AbstractLink.__internal_cmp__(%r, %r) => %d different FLAG_ACTIVE" % (self, other, c)
            return c

        c = cmp(self.targetGUID_blob, other.targetGUID_blob)
        if c != 0:
            if verbose:
                print "AbstractLink.__internal_cmp__(%r, %r) => %d different target" % (self, other, c)
            return c

        c = self.flags - other.flags
        if c != 0:
            if verbose:
                print "AbstractLink.__internal_cmp__(%r, %r) => %d different flags" % (self, other, c)
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
