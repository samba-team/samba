#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# script to verify cached prefixMap on remote
# server against the prefixMap stored in Schema NC
#
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

import os
import sys
from optparse import OptionParser

sys.path.insert(0, "bin/python")

import samba
import samba.getopt as options
from ldb import SCOPE_BASE, SCOPE_SUBTREE
from samba.dcerpc import drsuapi, misc, drsblobs
from samba.drs_utils import drs_DsBind
from samba.samdb import SamDB
from samba.auth import system_session
from samba.ndr import ndr_pack, ndr_unpack


def _samdb_fetch_pfm(samdb):
    """Fetch prefixMap stored in SamDB using LDB connection"""
    res = samdb.search(base=samdb.get_schema_basedn(), expression="", scope=SCOPE_BASE, attrs=["*"])
    assert len(res) == 1
    pfm = ndr_unpack(drsblobs.prefixMapBlob,
                     str(res[0]['prefixMap']))
    return pfm.ctr

def _drs_fetch_pfm(server, samdb, creds, lp):
    """Fetch prefixMap using DRS interface"""
    binding_str = "ncacn_ip_tcp:%s[print,seal]" % server

    drs = drsuapi.drsuapi(binding_str, lp, creds)
    (drs_handle, supported_extensions) = drs_DsBind(drs)
    print "DRS Handle: %s" % drs_handle

    req8 = drsuapi.DsGetNCChangesRequest8()

    dest_dsa = misc.GUID("9c637462-5b8c-4467-aef2-bdb1f57bc4ef")
    replica_flags = 0

    req8.destination_dsa_guid = dest_dsa
    req8.source_dsa_invocation_id = misc.GUID(samdb.get_invocation_id())
    req8.naming_context = drsuapi.DsReplicaObjectIdentifier()
    req8.naming_context.dn = unicode(samdb.get_schema_basedn())
    req8.highwatermark = drsuapi.DsReplicaHighWaterMark()
    req8.highwatermark.tmp_highest_usn = 0
    req8.highwatermark.reserved_usn = 0
    req8.highwatermark.highest_usn = 0
    req8.uptodateness_vector = None
    req8.replica_flags = replica_flags
    req8.max_object_count = 0
    req8.max_ndr_size = 402116
    req8.extended_op = 0
    req8.fsmo_info = 0
    req8.partial_attribute_set = None
    req8.partial_attribute_set_ex = None
    req8.mapping_ctr.num_mappings = 0
    req8.mapping_ctr.mappings = None

    (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)
    pfm = ctr.mapping_ctr
    # check for schemaInfo element
    pfm_it = pfm.mappings[-1]
    assert pfm_it.id_prefix == 0
    assert pfm_it.oid.length == 21
    assert pfm_it.oid.binary_oid[0] == 255
    # remove schemaInfo element
    pfm.num_mappings -= 1
    return pfm

def _pfm_verify(drs_pfm, ldb_pfm):
    errors = []
    if drs_pfm.num_mappings != ldb_pfm.num_mappings:
        errors.append("Different count of prefixes: drs = %d, ldb = %d"
                      % (drs_pfm.num_mappings, ldb_pfm.num_mappings))
    count = min(drs_pfm.num_mappings, ldb_pfm.num_mappings)
    for i in range(0, count):
        it_err = []
        drs_it = drs_pfm.mappings[i]
        ldb_it = ldb_pfm.mappings[i]
        if drs_it.id_prefix != ldb_it.id_prefix:
            it_err.append("id_prefix")
        if drs_it.oid.length != ldb_it.oid.length:
            it_err.append("oid.length")
        if drs_it.oid.binary_oid != ldb_it.oid.binary_oid:
            it_err.append("oid.binary_oid")
        if len(it_err):
            errors.append("[%2d] differences in (%s)" % (i, it_err))
    return errors

########### main code ###########
if __name__ == "__main__":
    # command line parsing
    parser = OptionParser("getncchanges [options] server")
    sambaopts = options.SambaOptions(parser)
    parser.add_option_group(sambaopts)
    credopts = options.CredentialsOptionsDouble(parser)
    parser.add_option_group(credopts)

    (opts, args) = parser.parse_args()

    lp = sambaopts.get_loadparm()
    creds = credopts.get_credentials(lp)

    if len(args) != 1:
        import os
        if not "DC_SERVER" in os.environ.keys():
             parser.error("You must supply a server")
        args.append(os.environ["DC_SERVER"])

    if creds.is_anonymous():
        parser.error("You must supply credentials")
        pass

    server = args[0]

    samdb = SamDB(url="ldap://%s" % server,
                  session_info=system_session(),
                  credentials=creds, lp=lp)

    drs_pfm = _drs_fetch_pfm(server, samdb, creds, lp)
    ldb_pfm = _samdb_fetch_pfm(samdb)
    errors = _pfm_verify(drs_pfm, ldb_pfm)
    if len(errors):
        print "prefixMap verification errors:"
        print "%s" % errors
        sys.exit(1)
