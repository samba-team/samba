# Uptodateness utils
#
# Copyright (C) Andrew Bartlett 2015, 2018
# Copyright (C) Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
# Copyright (C) Joe Guo <joeg@catalyst.net.nz>
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
from __future__ import print_function

import sys
import time

from ldb import SCOPE_BASE, LdbError

from samba import nttime2unix, dsdb
from samba.netcmd import CommandError
from samba.samdb import SamDB
from samba.kcc import KCC


def get_kcc_and_dsas(url, lp, creds):
    """Get a readonly KCC object and the list of DSAs it knows about."""
    unix_now = int(time.time())
    kcc = KCC(unix_now, readonly=True)
    kcc.load_samdb(url, lp, creds)

    dsa_list = kcc.list_dsas()
    dsas = set(dsa_list)
    if len(dsas) != len(dsa_list):
        print("There seem to be duplicate dsas", file=sys.stderr)

    return kcc, dsas


def get_partition_maps(samdb):
    """Generate dictionaries mapping short partition names to the
    appropriate DNs."""
    base_dn = samdb.domain_dn()
    short_to_long = {
        "DOMAIN": base_dn,
        "CONFIGURATION": str(samdb.get_config_basedn()),
        "SCHEMA": "CN=Schema,%s" % samdb.get_config_basedn(),
        "DNSDOMAIN": "DC=DomainDnsZones,%s" % base_dn,
        "DNSFOREST": "DC=ForestDnsZones,%s" % base_dn
    }

    long_to_short = {}
    for s, l in short_to_long.items():
        long_to_short[l] = s

    return short_to_long, long_to_short


def get_partition(samdb, part):
    # Allow people to say "--partition=DOMAIN" rather than
    # "--partition=DC=blah,DC=..."
    if part is not None:
        short_partitions, long_partitions = get_partition_maps(samdb)
        part = short_partitions.get(part.upper(), part)
        if part not in long_partitions:
            raise CommandError("unknown partition %s" % part)
    return part


def get_utdv(samdb, dn):
    """This finds the uptodateness vector in the database."""
    cursors = []
    config_dn = samdb.get_config_basedn()
    for c in dsdb._dsdb_load_udv_v2(samdb, dn):
        inv_id = str(c.source_dsa_invocation_id)
        res = samdb.search(base=config_dn,
                           expression=("(&(invocationId=%s)"
                                       "(objectClass=nTDSDSA))" % inv_id),
                           attrs=["distinguishedName", "invocationId"])
        try:
            settings_dn = str(res[0]["distinguishedName"][0])
            prefix, dsa_dn = settings_dn.split(',', 1)
        except IndexError as e:
            print("Unknown invocation ID %s" % inv_id,
                  file=sys.stderr)
            continue
        if prefix != 'CN=NTDS Settings':
            raise CommandError("Expected NTDS Settings DN, got %s" %
                               settings_dn)

        cursors.append((dsa_dn,
                        inv_id,
                        int(c.highest_usn),
                        nttime2unix(c.last_sync_success)))
    return cursors


def get_own_cursor(samdb):
    res = samdb.search(base="",
                       scope=SCOPE_BASE,
                       attrs=["highestCommittedUSN"])
    usn = int(res[0]["highestCommittedUSN"][0])
    now = int(time.time())
    return (usn, now)


def get_utdv_edges(local_kcc, dsas, part_dn, lp, creds):
    # we talk to each remote and make a matrix of the vectors
    # for each partition
    # normalise by oldest
    utdv_edges = {}
    for dsa_dn in dsas:
        res = local_kcc.samdb.search(dsa_dn,
                                     scope=SCOPE_BASE,
                                     attrs=["dNSHostName"])
        ldap_url = "ldap://%s" % res[0]["dNSHostName"][0]
        try:
            samdb = SamDB(url=ldap_url, credentials=creds, lp=lp)
            cursors = get_utdv(samdb, part_dn)
            own_usn, own_time = get_own_cursor(samdb)
            remotes = {dsa_dn: own_usn}
            for dn, guid, usn, t in cursors:
                remotes[dn] = usn
        except LdbError as e:
            print("Could not contact %s (%s)" % (ldap_url, e),
                  file=sys.stderr)
            continue
        utdv_edges[dsa_dn] = remotes
    return utdv_edges


def get_utdv_distances(utdv_edges, dsas):
    distances = {}
    for dn1 in dsas:
        try:
            peak = utdv_edges[dn1][dn1]
        except KeyError as e:
            peak = 0
        d = {}
        distances[dn1] = d
        for dn2 in dsas:
            if dn2 in utdv_edges:
                if dn1 in utdv_edges[dn2]:
                    dist = peak - utdv_edges[dn2][dn1]
                    d[dn2] = dist
                else:
                    print("Missing dn %s from UTD vector" % dn1,
                          file=sys.stderr)
            else:
                print("missing dn %s from UTD vector list" % dn2,
                      file=sys.stderr)
    return distances


def get_utdv_max_distance(distances):
    max_distance = 0
    for vector in distances.values():
        for distance in vector.values():
            max_distance = max(max_distance, distance)
    return max_distance


def get_utdv_summary(distances, filters=None):
    maximum = failure = 0
    median = 0.0  # could be average of 2 median values
    values = []
    # put all values into a list, exclude self to self ones
    for dn_outer, vector in distances.items():
        for dn_inner, distance in vector.items():
            if dn_outer != dn_inner:
                values.append(distance)

    if values:
        values.sort()
        maximum = values[-1]
        length = len(values)
        if length % 2 == 0:
            index = length//2 - 1
            median = (values[index] + values[index+1])/2.0
            median = round(median, 1)  # keep only 1 decimal digit like 2.5
        else:
            index = (length - 1)//2
            median = values[index]
            median = float(median)  # ensure median is always a float like 1.0
        # if value not exist, that's a failure
        expected_length = len(distances) * (len(distances) - 1)
        failure = expected_length - length

    summary = {
        'maximum': maximum,
        'median': median,
        'failure': failure,
    }

    if filters:
        return {key: summary[key] for key in filters}
    else:
        return summary
