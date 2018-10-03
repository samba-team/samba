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
import time

from ldb import SCOPE_BASE

from samba import nttime2unix, dsdb
from samba.netcmd import CommandError


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
        settings_dn = str(res[0]["distinguishedName"][0])
        prefix, dsa_dn = settings_dn.split(',', 1)
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
