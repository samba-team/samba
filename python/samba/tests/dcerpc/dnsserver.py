# Unix SMB/CIFS implementation.
# Copyright (C) Amitay Isaacs <amitay@gmail.com> 2011
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

"""Tests for samba.dcerpc.dnsserver"""

from samba.dcerpc import dnsp, dnsserver
from samba.tests import RpcInterfaceTestCase, env_get_var_value
from samba.netcmd.dns import ARecord, NSRecord

class DnsserverTests(RpcInterfaceTestCase):

    def setUp(self):
        super(DnsserverTests, self).setUp()
        self.server = env_get_var_value("SERVER_IP")
        self.zone = env_get_var_value("REALM").lower()
        self.conn = dnsserver.dnsserver("ncacn_ip_tcp:%s" % (self.server),
                                        self.get_loadparm(),
                                        self.get_credentials())

    def test_query2(self):
        typeid, result = self.conn.DnssrvQuery2(dnsserver.DNS_CLIENT_VERSION_W2K,
                                                0,
                                                self.server,
                                                None,
                                                'ServerInfo')
        self.assertEquals(dnsserver.DNSSRV_TYPEID_SERVER_INFO_W2K, typeid)

        typeid, result = self.conn.DnssrvQuery2(dnsserver.DNS_CLIENT_VERSION_DOTNET,
                                                0,
                                                self.server,
                                                None,
                                                'ServerInfo')
        self.assertEquals(dnsserver.DNSSRV_TYPEID_SERVER_INFO_DOTNET, typeid)

        typeid, result = self.conn.DnssrvQuery2(dnsserver.DNS_CLIENT_VERSION_LONGHORN,
                                                0,
                                                self.server,
                                                None,
                                                'ServerInfo')
        self.assertEquals(dnsserver.DNSSRV_TYPEID_SERVER_INFO, typeid)

    def test_operation2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        rev_zone = '1.168.192.in-addr.arpa'

        zone_create = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
        zone_create.pszZoneName = rev_zone
        zone_create.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
        zone_create.fAllowUpdate = dnsp.DNS_ZONE_UPDATE_SECURE
        zone_create.fAging = 0
        zone_create.dwDpFlags = dnsserver.DNS_DP_DOMAIN_DEFAULT

        # Create zone
        self.conn.DnssrvOperation2(client_version,
                                    0,
                                    self.server,
                                    None,
                                    0,
                                    'ZoneCreate',
                                    dnsserver.DNSSRV_TYPEID_ZONE_CREATE,
                                    zone_create)

        request_filter = (dnsserver.DNS_ZONE_REQUEST_REVERSE |
                            dnsserver.DNS_ZONE_REQUEST_PRIMARY)
        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(1, zones.dwZoneCount)

        # Delete zone
        self.conn.DnssrvOperation2(client_version,
                                    0,
                                    self.server,
                                    rev_zone,
                                    0,
                                    'DeleteZoneFromDs',
                                    dnsserver.DNSSRV_TYPEID_NULL,
                                    None)

        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(0, zones.dwZoneCount)


    def test_complexoperation2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        request_filter = (dnsserver.DNS_ZONE_REQUEST_FORWARD |
                            dnsserver.DNS_ZONE_REQUEST_PRIMARY)
        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(dnsserver.DNSSRV_TYPEID_ZONE_LIST, typeid)
        self.assertEquals(2, zones.dwZoneCount)

        request_filter = (dnsserver.DNS_ZONE_REQUEST_REVERSE |
                            dnsserver.DNS_ZONE_REQUEST_PRIMARY)
        typeid, zones = self.conn.DnssrvComplexOperation2(client_version,
                                                            0,
                                                            self.server,
                                                            None,
                                                            'EnumZones',
                                                            dnsserver.DNSSRV_TYPEID_DWORD,
                                                            request_filter)
        self.assertEquals(dnsserver.DNSSRV_TYPEID_ZONE_LIST, typeid)
        self.assertEquals(0, zones.dwZoneCount)


    def test_enumrecords2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        record_type = dnsp.DNS_TYPE_NS
        select_flags = (dnsserver.DNS_RPC_VIEW_ROOT_HINT_DATA |
                        dnsserver.DNS_RPC_VIEW_ADDITIONAL_DATA)
        buflen, roothints = self.conn.DnssrvEnumRecords2(client_version,
                                                            0,
                                                            self.server,
                                                            '..RootHints',
                                                            '.',
                                                            None,
                                                            record_type,
                                                            select_flags,
                                                            None,
                                                            None)
        self.assertEquals(14, roothints.count)  # 1 NS + 13 A records (a-m)


    def test_updaterecords2(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        record_type = dnsp.DNS_TYPE_A
        select_flags = dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA

        name = 'dummy'
        rec = ARecord('1.2.3.4')
        rec2 = ARecord('5.6.7.8')

        # Add record
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        add_rec_buf,
                                        None)

        buflen, result = self.conn.DnssrvEnumRecords2(client_version,
                                                        0,
                                                        self.server,
                                                        self.zone,
                                                        name,
                                                        None,
                                                        record_type,
                                                        select_flags,
                                                        None,
                                                        None)
        self.assertEquals(1, result.count)
        self.assertEquals(1, result.rec[0].wRecordCount)
        self.assertEquals(dnsp.DNS_TYPE_A, result.rec[0].records[0].wType)
        self.assertEquals('1.2.3.4', result.rec[0].records[0].data)

        # Update record
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec2
        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        del_rec_buf.rec = rec
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        add_rec_buf,
                                        del_rec_buf)

        buflen, result = self.conn.DnssrvEnumRecords2(client_version,
                                                        0,
                                                        self.server,
                                                        self.zone,
                                                        name,
                                                        None,
                                                        record_type,
                                                        select_flags,
                                                        None,
                                                        None)
        self.assertEquals(1, result.count)
        self.assertEquals(1, result.rec[0].wRecordCount)
        self.assertEquals(dnsp.DNS_TYPE_A, result.rec[0].records[0].wType)
        self.assertEquals('5.6.7.8', result.rec[0].records[0].data)

        # Delete record
        del_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        del_rec_buf.rec = rec2
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        None,
                                        del_rec_buf)

        self.assertRaises(RuntimeError, self.conn.DnssrvEnumRecords2,
                                        client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        name,
                                        None,
                                        record_type,
                                        select_flags,
                                        None,
                                        None)

    def test_updaterecords2_soa(self):
        client_version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
        record_type = dnsp.DNS_TYPE_NS
        select_flags = (dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA |
                        dnsserver.DNS_RPC_VIEW_NO_CHILDREN)

        nameserver = 'ns.example.local'
        rec = NSRecord(nameserver)

        # Add record
        add_rec_buf = dnsserver.DNS_RPC_RECORD_BUF()
        add_rec_buf.rec = rec
        self.conn.DnssrvUpdateRecord2(client_version,
                                        0,
                                        self.server,
                                        self.zone,
                                        '.',
                                        add_rec_buf,
                                        None)

        buflen, result = self.conn.DnssrvEnumRecords2(client_version,
                                                        0,
                                                        self.server,
                                                        self.zone,
                                                        '@',
                                                        None,
                                                        record_type,
                                                        select_flags,
                                                        None,
                                                        None)
        self.assertEquals(1, result.count)
        self.assertEquals(2, result.rec[0].wRecordCount)
        match = False
        for i in range(2):
            self.assertEquals(dnsp.DNS_TYPE_NS, result.rec[0].records[i].wType)
            if result.rec[0].records[i].data.str.rstrip('.') == nameserver:
                match = True
        self.assertEquals(match, True)
