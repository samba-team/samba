# helper for DNS management tool
#
# Copyright (C) Amitay Isaacs 2011-2012
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

from samba.dcerpc import dnsserver, dnsp

# Note: these are not quite the same as similar looking classes in
# provision/sambadns.py -- those ones are based on
# dnsp.DnssrvRpcRecord, these are based on dnsserver.DNS_RPC_RECORD.
# They encode the same information in slightly different ways.
#
# DNS_RPC_RECORD structures ([MS-DNSP]2.2.2.2.5 "DNS_RPC_RECORD") are
# used on the wire by DnssrvEnumRecords2. The dnsp.DnssrvRpcRecord
# versions have the in-database version of the same information, where
# the flags field is unpacked, and the struct ordering is different.
# See [MS-DNSP] 2.3.2.2 "DnsRecord".
#
# In both cases the structure and contents of .data depend on .wType.
# For example, if .wType is DNS_TYPE_A, .data is an IPv4 address. If
# the .wType is changed to DNS_TYPE_CNAME, the contents of .data will
# be interpreted as a cname blob, but the bytes there will still be
# those of the IPv4 address. If you don't also set the .data you may
# encounter stability problems. These DNS_RPC_RECORD subclasses
# attempt to hide that from you, but are only pretending -- any of
# them can represent any type of record.



class ARecord(dnsserver.DNS_RPC_RECORD):
    def __init__(self, ip_addr, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(ARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_A
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._ip_addr = ip_addr[:]
        self.data = self._ip_addr


class AAAARecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, ip6_addr, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(AAAARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_AAAA
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._ip6_addr = ip6_addr[:]
        self.data = self._ip6_addr


class PTRRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, ptr, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(PTRRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_PTR
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._ptr = ptr[:]
        ptr_name = dnsserver.DNS_RPC_NAME()
        ptr_name.str = self._ptr
        ptr_name.len = len(ptr)
        self.data = ptr_name


class CNAMERecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, cname, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super().__init__()
        self.wType = dnsp.DNS_TYPE_CNAME
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._cname = cname[:]
        cname_name = dnsserver.DNS_RPC_NAME()
        cname_name.str = self._cname
        cname_name.len = len(cname)
        self.data = cname_name


class NSRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, dns_server, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(NSRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_NS
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._dns_server = dns_server[:]
        ns = dnsserver.DNS_RPC_NAME()
        ns.str = self._dns_server
        ns.len = len(dns_server)
        self.data = ns


class MXRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, mail_server, preference, serial=1, ttl=900,
                 rank=dnsp.DNS_RANK_ZONE, node_flag=0):
        super(MXRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_MX
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._mail_server = mail_server[:]
        mx = dnsserver.DNS_RPC_RECORD_NAME_PREFERENCE()
        mx.wPreference = preference
        mx.nameExchange.str = self._mail_server
        mx.nameExchange.len = len(mail_server)
        self.data = mx


class SOARecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, mname, rname, serial=1, refresh=900, retry=600,
                 expire=86400, minimum=3600, ttl=3600, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=dnsp.DNS_RPC_FLAG_AUTH_ZONE_ROOT):
        super(SOARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_SOA
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._mname = mname[:]
        self._rname = rname[:]
        soa = dnsserver.DNS_RPC_RECORD_SOA()
        soa.dwSerialNo = serial
        soa.dwRefresh = refresh
        soa.dwRetry = retry
        soa.dwExpire = expire
        soa.dwMinimumTtl = minimum
        soa.NamePrimaryServer.str = self._mname
        soa.NamePrimaryServer.len = len(mname)
        soa.ZoneAdministratorEmail.str = self._rname
        soa.ZoneAdministratorEmail.len = len(rname)
        self.data = soa


class SRVRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, target, port, priority=0, weight=100, serial=1, ttl=900,
                 rank=dnsp.DNS_RANK_ZONE, node_flag=0):
        super(SRVRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_SRV
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._target = target[:]
        srv = dnsserver.DNS_RPC_RECORD_SRV()
        srv.wPriority = priority
        srv.wWeight = weight
        srv.wPort = port
        srv.nameTarget.str = self._target
        srv.nameTarget.len = len(target)
        self.data = srv


class TXTRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, slist, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(TXTRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_TXT
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self._slist = []
        for s in slist:
            self._slist.append(s[:])
        names = []
        for s in self._slist:
            name = dnsserver.DNS_RPC_NAME()
            name.str = s
            name.len = len(s)
            names.append(name)
        txt = dnsserver.DNS_RPC_RECORD_STRING()
        txt.count = len(slist)
        txt.str = names
        self.data = txt
