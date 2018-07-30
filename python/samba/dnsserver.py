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

#
# Always create a copy of strings when creating DNS_RPC_RECORDs
# to overcome the bug in pidl generated python bindings.
#


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


class CNameRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, cname, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(CNameRecord, self).__init__()
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
