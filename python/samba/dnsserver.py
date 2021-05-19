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

import shlex
import socket
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


class DNSParseError(ValueError):
    pass


class ARecord(dnsserver.DNS_RPC_RECORD):
    def __init__(self, ip_addr, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(ARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_A
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = ip_addr

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        return cls(data, **kwargs)


class AAAARecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, ip6_addr, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(AAAARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_AAAA
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = ip6_addr

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        return cls(data, **kwargs)


class PTRRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, ptr, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(PTRRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_PTR
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        ptr_name = dnsserver.DNS_RPC_NAME()
        ptr_name.str = ptr
        ptr_name.len = len(ptr)
        self.data = ptr_name

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        return cls(data, **kwargs)


class CNAMERecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, cname, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super().__init__()
        self.wType = dnsp.DNS_TYPE_CNAME
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        cname_name = dnsserver.DNS_RPC_NAME()
        cname_name.str = cname
        cname_name.len = len(cname)
        self.data = cname_name

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        return cls(data, **kwargs)


class NSRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, dns_server, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(NSRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_NS
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        ns = dnsserver.DNS_RPC_NAME()
        ns.str = dns_server
        ns.len = len(dns_server)
        self.data = ns

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        return cls(data, **kwargs)


class MXRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, mail_server, preference, serial=1, ttl=900,
                 rank=dnsp.DNS_RANK_ZONE, node_flag=0):
        super(MXRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_MX
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        mx = dnsserver.DNS_RPC_RECORD_NAME_PREFERENCE()
        mx.wPreference = preference
        mx.nameExchange.str = mail_server
        mx.nameExchange.len = len(mail_server)
        self.data = mx

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        try:
            server, priority = data.split(sep)
            priority = int(priority)
        except ValueError as e:
            raise DNSParseError("MX data must have server and priority "
                                "(space separated), not %r" % data) from e
        return cls(server, priority, **kwargs)


class SOARecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, mname, rname, serial=1, refresh=900, retry=600,
                 expire=86400, minimum=3600, ttl=3600, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=dnsp.DNS_RPC_FLAG_AUTH_ZONE_ROOT):
        super(SOARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_SOA
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        soa = dnsserver.DNS_RPC_RECORD_SOA()
        soa.dwSerialNo = serial
        soa.dwRefresh = refresh
        soa.dwRetry = retry
        soa.dwExpire = expire
        soa.dwMinimumTtl = minimum
        soa.NamePrimaryServer.str = mname
        soa.NamePrimaryServer.len = len(mname)
        soa.ZoneAdministratorEmail.str = rname
        soa.ZoneAdministratorEmail.len = len(rname)
        self.data = soa

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        args = data.split(sep)
        if len(args) != 7:
            raise DNSParseError('Data requires 7 space separated elements - '
                                'nameserver, email, serial, '
                                'refresh, retry, expire, minimumttl')
        try:
            for i in range(2, 7):
                args[i] = int(args[i])
        except ValueError as e:
            raise DNSParseError("SOA serial, refresh, retry, expire, minimumttl' "
                                "should be integers") from e
        return cls(*args, **kwargs)


class SRVRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, target, port, priority=0, weight=100, serial=1, ttl=900,
                 rank=dnsp.DNS_RANK_ZONE, node_flag=0):
        super(SRVRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_SRV
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        srv = dnsserver.DNS_RPC_RECORD_SRV()
        srv.wPriority = priority
        srv.wWeight = weight
        srv.wPort = port
        srv.nameTarget.str = target
        srv.nameTarget.len = len(target)
        self.data = srv

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        try:
            target, port, priority, weight = data.split(sep)
        except ValueError as e:
            raise DNSParseError("SRV data must have four space "
                                "separated elements: "
                                "server, port, priority, weight; "
                                "not %r" % data) from e
        try:
            args = (target, int(port), int(priority), int(weight))
        except ValueError as e:
            raise DNSParseError("SRV port, priority, and weight "
                                "must be integers") from e

        return cls(*args, **kwargs)


class TXTRecord(dnsserver.DNS_RPC_RECORD):

    def __init__(self, slist, serial=1, ttl=900, rank=dnsp.DNS_RANK_ZONE,
                 node_flag=0):
        super(TXTRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_TXT
        self.dwFlags = rank | node_flag
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        if isinstance(slist, str):
            slist = [slist]
        names = []
        for s in slist:
            name = dnsserver.DNS_RPC_NAME()
            name.str = s
            name.len = len(s)
            names.append(name)
        txt = dnsserver.DNS_RPC_RECORD_STRING()
        txt.count = len(slist)
        txt.str = names
        self.data = txt

    @classmethod
    def from_string(cls, data, sep=None, **kwargs):
        slist = shlex.split(data)
        return cls(slist, **kwargs)


#
# Don't add new Record types after this line

_RECORD_TYPE_LUT = {}
def _setup_record_type_lut():
    for k, v in globals().items():
        if k[-6:] == 'Record':
            k = k[:-6]
            flag = getattr(dnsp, 'DNS_TYPE_' + k)
            _RECORD_TYPE_LUT[k] = v
            _RECORD_TYPE_LUT[flag] = v

_setup_record_type_lut()
del _setup_record_type_lut


def record_from_string(t, data, sep=None, **kwargs):
    """Get a DNS record of type t based on the data string.
    Additional keywords (ttl, rank, etc) can be passed in.

    t can be a dnsp.DNS_TYPE_* integer or a string like "A", "TXT", etc.
    """
    if isinstance(t, str):
        t = t.upper()
    try:
        Record = _RECORD_TYPE_LUT[t]
    except KeyError as e:
        raise DNSParseError("Unsupported record type") from e

    return Record.from_string(data, sep=sep, **kwargs)


def flag_from_string(rec_type):
    rtype = rec_type.upper()
    try:
        return getattr(dnsp, 'DNS_TYPE_' + rtype)
    except AttributeError:
        raise DNSParseError('Unknown type of DNS record %s' % rec_type) from e


def recbuf_from_string(*args, **kwargs):
    rec = record_from_string(*args, **kwargs)
    buf = dnsserver.DNS_RPC_RECORD_BUF()
    buf.rec = rec
    return buf


def dns_name_equal(n1, n2):
    """Match dns name (of type DNS_RPC_NAME)"""
    return n1.str.rstrip('.').lower() == n2.str.rstrip('.').lower()


def ipv6_normalise(addr):
    """Convert an AAAA adresss into a canonical form."""
    packed = socket.inet_pton(socket.AF_INET6, addr)
    return socket.inet_ntop(socket.AF_INET6, packed)


def dns_record_match(dns_conn, server, zone, name, record_type, data):
    """Find a dns record that matches the specified data"""

    # The matching is not as precises as that offered by
    # dsdb_dns.match_record, which, for example, compares IPv6 records
    # semantically rather than as strings. However that function
    # compares database DnssrvRpcRecord structures, not wire
    # DNS_RPC_RECORD structures.
    #
    # While it would be possible, perhaps desirable, to wrap that
    # function for use in samba-tool, there is value in having a
    # separate implementation for tests, to avoid the circularity of
    # asserting the function matches itself.

    urec = record_from_string(record_type, data)

    select_flags = dnsserver.DNS_RPC_VIEW_AUTHORITY_DATA

    try:
        buflen, res = dns_conn.DnssrvEnumRecords2(
            dnsserver.DNS_CLIENT_VERSION_LONGHORN, 0, server, zone, name, None,
            record_type, select_flags, None, None)
    except WERRORError as e:
        if e.args[0] == werror.WERR_DNS_ERROR_NAME_DOES_NOT_EXIST:
            # Either the zone doesn't exist, or there were no records.
            # We can't differentiate the two.
            return None
        raise e

    if not res or res.count == 0:
        return None

    for rec in res.rec[0].records:
        if rec.wType != record_type:
            continue

        found = False
        if record_type == dnsp.DNS_TYPE_A:
            if rec.data == urec.data:
                found = True
        elif record_type == dnsp.DNS_TYPE_AAAA:
            if ipv6_normalise(rec.data) == ipv6_normalise(urec.data):
                found = True
        elif record_type == dnsp.DNS_TYPE_PTR:
            if dns_name_equal(rec.data, urec.data):
                found = True
        elif record_type == dnsp.DNS_TYPE_CNAME:
            if dns_name_equal(rec.data, urec.data):
                found = True
        elif record_type == dnsp.DNS_TYPE_NS:
            if dns_name_equal(rec.data, urec.data):
                found = True
        elif record_type == dnsp.DNS_TYPE_MX:
            if dns_name_equal(rec.data.nameExchange, urec.data.nameExchange) and \
               rec.data.wPreference == urec.data.wPreference:
                found = True
        elif record_type == dnsp.DNS_TYPE_SRV:
            if rec.data.wPriority == urec.data.wPriority and \
               rec.data.wWeight == urec.data.wWeight and \
               rec.data.wPort == urec.data.wPort and \
               dns_name_equal(rec.data.nameTarget, urec.data.nameTarget):
                found = True
        elif record_type == dnsp.DNS_TYPE_SOA:
            if rec.data.dwSerialNo == urec.data.dwSerialNo and \
               rec.data.dwRefresh == urec.data.dwRefresh and \
               rec.data.dwRetry == urec.data.dwRetry and \
               rec.data.dwExpire == urec.data.dwExpire and \
               rec.data.dwMinimumTtl == urec.data.dwMinimumTtl and \
               dns_name_equal(rec.data.NamePrimaryServer,
                              urec.data.NamePrimaryServer) and \
               dns_name_equal(rec.data.ZoneAdministratorEmail,
                              urec.data.ZoneAdministratorEmail):
                found = True
        elif record_type == dnsp.DNS_TYPE_TXT:
            if rec.data.count == urec.data.count:
                found = True
                for i in range(rec.data.count):
                    found = found and \
                            (rec.data.str[i].str == urec.data.str[i].str)

        if found:
            return rec

    return None
