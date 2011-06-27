# Unix SMB/CIFS implementation.
# backend code for provisioning DNS for a Samba4 server
#
# Copyright (C) Kai Blin <kai@samba.org> 2011
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

"""DNS-related provisioning"""

import os
import ldb
import samba
from samba.ndr import ndr_pack
from samba import read_and_sub_file
from samba.dcerpc import dnsp

class ARecord(dnsp.DnssrvRpcRecord):
    def __init__(self, ip_addr, serial=1, ttl=3600):
        super(ARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_A
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = ip_addr

class AAAARecord(dnsp.DnssrvRpcRecord):
    def __init__(self, ip6_addr, serial=1, ttl=3600):
        super(AAAARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_AAAA
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = ip6_addr

class NSRecord(dnsp.DnssrvRpcRecord):
    def __init__(self, dns_server, serial=1, ttl=3600):
        super(NSRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_NS
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = dns_server

class SOARecord(dnsp.DnssrvRpcRecord):
    def __init__(self, mname, rname, serial=1, refresh=900, retry=600,
                 expire=86400, minimum=3600, ttl=3600):
        super(SOARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_SOA
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        soa = dnsp.soa()
        soa.serial = serial
        soa.refresh = refresh
        soa.retry = retry
        soa.expire = expire
        soa.mname = mname
        soa.rname = rname
        self.data = soa

class SRVRecord(dnsp.DnssrvRpcRecord):
    def __init__(self, target, port, priority=0, weight=0, serial=1, ttl=3600):
        super(SRVRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_SRV
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        srv = dnsp.srv()
        srv.nameTarget = target
        srv.wPort = port
        srv.wPriority = priority
        srv.wWeight = weight
        self.data = srv

def setup_ad_dns(samdb, names, hostip=None, hostip6=None):
    domaindn = names.domaindn
    dnsdomain = names.dnsdomain.lower()
    hostname = names.netbiosname.lower()
    dnsname = "%s.%s" % (hostname, dnsdomain)
    site = names.sitename

    dns_ldif = os.path.join(samba.param.setup_dir(), "provision_dns_add.ldif")

    dns_data = read_and_sub_file(dns_ldif, {
              "DOMAINDN": domaindn,
              "DNSDOMAIN" : dnsdomain
              })
    samdb.add_ldif(dns_data, ["relax:0"])

    soa_subrecords = []
    dns_records = []

    # @ entry for the domain
    at_soa_record = SOARecord(dnsname, "hostmaster.%s" % dnsdomain)
    soa_subrecords.append(ndr_pack(at_soa_record))

    at_ns_record = NSRecord(dnsname)
    soa_subrecords.append(ndr_pack(at_ns_record))

    if hostip is not None:
        # A record
        at_a_record = ARecord(hostip)
        dns_records.append(ndr_pack(at_a_record))

    if hostip6 is not None:
        at_aaaa_record = AAAARecord(hostip6)
        dns_records.append(ndr_pack(at_aaaa_record))

    msg = ldb.Message(ldb.Dn(samdb, "DC=@,DC=%s,CN=MicrosoftDNS,CN=System,%s" %\
                                    (dnsdomain, domaindn )))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = ldb.MessageElement(soa_subrecords + dns_records,
                                          ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.add(msg)

    # _gc._tcp record
    gc_tcp_record = SRVRecord(dnsname, 3268)
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_gc._tcp,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(gc_tcp_record)]
    samdb.add(msg)

    # _gc._tcp.sitename._site record
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_gc._tcp.%s._sites,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (names.sitename, dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(gc_tcp_record)]
    samdb.add(msg)

    # _kerberos._tcp record
    kerberos_record = SRVRecord(dnsname, 88)
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_kerberos._tcp,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(kerberos_record)]
    samdb.add(msg)

    # _kerberos._tcp.sitename._site record
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_kerberos._tcp.%s._sites,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (site, dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(kerberos_record)]
    samdb.add(msg)

    # _kerberos._udp record
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_kerberos._udp,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(kerberos_record)]
    samdb.add(msg)

    # _kpasswd._tcp record
    kpasswd_record = SRVRecord(dnsname, 464)
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_kpasswd._tcp,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(kpasswd_record)]
    samdb.add(msg)

    # _kpasswd._udp record
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_kpasswd._udp,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(kpasswd_record)]
    samdb.add(msg)

    # _ldap._tcp record
    ldap_record = SRVRecord(dnsname, 389)
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_ldap._tcp,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(ldap_record)]
    samdb.add(msg)

    # _ldap._tcp.sitename._site record
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_ldap._tcp.%s._site,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (site, dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(ldap_record)]
    samdb.add(msg)

    # _msdcs record
    msdcs_record = NSRecord(dnsname)
    msg = ldb.Message(ldb.Dn(samdb,
            "DC=_msdcs,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                    (dnsdomain, domaindn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = [ndr_pack(msdcs_record)]
    samdb.add(msg)

    # the host's own record
    # Only do this if there's IP addresses to set up.
    # This is a bit weird, but the samba4.blackbox.provision.py test apparently
    # doesn't set up any IPs
    if len(dns_records) > 0:
        msg = ldb.Message(ldb.Dn(samdb,
                "DC=%s,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                        (hostname, dnsdomain, domaindn)))
        msg["objectClass"] = ["top", "dnsNode"]
        msg["dnsRecord"] = ldb.MessageElement(dns_records,
                                              ldb.FLAG_MOD_ADD, "dnsRecord")
        samdb.add(msg)

        # DomainDnsZones record
        msg = ldb.Message(ldb.Dn(samdb,
                "DC=DomainDnsZones,DC=%s,CN=MicrosoftDNS,CN=System,%s" % \
                        (dnsdomain, domaindn)))
        msg["objectClass"] = ["top", "dnsNode"]
        msg["dnsRecord"] = ldb.MessageElement(dns_records,
                                              ldb.FLAG_MOD_ADD, "dnsRecord")

        samdb.add(msg)


