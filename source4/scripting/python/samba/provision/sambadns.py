# Unix SMB/CIFS implementation.
# backend code for provisioning DNS for a Samba4 server
#
# Copyright (C) Kai Blin <kai@samba.org> 2011
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

"""DNS-related provisioning"""

import os
import uuid
import ldb
import samba
from samba.ndr import ndr_pack, ndr_unpack
from samba import read_and_sub_file
from samba.dcerpc import dnsp, misc
from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2000,
    DS_DOMAIN_FUNCTION_2003,
    DS_DOMAIN_FUNCTION_2008,
    DS_DOMAIN_FUNCTION_2008_R2
    )


def add_ldif(ldb, ldif_file, subst_vars, controls=["relax:0"]):
    ldif_file_path = os.path.join(samba.param.setup_dir(), ldif_file)
    data = read_and_sub_file(ldif_file_path, subst_vars)
    ldb.add_ldif(data, controls)

def modify_ldif(ldb, ldif_file, subst_vars, controls=["relax:0"]):
    ldif_file_path = os.path.join(samba.param.setup_dir(), ldif_file)
    data = read_and_sub_file(ldif_file_path, subst_vars)
    ldb.modify_ldif(data, controls)

def get_domainguid(samdb, domaindn):
    res = samdb.search(base=domaindn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
    domainguid =  str(ndr_unpack(misc.GUID, res[0]["objectGUID"][0]))
    return domainguid

def get_ntdsguid(samdb, domaindn):
    configdn = "CN=Configuration,%s" % domaindn

    res1 = samdb.search(base="OU=Domain Controllers,%s" % domaindn, scope=ldb.SCOPE_ONELEVEL,
                        attrs=["dNSHostName"])

    res2 = samdb.search(expression="serverReference=%s" % res1[0].dn, base=configdn)

    res3 = samdb.search(base="CN=NTDS Settings,%s" % res2[0].dn, scope=ldb.SCOPE_BASE,
                        attrs=["objectGUID"])
    ntdsguid = str(ndr_unpack(misc.GUID, res3[0]["objectGUID"][0]))
    return ntdsguid


class ARecord(dnsp.DnssrvRpcRecord):
    def __init__(self, ip_addr, serial=1, ttl=900):
        super(ARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_A
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = ip_addr

class AAAARecord(dnsp.DnssrvRpcRecord):
    def __init__(self, ip6_addr, serial=1, ttl=900):
        super(AAAARecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_AAAA
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = ip6_addr

class CNameRecord(dnsp.DnssrvRpcRecord):
    def __init__(self, cname, serial=1, ttl=900):
        super(CNameRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_CNAME
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = cname

class NSRecord(dnsp.DnssrvRpcRecord):
    def __init__(self, dns_server, serial=1, ttl=900):
        super(NSRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_NS
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = dns_server

class RootNSRecord(dnsp.DnssrvRpcRecord):
    def __init__(self, dns_server, serial=1, ttl=3600):
        super(RootNSRecord, self).__init__()
        self.wType = dnsp.DNS_TYPE_NS
        self.dwSerial = serial
        self.dwTtlSeconds = ttl
        self.data = dns_server
        self.rank = dnsp.DNS_RANK_ROOT_HINT

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
    def __init__(self, target, port, priority=0, weight=100, serial=1, ttl=900):
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


def setup_dns_partitions(samdb, domaindn, forestdn, configdn, serverdn):

    # FIXME: Default security descriptor for Domain-DNS objectCategory is different in
    #        our documentation from windows

    domainzone_dn = "DC=DomainDnsZones,%s" % domaindn
    forestzone_dn = "DC=ForestDnsZones,%s" % forestdn

    add_ldif(samdb, "provision_dnszones_partitions.ldif", {
        "DOMAINZONE_DN": domainzone_dn,
        "FORESTZONE_DN": forestzone_dn,
        })

    domainzone_guid = get_domainguid(samdb, domainzone_dn)
    forestzone_guid = get_domainguid(samdb, forestzone_dn)

    domainzone_guid = str(uuid.uuid4())
    forestzone_guid = str(uuid.uuid4())

    domainzone_dns = ldb.Dn(samdb, domainzone_dn).canonical_ex_str().strip()
    forestzone_dns = ldb.Dn(samdb, forestzone_dn).canonical_ex_str().strip()

    add_ldif(samdb, "provision_dnszones_add.ldif", {
        "DOMAINZONE_DN": domainzone_dn,
        "FORESTZONE_DN": forestzone_dn,
        "DOMAINZONE_GUID": domainzone_guid,
        "FORESTZONE_GUID": forestzone_guid,
        "DOMAINZONE_DNS": domainzone_dns,
        "FORESTZONE_DNS": forestzone_dns,
        "CONFIGDN": configdn,
        "SERVERDN": serverdn,
        })

    modify_ldif(samdb, "provision_dnszones_modify.ldif", {
        "CONFIGDN": configdn,
        "SERVERDN": serverdn,
        "DOMAINZONE_DN": domainzone_dn,
        "FORESTZONE_DN": forestzone_dn,
    })


def add_dns_accounts(samdb, domaindn):
    add_ldif(samdb, "provision_dns_accounts_add.ldif", {
        "DOMAINDN": domaindn,
        })

def add_dns_container(samdb, domaindn, prefix):
    # CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    msg = ldb.Message(ldb.Dn(samdb, "CN=MicrosoftDNS,%s,%s" % (prefix, domaindn)))
    msg["objectClass"] = ["top", "container"]
    msg["displayName"] = ldb.MessageElement("DNS Servers", ldb.FLAG_MOD_ADD, "displayName")
    samdb.add(msg)


def add_rootservers(samdb, domaindn, prefix):
    rootservers = {}
    rootservers["a.root-servers.net"] = "198.41.0.4"
    rootservers["b.root-servers.net"] = "192.228.79.201"
    rootservers["c.root-servers.net"] = "192.33.4.12"
    rootservers["d.root-servers.net"] = "128.8.10.90"
    rootservers["e.root-servers.net"] = "192.203.230.10"
    rootservers["f.root-servers.net"] = "192.5.5.241"
    rootservers["g.root-servers.net"] = "192.112.36.4"
    rootservers["h.root-servers.net"] = "128.63.2.53"
    rootservers["i.root-servers.net"] = "192.36.148.17"
    rootservers["j.root-servers.net"] = "192.58.128.30"
    rootservers["k.root-servers.net"] = "193.0.14.129"
    rootservers["l.root-servers.net"] = "199.7.83.42"
    rootservers["m.root-servers.net"] = "202.12.27.33"

    rootservers_v6 = {}
    rootservers_v6["a.root-servers.net"] = "2001:503:ba3e::2:30"
    rootservers_v6["f.root-servers.net"] = "2001:500:2f::f"
    rootservers_v6["h.root-servers.net"] = "2001:500:1::803f:235"
    rootservers_v6["j.root-servers.net"] = "2001:503:c27::2:30"
    rootservers_v6["k.root-servers.net"] = "2001:7fd::1"
    rootservers_v6["m.root-servers.net"] = "2001:dc3::35"

    container_dn = "DC=RootDNSServers,CN=MicrosoftDNS,%s,%s" % (prefix, domaindn)

    # Add DC=RootDNSServers,CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    msg = ldb.Message(ldb.Dn(samdb, container_dn))
    msg["objectClass"] = ["top", "dnsZone"]
    samdb.add(msg)

    # Add DC=@,DC=RootDNSServers,CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    record = []
    for rserver in rootservers:
        record.append(ndr_pack(RootNSRecord(rserver, serial=0, ttl=0)))

    msg = ldb.Message(ldb.Dn(samdb, "DC=@,%s" % container_dn))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = ldb.MessageElement(record, ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.add(msg)

    # Add DC=<rootserver>,DC=RootDNSServers,CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    for rserver in rootservers:
        record = [ndr_pack(ARecord(rootservers[rserver], serial=0, ttl=0))]
        # Add AAAA record as well (How does W2K* add IPv6 records?)
        #if rserver in rootservers_v6:
        #    record.append(ndr_pack(AAAARecord(rootservers_v6[rserver], serial=0, ttl=0)))
        msg = ldb.Message(ldb.Dn(samdb, "DC=%s,%s" % (rserver, container_dn)))
        msg["objectClass"] = ["top", "dnsNode"]
        msg["dnsRecord"] = ldb.MessageElement(record, ldb.FLAG_MOD_ADD, "dnsRecord")
        samdb.add(msg)

def add_at_record(samdb, container_dn, prefix, hostname, dnsdomain, hostip, hostip6):

    fqdn_hostname = "%s.%s" % (hostname, dnsdomain)

    at_records = []

    # SOA record
    at_soa_record = SOARecord(fqdn_hostname, "hostmaster.%s" % dnsdomain)
    at_records.append(ndr_pack(at_soa_record))

    # NS record
    at_ns_record = NSRecord(fqdn_hostname)
    at_records.append(ndr_pack(at_ns_record))

    if hostip is not None:
        # A record
        at_a_record = ARecord(hostip)
        at_records.append(ndr_pack(at_a_record))

    if hostip6 is not None:
        # AAAA record
        at_aaaa_record = AAAARecord(hostip6)
        at_records.append(ndr_pack(at_aaaa_record))

    msg = ldb.Message(ldb.Dn(samdb, "DC=@,%s" % container_dn))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = ldb.MessageElement(at_records, ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.add(msg)

def add_srv_record(samdb, container_dn, prefix, host, port):
    srv_record = SRVRecord(host, port)
    msg = ldb.Message(ldb.Dn(samdb, "%s,%s" % (prefix, container_dn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = ldb.MessageElement(ndr_pack(srv_record), ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.add(msg)

def add_ns_record(samdb, container_dn, prefix, host):
    ns_record = NSRecord(host)
    msg = ldb.Message(ldb.Dn(samdb, "%s,%s" % (prefix, container_dn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = ldb.MessageElement(ndr_pack(ns_record), ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.add(msg)

def add_cname_record(samdb, container_dn, prefix, host):
    cname_record = CNameRecord(host)
    msg = ldb.Message(ldb.Dn(samdb, "%s,%s" % (prefix, container_dn)))
    msg["objectClass"] = ["top", "dnsNode"]
    msg["dnsRecord"] = ldb.MessageElement(ndr_pack(cname_record), ldb.FLAG_MOD_ADD, "dnsRecord")
    samdb.add(msg)

def add_host_record(samdb, container_dn, prefix, hostip, hostip6):
    host_records = []
    if hostip:
        a_record = ARecord(hostip)
        host_records.append(ndr_pack(a_record))
    if hostip6:
        aaaa_record = AAAARecord(hostip6)
        host_records.append(ndr_pack(aaaa_record))
    if host_records:
        msg = ldb.Message(ldb.Dn(samdb, "%s,%s" % (prefix, container_dn)))
        msg["objectClass"] = ["top", "dnsNode"]
        msg["dnsRecord"] = ldb.MessageElement(host_records, ldb.FLAG_MOD_ADD, "dnsRecord")
        samdb.add(msg)

def add_domain_record(samdb, domaindn, prefix, dnsdomain):
    # DC=<DNSDOMAIN>,CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    msg = ldb.Message(ldb.Dn(samdb, "DC=%s,CN=MicrosoftDNS,%s,%s" % (dnsdomain, prefix, domaindn)))
    msg["objectClass"] = ["top", "dnsZone"]
    samdb.add(msg)

def add_msdcs_record(samdb, forestdn, prefix, dnsforest):
    # DC=_msdcs.<DNSFOREST>,CN=MicrosoftDNS,<PREFIX>,<FORESTDN>
    msg = ldb.Message(ldb.Dn(samdb, "DC=_msdcs.%s,CN=MicrosoftDNS,%s,%s" %
                                    (dnsforest, prefix, forestdn)))
    msg["objectClass"] = ["top", "dnsZone"]
    samdb.add(msg)


def add_dc_domain_records(samdb, domaindn, prefix, site, dnsdomain, hostname, hostip, hostip6):

    fqdn_hostname = "%s.%s" % (hostname, dnsdomain)

    # Set up domain container - DC=<DNSDOMAIN>,CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    domain_container_dn = ldb.Dn(samdb, "DC=%s,CN=MicrosoftDNS,%s,%s" %
                                    (dnsdomain, prefix, domaindn))

    # DC=@ record
    add_at_record(samdb, domain_container_dn, "DC=@", hostname, dnsdomain, hostip, hostip6)

    # DC=<HOSTNAME> record
    add_host_record(samdb, domain_container_dn, "DC=%s" % hostname, hostip, hostip6)

    # DC=_kerberos._tcp record
    add_srv_record(samdb, domain_container_dn, "DC=_kerberos._tcp", fqdn_hostname, 88)

    # DC=_kerberos._tcp.<SITENAME>._sites record
    add_srv_record(samdb, domain_container_dn, "DC=_kerberos._tcp.%s._sites" % site,
                    fqdn_hostname, 88)

    # DC=_kerberos._udp record
    add_srv_record(samdb, domain_container_dn, "DC=_kerberos._udp", fqdn_hostname, 88)

    # DC=_kpasswd._tcp record
    add_srv_record(samdb, domain_container_dn, "DC=_kpasswd._tcp", fqdn_hostname, 464)

    # DC=_kpasswd._udp record
    add_srv_record(samdb, domain_container_dn, "DC=_kpasswd._udp", fqdn_hostname, 464)

    # DC=_ldap._tcp record
    add_srv_record(samdb, domain_container_dn, "DC=_ldap._tcp", fqdn_hostname, 389)

    # DC=_ldap._tcp.<SITENAME>._sites record
    add_srv_record(samdb, domain_container_dn, "DC=_ldap._tcp.%s._sites" % site,
                    fqdn_hostname, 389)

    # FIXME: The number of SRV records depend on the various roles this DC has.
    #        _gc and _msdcs records are added if the we are the forest dc and not subdomain dc
    #
    # Assumption: current DC is GC and add all the entries

    # DC=_gc._tcp record
    add_srv_record(samdb, domain_container_dn, "DC=_gc._tcp", fqdn_hostname, 3268)

    # DC=_gc._tcp.<SITENAME>,_sites record
    add_srv_record(samdb, domain_container_dn, "DC=_gc._tcp.%s._sites" % site, fqdn_hostname, 3268)

    # DC=_msdcs record
    add_ns_record(samdb, domain_container_dn, "DC=_msdcs", fqdn_hostname)

    # FIXME: Following entries are added only if DomainDnsZones and ForestDnsZones partitions
    #        are created
    #
    # Assumption: Additional entries won't hurt on os_level = 2000

    # DC=_ldap._tcp.<SITENAME>._sites.DomainDnsZones
    add_srv_record(samdb, domain_container_dn, "DC=_ldap._tcp.%s._sites.DomainDnsZones" % site,
                    fqdn_hostname, 389)

    # DC=_ldap._tcp.<SITENAME>._sites.ForestDnsZones
    add_srv_record(samdb, domain_container_dn, "DC=_ldap._tcp.%s._sites.ForestDnsZones" % site,
                    fqdn_hostname, 389)

    # DC=_ldap._tcp.DomainDnsZones
    add_srv_record(samdb, domain_container_dn, "DC=_ldap._tcp.DomainDnsZones",
                    fqdn_hostname, 389)

    # DC=_ldap._tcp.ForestDnsZones
    add_srv_record(samdb, domain_container_dn, "DC=_ldap._tcp.ForestDnsZones",
                    fqdn_hostname, 389)

    # DC=DomainDnsZones
    add_host_record(samdb, domain_container_dn, "DC=DomainDnsZones", hostip, hostip6)

    # DC=ForestDnsZones
    add_host_record(samdb, domain_container_dn, "DC=ForestDnsZones", hostip, hostip6)


def add_dc_msdcs_records(samdb, forestdn, prefix, site, dnsforest, hostname,
                            hostip, hostip6, domainguid, ntdsguid):

    fqdn_hostname = "%s.%s" % (hostname, dnsforest)

    # Set up forest container - DC=<DNSDOMAIN>,CN=MicrosoftDNS,<PREFIX>,<DOMAINDN>
    forest_container_dn = ldb.Dn(samdb, "DC=_msdcs.%s,CN=MicrosoftDNS,%s,%s" %
                                    (dnsforest, prefix, forestdn))

    # DC=@ record
    add_at_record(samdb, forest_container_dn, "DC=@", hostname, dnsforest, None, None)

    # DC=_kerberos._tcp.dc record
    add_srv_record(samdb, forest_container_dn, "DC=_kerberos._tcp.dc", fqdn_hostname, 88)

    # DC=_kerberos._tcp.<SITENAME>._sites.dc record
    add_srv_record(samdb, forest_container_dn, "DC=_kerberos._tcp.%s._sites.dc" % site,
                    fqdn_hostname, 88)

    # DC=_ldap._tcp.dc record
    add_srv_record(samdb, forest_container_dn, "DC=_ldap._tcp.dc", fqdn_hostname, 389)

    # DC=_ldap._tcp.<SITENAME>._sites.dc record
    add_srv_record(samdb, forest_container_dn, "DC=_ldap._tcp.%s._sites.dc" % site,
                    fqdn_hostname, 389)

    # DC=_ldap._tcp.<SITENAME>._sites.gc record
    add_srv_record(samdb, forest_container_dn, "DC=_ldap._tcp.%s._sites.gc" % site,
                    fqdn_hostname, 3268)

    # DC=_ldap._tcp.gc record
    add_srv_record(samdb, forest_container_dn, "DC=_ldap._tcp.gc", fqdn_hostname, 3268)

    # DC=_ldap._tcp.pdc record
    add_srv_record(samdb, forest_container_dn, "DC=_ldap._tcp.pdc", fqdn_hostname, 389)

    # DC=gc record
    add_host_record(samdb, forest_container_dn, "DC=gc", hostip, hostip6)

    # DC=_ldap._tcp.<DOMAINGUID>.domains record
    add_srv_record(samdb, forest_container_dn, "DC=_ldap._tcp.%s.domains" % domainguid,
                    fqdn_hostname, 389)

    # DC=<NTDSGUID>
    add_cname_record(samdb, forest_container_dn, "DC=%s" % ntdsguid, fqdn_hostname)


def setup_ad_dns(samdb, names, logger, hostip=None, hostip6=None, dns_backend=None,
                os_level=None):
    """Provision DNS information (assuming GC role)

    :param samdb: LDB object connected to sam.ldb file
    :param names: Names shortcut
    :param logger: Logger object
    :param hostip: IPv4 address
    :param hostip6: IPv6 address
    :param dns_backend: Type of DNS backend
    :param os_level: Functional level (treated as os level)
    """

    if dns_backend is None:
        dns_backend = "BIND9"
        logger.info("Assuming bind9 DNS server backend")

    # If dns_backend is BIND9
    #   Populate only CN=MicrosoftDNS,CN=System,<DOMAINDN>
    #
    # If dns_backend is SAMBA or BIND9_DLZ 
    #   Populate DNS partitions

    if os_level is None:
        os_level = DS_DOMAIN_FUNCTION_2003

    # If os_level < 2003 (DS_DOMAIN_FUNCTION_2000)
    #   All dns records are in CN=MicrosoftDNS,CN=System,<DOMAINDN>
    #
    # If os_level >= 2003 (DS_DOMAIN_FUNCTION_2003, DS_DOMAIN_FUNCTION_2008,
    #                        DS_DOMAIN_FUNCTION_2008_R2)
    #   Root server records are in CN=MicrosoftDNS,CN=System,<DOMAINDN>
    #   Domain records are in CN=MicrosoftDNS,CN=System,<DOMAINDN>
    #   Domain records are in CN=MicrosoftDNS,DC=DomainDnsZones,<DOMAINDN>
    #   Forest records are in CN=MicrosoftDNS,DC=ForestDnsZones,<DOMAINDN>

    domaindn = names.domaindn
    forestdn = samdb.get_root_basedn().get_linearized()

    dnsdomain = names.dnsdomain.lower()
    dnsforest = dnsdomain

    hostname = names.netbiosname.lower()
    site = names.sitename

    domainguid = get_domainguid(samdb, domaindn)
    ntdsguid = get_ntdsguid(samdb, domaindn)

    # Add dns accounts (DnsAdmins, DnsUpdateProxy) in domain
    logger.info("Adding DNS accounts")
    add_dns_accounts(samdb, domaindn)

    logger.info("Populating CN=System,%s" % domaindn)

    # Set up MicrosoftDNS container
    add_dns_container(samdb, domaindn, "CN=System")

    # Add root servers
    add_rootservers(samdb, domaindn, "CN=System")

    if os_level == DS_DOMAIN_FUNCTION_2000:

        # Add domain record
        add_domain_record(samdb, domaindn, "CN=System", dnsdomain)

        # Add DNS records for a DC in domain
        add_dc_domain_records(samdb, domaindn, "CN=System", site, dnsdomain,
                                hostname, hostip, hostip6)

    elif (dns_backend == "SAMBA" or dns_backend == "BIND9_DLZ") and (
            os_level == DS_DOMAIN_FUNCTION_2003 or
            os_level == DS_DOMAIN_FUNCTION_2008 or
            os_level == DS_DOMAIN_FUNCTION_2008_R2):

        # Set up additional partitions (DomainDnsZones, ForstDnsZones)
        logger.info("Creating DomainDnsZones and ForestDnsZones partitions")
        setup_dns_partitions(samdb, domaindn, forestdn, names.configdn, names.serverdn)

        ##### Set up DC=DomainDnsZones,<DOMAINDN>
        logger.info("Populating DomainDnsZones partition")

        # Set up MicrosoftDNS container
        add_dns_container(samdb, domaindn, "DC=DomainDnsZones")

        # Add rootserver records
        add_rootservers(samdb, domaindn, "DC=DomainDnsZones")

        # Add domain record
        add_domain_record(samdb, domaindn, "DC=DomainDnsZones", dnsdomain)

        # Add DNS records for a DC in domain
        add_dc_domain_records(samdb, domaindn, "DC=DomainDnsZones", site, dnsdomain,
                                hostname, hostip, hostip6)

        ##### Set up DC=ForestDnsZones,<DOMAINDN>
        logger.info("Populating ForestDnsZones partition")

        # Set up MicrosoftDNS container
        add_dns_container(samdb, forestdn, "DC=ForestDnsZones")

        # Add _msdcs record
        add_msdcs_record(samdb, forestdn, "DC=ForestDnsZones", dnsforest)

        # Add DNS records for a DC in forest
        add_dc_msdcs_records(samdb, forestdn, "DC=ForestDnsZones", site, dnsforest,
                                hostname, hostip, hostip6, domainguid, ntdsguid)
