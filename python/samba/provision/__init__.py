# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2012
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008-2009
# Copyright (C) Oliver Liebel <oliver@itc.li> 2008-2009
#
# Based on the original in EJS:
# Copyright (C) Andrew Tridgell <tridge@samba.org> 2005
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

"""Functions for setting up a Samba configuration."""

__docformat__ = "restructuredText"

from base64 import b64encode
import os
import re
import pwd
import grp
import logging
import time
import uuid
import socket
import urllib
import string
import tempfile

import ldb

from samba.auth import system_session, admin_session
import samba
from samba.samba3 import smbd, passdb
from samba.samba3 import param as s3param
from samba.dsdb import DS_DOMAIN_FUNCTION_2000
from samba import (
    Ldb,
    MAX_NETBIOS_NAME_LEN,
    check_all_substituted,
    is_valid_netbios_char,
    setup_file,
    substitute_var,
    valid_netbios_name,
    version,
    )
from samba.dcerpc import security, misc
from samba.dcerpc.misc import (
    SEC_CHAN_BDC,
    SEC_CHAN_WKSTA,
    )
from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2003,
    DS_DOMAIN_FUNCTION_2008_R2,
    ENC_ALL_TYPES,
    )
from samba.idmap import IDmapDB
from samba.ms_display_specifiers import read_ms_ldif
from samba.ntacls import setntacl, getntacl, dsacl2fsacl
from samba.ndr import ndr_pack, ndr_unpack
from samba.provision.backend import (
    ExistingBackend,
    FDSBackend,
    LDBBackend,
    OpenLDAPBackend,
    )
from samba.descriptor import (
    get_empty_descriptor,
    get_config_descriptor,
    get_config_partitions_descriptor,
    get_config_sites_descriptor,
    get_config_ntds_quotas_descriptor,
    get_config_delete_protected1_descriptor,
    get_config_delete_protected1wd_descriptor,
    get_config_delete_protected2_descriptor,
    get_domain_descriptor,
    get_domain_infrastructure_descriptor,
    get_domain_builtin_descriptor,
    get_domain_computers_descriptor,
    get_domain_users_descriptor,
    get_domain_controllers_descriptor,
    get_domain_delete_protected1_descriptor,
    get_domain_delete_protected2_descriptor,
    get_dns_partition_descriptor,
    get_dns_forest_microsoft_dns_descriptor,
    get_dns_domain_microsoft_dns_descriptor,
    )
from samba.provision.common import (
    setup_path,
    setup_add_ldif,
    setup_modify_ldif,
    )
from samba.provision.sambadns import (
    get_dnsadmins_sid,
    setup_ad_dns,
    create_dns_update_list
    )

import samba.param
import samba.registry
from samba.schema import Schema
from samba.samdb import SamDB
from samba.dbchecker import dbcheck


DEFAULT_POLICY_GUID = "31B2F340-016D-11D2-945F-00C04FB984F9"
DEFAULT_DC_POLICY_GUID = "6AC1786C-016F-11D2-945F-00C04fB984F9"
DEFAULTSITE = "Default-First-Site-Name"
LAST_PROVISION_USN_ATTRIBUTE = "lastProvisionUSN"


class ProvisionPaths(object):

    def __init__(self):
        self.shareconf = None
        self.hklm = None
        self.hkcu = None
        self.hkcr = None
        self.hku = None
        self.hkpd = None
        self.hkpt = None
        self.samdb = None
        self.idmapdb = None
        self.secrets = None
        self.keytab = None
        self.dns_keytab = None
        self.dns = None
        self.winsdb = None
        self.private_dir = None
        self.state_dir = None


class ProvisionNames(object):

    def __init__(self):
        self.ncs = None
        self.rootdn = None
        self.domaindn = None
        self.configdn = None
        self.schemadn = None
        self.dnsforestdn = None
        self.dnsdomaindn = None
        self.ldapmanagerdn = None
        self.dnsdomain = None
        self.realm = None
        self.netbiosname = None
        self.domain = None
        self.hostname = None
        self.sitename = None
        self.smbconf = None
        self.name_map = {}


def find_provision_key_parameters(samdb, secretsdb, idmapdb, paths, smbconf,
        lp):
    """Get key provision parameters (realm, domain, ...) from a given provision

    :param samdb: An LDB object connected to the sam.ldb file
    :param secretsdb: An LDB object connected to the secrets.ldb file
    :param idmapdb: An LDB object connected to the idmap.ldb file
    :param paths: A list of path to provision object
    :param smbconf: Path to the smb.conf file
    :param lp: A LoadParm object
    :return: A list of key provision parameters
    """
    names = ProvisionNames()
    names.adminpass = None

    # NT domain, kerberos realm, root dn, domain dn, domain dns name
    names.domain = string.upper(lp.get("workgroup"))
    names.realm = lp.get("realm")
    names.dnsdomain = names.realm.lower()
    basedn = samba.dn_from_dns_name(names.dnsdomain)
    names.realm = string.upper(names.realm)
    # netbiosname
    # Get the netbiosname first (could be obtained from smb.conf in theory)
    res = secretsdb.search(expression="(flatname=%s)" %
                            names.domain,base="CN=Primary Domains",
                            scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"])
    names.netbiosname = str(res[0]["sAMAccountName"]).replace("$","")

    names.smbconf = smbconf

    # That's a bit simplistic but it's ok as long as we have only 3
    # partitions
    current = samdb.search(expression="(objectClass=*)",
        base="", scope=ldb.SCOPE_BASE,
        attrs=["defaultNamingContext", "schemaNamingContext",
               "configurationNamingContext","rootDomainNamingContext",
               "namingContexts"])

    names.configdn = current[0]["configurationNamingContext"][0]
    names.schemadn = current[0]["schemaNamingContext"][0]
    if not (ldb.Dn(samdb, basedn) == (ldb.Dn(samdb,
                                       current[0]["defaultNamingContext"][0]))):
        raise ProvisioningError(("basedn in %s (%s) and from %s (%s)"
                                 "is not the same ..." % (paths.samdb,
                                    str(current[0]["defaultNamingContext"][0]),
                                    paths.smbconf, basedn)))

    names.domaindn=current[0]["defaultNamingContext"][0]
    names.rootdn=current[0]["rootDomainNamingContext"][0]
    names.ncs=current[0]["namingContexts"]
    names.dnsforestdn = None
    names.dnsdomaindn = None

    for i in range(0, len(names.ncs)):
        nc = names.ncs[i]

        dnsforestdn = "DC=ForestDnsZones,%s" % (str(names.rootdn))
        if nc == dnsforestdn:
            names.dnsforestdn = dnsforestdn
            continue

        dnsdomaindn = "DC=DomainDnsZones,%s" % (str(names.domaindn))
        if nc == dnsdomaindn:
            names.dnsdomaindn = dnsdomaindn
            continue

    # default site name
    res3 = samdb.search(expression="(objectClass=site)",
        base="CN=Sites," + names.configdn, scope=ldb.SCOPE_ONELEVEL, attrs=["cn"])
    names.sitename = str(res3[0]["cn"])

    # dns hostname and server dn
    res4 = samdb.search(expression="(CN=%s)" % names.netbiosname,
                            base="OU=Domain Controllers,%s" % basedn,
                            scope=ldb.SCOPE_ONELEVEL, attrs=["dNSHostName"])
    names.hostname = str(res4[0]["dNSHostName"]).replace("." + names.dnsdomain, "")

    server_res = samdb.search(expression="serverReference=%s" % res4[0].dn,
                                attrs=[], base=names.configdn)
    names.serverdn = str(server_res[0].dn)

    # invocation id/objectguid
    res5 = samdb.search(expression="(objectClass=*)",
            base="CN=NTDS Settings,%s" % str(names.serverdn),
            scope=ldb.SCOPE_BASE,
            attrs=["invocationID", "objectGUID"])
    names.invocation = str(ndr_unpack(misc.GUID, res5[0]["invocationId"][0]))
    names.ntdsguid = str(ndr_unpack(misc.GUID, res5[0]["objectGUID"][0]))

    # domain guid/sid
    res6 = samdb.search(expression="(objectClass=*)", base=basedn,
            scope=ldb.SCOPE_BASE, attrs=["objectGUID",
                "objectSid","msDS-Behavior-Version" ])
    names.domainguid = str(ndr_unpack(misc.GUID, res6[0]["objectGUID"][0]))
    names.domainsid = ndr_unpack( security.dom_sid, res6[0]["objectSid"][0])
    if res6[0].get("msDS-Behavior-Version") is None or \
        int(res6[0]["msDS-Behavior-Version"][0]) < DS_DOMAIN_FUNCTION_2000:
        names.domainlevel = DS_DOMAIN_FUNCTION_2000
    else:
        names.domainlevel = int(res6[0]["msDS-Behavior-Version"][0])

    # policy guid
    res7 = samdb.search(expression="(displayName=Default Domain Policy)",
                        base="CN=Policies,CN=System," + basedn,
                        scope=ldb.SCOPE_ONELEVEL, attrs=["cn","displayName"])
    names.policyid = str(res7[0]["cn"]).replace("{","").replace("}","")
    # dc policy guid
    res8 = samdb.search(expression="(displayName=Default Domain Controllers"
                                   " Policy)",
                            base="CN=Policies,CN=System," + basedn,
                            scope=ldb.SCOPE_ONELEVEL,
                            attrs=["cn","displayName"])
    if len(res8) == 1:
        names.policyid_dc = str(res8[0]["cn"]).replace("{","").replace("}","")
    else:
        names.policyid_dc = None

    res9 = idmapdb.search(expression="(cn=%s-%s)" %
                          (str(names.domainsid), security.DOMAIN_RID_ADMINISTRATOR),
                          attrs=["xidNumber", "type"])
    if len(res9) != 1:
        raise ProvisioningError("Unable to find uid/gid for Domain Admins rid (%s-%s" % (str(names.domainsid), security.DOMAIN_RID_ADMINISTRATOR))
    if res9[0]["type"][0] == "ID_TYPE_BOTH":
        names.root_gid = res9[0]["xidNumber"][0]
    else:
        names.root_gid = pwd.getpwuid(int(res9[0]["xidNumber"][0])).pw_gid

    res10 = samdb.search(expression="(samaccountname=dns)",
                         scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         controls=["search_options:1:2"])
    if (len(res10) > 0):
        has_legacy_dns_account = True
    else:
        has_legacy_dns_account = False

    res11 = samdb.search(expression="(samaccountname=dns-%s)" % names.netbiosname,
                         scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                         controls=["search_options:1:2"])
    if (len(res11) > 0):
        has_dns_account = True
    else:
        has_dns_account = False

    if names.dnsdomaindn is not None:
        if has_dns_account:
            names.dns_backend = 'BIND9_DLZ'
        else:
            names.dns_backend = 'SAMBA_INTERNAL'
    elif has_dns_account or has_legacy_dns_account:
        names.dns_backend = 'BIND9_FLATFILE'
    else:
        names.dns_backend = 'NONE'

    dns_admins_sid = get_dnsadmins_sid(samdb, names.domaindn)
    names.name_map['DnsAdmins'] = str(dns_admins_sid)

    return names


def update_provision_usn(samdb, low, high, id, replace=False):
    """Update the field provisionUSN in sam.ldb

    This field is used to track range of USN modified by provision and
    upgradeprovision.
    This value is used afterward by next provision to figure out if
    the field have been modified since last provision.

    :param samdb: An LDB object connect to sam.ldb
    :param low: The lowest USN modified by this upgrade
    :param high: The highest USN modified by this upgrade
    :param id: The invocation id of the samba's dc
    :param replace: A boolean indicating if the range should replace any
                    existing one or appended (default)
    """

    tab = []
    if not replace:
        entry = samdb.search(base="@PROVISION",
                             scope=ldb.SCOPE_BASE,
                             attrs=[LAST_PROVISION_USN_ATTRIBUTE, "dn"])
        for e in entry[0][LAST_PROVISION_USN_ATTRIBUTE]:
            if not re.search(';', e):
                e = "%s;%s" % (e, id)
            tab.append(str(e))

    tab.append("%s-%s;%s" % (low, high, id))
    delta = ldb.Message()
    delta.dn = ldb.Dn(samdb, "@PROVISION")
    delta[LAST_PROVISION_USN_ATTRIBUTE] = ldb.MessageElement(tab,
        ldb.FLAG_MOD_REPLACE, LAST_PROVISION_USN_ATTRIBUTE)
    entry = samdb.search(expression='provisionnerID=*',
                         base="@PROVISION", scope=ldb.SCOPE_BASE,
                         attrs=["provisionnerID"])
    if len(entry) == 0 or len(entry[0]) == 0:
        delta["provisionnerID"] = ldb.MessageElement(id, ldb.FLAG_MOD_ADD, "provisionnerID")
    samdb.modify(delta)


def set_provision_usn(samdb, low, high, id):
    """Set the field provisionUSN in sam.ldb
    This field is used to track range of USN modified by provision and
    upgradeprovision.
    This value is used afterward by next provision to figure out if
    the field have been modified since last provision.

    :param samdb: An LDB object connect to sam.ldb
    :param low: The lowest USN modified by this upgrade
    :param high: The highest USN modified by this upgrade
    :param id: The invocationId of the provision"""

    tab = []
    tab.append("%s-%s;%s" % (low, high, id))

    delta = ldb.Message()
    delta.dn = ldb.Dn(samdb, "@PROVISION")
    delta[LAST_PROVISION_USN_ATTRIBUTE] = ldb.MessageElement(tab,
        ldb.FLAG_MOD_ADD, LAST_PROVISION_USN_ATTRIBUTE)
    samdb.add(delta)


def get_max_usn(samdb,basedn):
    """ This function return the biggest USN present in the provision

    :param samdb: A LDB object pointing to the sam.ldb
    :param basedn: A string containing the base DN of the provision
                    (ie. DC=foo, DC=bar)
    :return: The biggest USN in the provision"""

    res = samdb.search(expression="objectClass=*",base=basedn,
                         scope=ldb.SCOPE_SUBTREE,attrs=["uSNChanged"],
                         controls=["search_options:1:2",
                                   "server_sort:1:1:uSNChanged",
                                   "paged_results:1:1"])
    return res[0]["uSNChanged"]


def get_last_provision_usn(sam):
    """Get USNs ranges modified by a provision or an upgradeprovision

    :param sam: An LDB object pointing to the sam.ldb
    :return: a dictionary which keys are invocation id and values are an array
             of integer representing the different ranges
    """
    try:
        entry = sam.search(expression="%s=*" % LAST_PROVISION_USN_ATTRIBUTE,
                       base="@PROVISION", scope=ldb.SCOPE_BASE,
                       attrs=[LAST_PROVISION_USN_ATTRIBUTE, "provisionnerID"])
    except ldb.LdbError, (ecode, emsg):
        if ecode == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise
    if len(entry) > 0:
        myids = []
        range = {}
        p = re.compile(r'-')
        if entry[0].get("provisionnerID"):
            for e in entry[0]["provisionnerID"]:
                myids.append(str(e))
        for r in entry[0][LAST_PROVISION_USN_ATTRIBUTE]:
            tab1 = str(r).split(';')
            if len(tab1) == 2:
                id = tab1[1]
            else:
                id = "default"
            if (len(myids) > 0 and id not in myids):
                continue
            tab2 = p.split(tab1[0])
            if range.get(id) is None:
                range[id] = []
            range[id].append(tab2[0])
            range[id].append(tab2[1])
        return range
    else:
        return None


class ProvisionResult(object):
    """Result of a provision.

    :ivar server_role: The server role
    :ivar paths: ProvisionPaths instance
    :ivar domaindn: The domain dn, as string
    """

    def __init__(self):
        self.server_role = None
        self.paths = None
        self.domaindn = None
        self.lp = None
        self.samdb = None
        self.idmap = None
        self.names = None
        self.domainsid = None
        self.adminpass_generated = None
        self.adminpass = None
        self.backend_result = None

    def report_logger(self, logger):
        """Report this provision result to a logger."""
        logger.info(
            "Once the above files are installed, your Samba4 server will "
            "be ready to use")
        if self.adminpass_generated:
            logger.info("Admin password:        %s", self.adminpass)
        logger.info("Server Role:           %s", self.server_role)
        logger.info("Hostname:              %s", self.names.hostname)
        logger.info("NetBIOS Domain:        %s", self.names.domain)
        logger.info("DNS Domain:            %s", self.names.dnsdomain)
        logger.info("DOMAIN SID:            %s", self.domainsid)

        if self.backend_result:
            self.backend_result.report_logger(logger)


def check_install(lp, session_info, credentials):
    """Check whether the current install seems ok.

    :param lp: Loadparm context
    :param session_info: Session information
    :param credentials: Credentials
    """
    if lp.get("realm") == "":
        raise Exception("Realm empty")
    samdb = Ldb(lp.samdb_url(), session_info=session_info,
            credentials=credentials, lp=lp)
    if len(samdb.search("(cn=Administrator)")) != 1:
        raise ProvisioningError("No administrator account found")


def findnss(nssfn, names):
    """Find a user or group from a list of possibilities.

    :param nssfn: NSS Function to try (should raise KeyError if not found)
    :param names: Names to check.
    :return: Value return by first names list.
    """
    for name in names:
        try:
            return nssfn(name)
        except KeyError:
            pass
    raise KeyError("Unable to find user/group in %r" % names)


findnss_uid = lambda names: findnss(pwd.getpwnam, names)[2]
findnss_gid = lambda names: findnss(grp.getgrnam, names)[2]


def provision_paths_from_lp(lp, dnsdomain):
    """Set the default paths for provisioning.

    :param lp: Loadparm context.
    :param dnsdomain: DNS Domain name
    """
    paths = ProvisionPaths()
    paths.private_dir = lp.get("private dir")
    paths.state_dir = lp.get("state directory")

    # This is stored without path prefix for the "privateKeytab" attribute in
    # "secrets_dns.ldif".
    paths.dns_keytab = "dns.keytab"
    paths.keytab = "secrets.keytab"

    paths.shareconf = os.path.join(paths.private_dir, "share.ldb")
    paths.samdb = os.path.join(paths.private_dir, "sam.ldb")
    paths.idmapdb = os.path.join(paths.private_dir, "idmap.ldb")
    paths.secrets = os.path.join(paths.private_dir, "secrets.ldb")
    paths.privilege = os.path.join(paths.private_dir, "privilege.ldb")
    paths.dns = os.path.join(paths.private_dir, "dns", dnsdomain + ".zone")
    paths.dns_update_list = os.path.join(paths.private_dir, "dns_update_list")
    paths.spn_update_list = os.path.join(paths.private_dir, "spn_update_list")
    paths.namedconf = os.path.join(paths.private_dir, "named.conf")
    paths.namedconf_update = os.path.join(paths.private_dir, "named.conf.update")
    paths.namedtxt = os.path.join(paths.private_dir, "named.txt")
    paths.krb5conf = os.path.join(paths.private_dir, "krb5.conf")
    paths.winsdb = os.path.join(paths.private_dir, "wins.ldb")
    paths.s4_ldapi_path = os.path.join(paths.private_dir, "ldapi")
    paths.hklm = "hklm.ldb"
    paths.hkcr = "hkcr.ldb"
    paths.hkcu = "hkcu.ldb"
    paths.hku = "hku.ldb"
    paths.hkpd = "hkpd.ldb"
    paths.hkpt = "hkpt.ldb"
    paths.sysvol = lp.get("path", "sysvol")
    paths.netlogon = lp.get("path", "netlogon")
    paths.smbconf = lp.configfile
    return paths


def determine_netbios_name(hostname):
    """Determine a netbios name from a hostname."""
    # remove forbidden chars and force the length to be <16
    netbiosname = "".join([x for x in hostname if is_valid_netbios_char(x)])
    return netbiosname[:MAX_NETBIOS_NAME_LEN].upper()


def guess_names(lp=None, hostname=None, domain=None, dnsdomain=None,
                serverrole=None, rootdn=None, domaindn=None, configdn=None,
                schemadn=None, serverdn=None, sitename=None,
                domain_names_forced=False):
    """Guess configuration settings to use."""

    if hostname is None:
        hostname = socket.gethostname().split(".")[0]

    netbiosname = lp.get("netbios name")
    if netbiosname is None:
        netbiosname = determine_netbios_name(hostname)
    netbiosname = netbiosname.upper()
    if not valid_netbios_name(netbiosname):
        raise InvalidNetbiosName(netbiosname)

    if dnsdomain is None:
        dnsdomain = lp.get("realm")
        if dnsdomain is None or dnsdomain == "":
            raise ProvisioningError("guess_names: 'realm' not specified in supplied %s!", lp.configfile)

    dnsdomain = dnsdomain.lower()

    if serverrole is None:
        serverrole = lp.get("server role")
        if serverrole is None:
            raise ProvisioningError("guess_names: 'server role' not specified in supplied %s!" % lp.configfile)

    serverrole = serverrole.lower()

    realm = dnsdomain.upper()

    if lp.get("realm") == "":
        raise ProvisioningError("guess_names: 'realm =' was not specified in supplied %s.  Please remove the smb.conf file and let provision generate it" % lp.configfile)

    if lp.get("realm").upper() != realm:
        raise ProvisioningError("guess_names: 'realm=%s' in %s must match chosen realm '%s'!  Please remove the smb.conf file and let provision generate it" % (lp.get("realm").upper(), realm, lp.configfile))

    if lp.get("server role").lower() != serverrole:
        raise ProvisioningError("guess_names: 'server role=%s' in %s must match chosen server role '%s'!  Please remove the smb.conf file and let provision generate it" % (lp.get("server role"), lp.configfile, serverrole))

    if serverrole == "active directory domain controller":
        if domain is None:
            # This will, for better or worse, default to 'WORKGROUP'
            domain = lp.get("workgroup")
        domain = domain.upper()

        if lp.get("workgroup").upper() != domain:
            raise ProvisioningError("guess_names: Workgroup '%s' in smb.conf must match chosen domain '%s'!  Please remove the %s file and let provision generate it" % (lp.get("workgroup").upper(), domain, lp.configfile))

        if domaindn is None:
            domaindn = samba.dn_from_dns_name(dnsdomain)

        if domain == netbiosname:
            raise ProvisioningError("guess_names: Domain '%s' must not be equal to short host name '%s'!" % (domain, netbiosname))
    else:
        domain = netbiosname
        if domaindn is None:
            domaindn = "DC=" + netbiosname

    if not valid_netbios_name(domain):
        raise InvalidNetbiosName(domain)

    if hostname.upper() == realm:
        raise ProvisioningError("guess_names: Realm '%s' must not be equal to hostname '%s'!" % (realm, hostname))
    if netbiosname.upper() == realm:
        raise ProvisioningError("guess_names: Realm '%s' must not be equal to NetBIOS hostname '%s'!" % (realm, netbiosname))
    if domain == realm and not domain_names_forced:
        raise ProvisioningError("guess_names: Realm '%s' must not be equal to short domain name '%s'!" % (realm, domain))

    if rootdn is None:
       rootdn = domaindn

    if configdn is None:
        configdn = "CN=Configuration," + rootdn
    if schemadn is None:
        schemadn = "CN=Schema," + configdn

    if sitename is None:
        sitename = DEFAULTSITE

    names = ProvisionNames()
    names.rootdn = rootdn
    names.domaindn = domaindn
    names.configdn = configdn
    names.schemadn = schemadn
    names.ldapmanagerdn = "CN=Manager," + rootdn
    names.dnsdomain = dnsdomain
    names.domain = domain
    names.realm = realm
    names.netbiosname = netbiosname
    names.hostname = hostname
    names.sitename = sitename
    names.serverdn = "CN=%s,CN=Servers,CN=%s,CN=Sites,%s" % (
        netbiosname, sitename, configdn)

    return names


def make_smbconf(smbconf, hostname, domain, realm, targetdir,
                 serverrole=None, eadb=False, use_ntvfs=False, lp=None,
                 global_param=None):
    """Create a new smb.conf file based on a couple of basic settings.
    """
    assert smbconf is not None

    if hostname is None:
        hostname = socket.gethostname().split(".")[0]

    netbiosname = determine_netbios_name(hostname)

    if serverrole is None:
        serverrole = "standalone server"

    assert domain is not None
    domain = domain.upper()

    assert realm is not None
    realm = realm.upper()

    global_settings = {
        "netbios name": netbiosname,
        "workgroup": domain,
        "realm": realm,
        "server role": serverrole,
        }

    if lp is None:
        lp = samba.param.LoadParm()
    #Load non-existent file
    if os.path.exists(smbconf):
        lp.load(smbconf)

    if global_param is not None:
        for ent in global_param:
            if global_param[ent] is not None:
                global_settings[ent] = " ".join(global_param[ent])

    if targetdir is not None:
        global_settings["private dir"] = os.path.abspath(os.path.join(targetdir, "private"))
        global_settings["lock dir"] = os.path.abspath(targetdir)
        global_settings["state directory"] = os.path.abspath(os.path.join(targetdir, "state"))
        global_settings["cache directory"] = os.path.abspath(os.path.join(targetdir, "cache"))

        lp.set("lock dir", os.path.abspath(targetdir))
        lp.set("state directory",  global_settings["state directory"])
        lp.set("cache directory", global_settings["cache directory"])

    if eadb:
        if use_ntvfs and not lp.get("posix:eadb"):
            if targetdir is not None:
                privdir = os.path.join(targetdir, "private")
            else:
                privdir = lp.get("private dir")
            lp.set("posix:eadb", os.path.abspath(os.path.join(privdir, "eadb.tdb")))
        elif not use_ntvfs and not lp.get("xattr_tdb:file"):
            if targetdir is not None:
                statedir = os.path.join(targetdir, "state")
            else:
                statedir = lp.get("state directory")
            lp.set("xattr_tdb:file", os.path.abspath(os.path.join(statedir, "xattr.tdb")))

    shares = {}
    if serverrole == "active directory domain controller":
        shares["sysvol"] = os.path.join(lp.get("state directory"), "sysvol")
        shares["netlogon"] = os.path.join(shares["sysvol"], realm.lower(),
            "scripts")
    else:
        global_settings["passdb backend"] = "samba_dsdb"

    f = open(smbconf, 'w')
    try:
        f.write("[globals]\n")
        for key, val in global_settings.iteritems():
            f.write("\t%s = %s\n" % (key, val))
        f.write("\n")

        for name, path in shares.iteritems():
            f.write("[%s]\n" % name)
            f.write("\tpath = %s\n" % path)
            f.write("\tread only = no\n")
            f.write("\n")
    finally:
        f.close()
    # reload the smb.conf
    lp.load(smbconf)

    # and dump it without any values that are the default
    # this ensures that any smb.conf parameters that were set
    # on the provision/join command line are set in the resulting smb.conf
    f = open(smbconf, mode='w')
    try:
        lp.dump(f, False)
    finally:
        f.close()


def setup_name_mappings(idmap, sid, root_uid, nobody_uid,
                        users_gid, root_gid):
    """setup reasonable name mappings for sam names to unix names.

    :param samdb: SamDB object.
    :param idmap: IDmap db object.
    :param sid: The domain sid.
    :param domaindn: The domain DN.
    :param root_uid: uid of the UNIX root user.
    :param nobody_uid: uid of the UNIX nobody user.
    :param users_gid: gid of the UNIX users group.
    :param root_gid: gid of the UNIX root group.
    """
    idmap.setup_name_mapping("S-1-5-7", idmap.TYPE_UID, nobody_uid)

    idmap.setup_name_mapping(sid + "-500", idmap.TYPE_UID, root_uid)
    idmap.setup_name_mapping(sid + "-513", idmap.TYPE_GID, users_gid)


def setup_samdb_partitions(samdb_path, logger, lp, session_info,
                           provision_backend, names, schema, serverrole,
                           erase=False):
    """Setup the partitions for the SAM database.

    Alternatively, provision() may call this, and then populate the database.

    :note: This will wipe the Sam Database!

    :note: This function always removes the local SAM LDB file. The erase
        parameter controls whether to erase the existing data, which
        may not be stored locally but in LDAP.

    """
    assert session_info is not None

    # We use options=["modules:"] to stop the modules loading - we
    # just want to wipe and re-initialise the database, not start it up

    try:
        os.unlink(samdb_path)
    except OSError:
        pass

    samdb = Ldb(url=samdb_path, session_info=session_info,
                lp=lp, options=["modules:"])

    ldap_backend_line = "# No LDAP backend"
    if provision_backend.type != "ldb":
        ldap_backend_line = "ldapBackend: %s" % provision_backend.ldap_uri

    samdb.transaction_start()
    try:
        logger.info("Setting up sam.ldb partitions and settings")
        setup_add_ldif(samdb, setup_path("provision_partitions.ldif"), {
                "LDAP_BACKEND_LINE": ldap_backend_line
        })


        setup_add_ldif(samdb, setup_path("provision_init.ldif"), {
                "BACKEND_TYPE": provision_backend.type,
                "SERVER_ROLE": serverrole
                })

        logger.info("Setting up sam.ldb rootDSE")
        setup_samdb_rootdse(samdb, names)
    except:
        samdb.transaction_cancel()
        raise
    else:
        samdb.transaction_commit()


def secretsdb_self_join(secretsdb, domain,
                        netbiosname, machinepass, domainsid=None,
                        realm=None, dnsdomain=None,
                        keytab_path=None,
                        key_version_number=1,
                        secure_channel_type=SEC_CHAN_WKSTA):
    """Add domain join-specific bits to a secrets database.

    :param secretsdb: Ldb Handle to the secrets database
    :param machinepass: Machine password
    """
    attrs = ["whenChanged",
           "secret",
           "priorSecret",
           "priorChanged",
           "krb5Keytab",
           "privateKeytab"]

    if realm is not None:
        if dnsdomain is None:
            dnsdomain = realm.lower()
        dnsname = '%s.%s' % (netbiosname.lower(), dnsdomain.lower())
    else:
        dnsname = None
    shortname = netbiosname.lower()

    # We don't need to set msg["flatname"] here, because rdn_name will handle
    # it, and it causes problems for modifies anyway
    msg = ldb.Message(ldb.Dn(secretsdb, "flatname=%s,cn=Primary Domains" % domain))
    msg["secureChannelType"] = [str(secure_channel_type)]
    msg["objectClass"] = ["top", "primaryDomain"]
    if dnsname is not None:
        msg["objectClass"] = ["top", "primaryDomain", "kerberosSecret"]
        msg["realm"] = [realm]
        msg["saltPrincipal"] = ["host/%s@%s" % (dnsname, realm.upper())]
        msg["msDS-KeyVersionNumber"] = [str(key_version_number)]
        msg["privateKeytab"] = ["secrets.keytab"]

    msg["secret"] = [machinepass]
    msg["samAccountName"] = ["%s$" % netbiosname]
    msg["secureChannelType"] = [str(secure_channel_type)]
    if domainsid is not None:
        msg["objectSid"] = [ndr_pack(domainsid)]

    # This complex expression tries to ensure that we don't have more
    # than one record for this SID, realm or netbios domain at a time,
    # but we don't delete the old record that we are about to modify,
    # because that would delete the keytab and previous password.
    res = secretsdb.search(base="cn=Primary Domains", attrs=attrs,
        expression=("(&(|(flatname=%s)(realm=%s)(objectSid=%s))(objectclass=primaryDomain)(!(distinguishedName=%s)))" % (domain, realm, str(domainsid), str(msg.dn))),
        scope=ldb.SCOPE_ONELEVEL)

    for del_msg in res:
        secretsdb.delete(del_msg.dn)

    res = secretsdb.search(base=msg.dn, attrs=attrs, scope=ldb.SCOPE_BASE)

    if len(res) == 1:
        msg["priorSecret"] = [res[0]["secret"][0]]
        msg["priorWhenChanged"] = [res[0]["whenChanged"][0]]

        try:
            msg["privateKeytab"] = [res[0]["privateKeytab"][0]]
        except KeyError:
            pass

        try:
            msg["krb5Keytab"] = [res[0]["krb5Keytab"][0]]
        except KeyError:
            pass

        for el in msg:
            if el != 'dn':
                msg[el].set_flags(ldb.FLAG_MOD_REPLACE)
        secretsdb.modify(msg)
        secretsdb.rename(res[0].dn, msg.dn)
    else:
        spn = [ 'HOST/%s' % shortname ]
        if secure_channel_type == SEC_CHAN_BDC and dnsname is not None:
            # we are a domain controller then we add servicePrincipalName
            # entries for the keytab code to update.
            spn.extend([ 'HOST/%s' % dnsname ])
        msg["servicePrincipalName"] = spn

        secretsdb.add(msg)


def setup_secretsdb(paths, session_info, backend_credentials, lp):
    """Setup the secrets database.

   :note: This function does not handle exceptions and transaction on purpose,
       it's up to the caller to do this job.

    :param path: Path to the secrets database.
    :param session_info: Session info.
    :param credentials: Credentials
    :param lp: Loadparm context
    :return: LDB handle for the created secrets database
    """
    if os.path.exists(paths.secrets):
        os.unlink(paths.secrets)

    keytab_path = os.path.join(paths.private_dir, paths.keytab)
    if os.path.exists(keytab_path):
        os.unlink(keytab_path)

    dns_keytab_path = os.path.join(paths.private_dir, paths.dns_keytab)
    if os.path.exists(dns_keytab_path):
        os.unlink(dns_keytab_path)

    path = paths.secrets

    secrets_ldb = Ldb(path, session_info=session_info, lp=lp)
    secrets_ldb.erase()
    secrets_ldb.load_ldif_file_add(setup_path("secrets_init.ldif"))
    secrets_ldb = Ldb(path, session_info=session_info, lp=lp)
    secrets_ldb.transaction_start()
    try:
        secrets_ldb.load_ldif_file_add(setup_path("secrets.ldif"))

        if (backend_credentials is not None and
            backend_credentials.authentication_requested()):
            if backend_credentials.get_bind_dn() is not None:
                setup_add_ldif(secrets_ldb,
                    setup_path("secrets_simple_ldap.ldif"), {
                        "LDAPMANAGERDN": backend_credentials.get_bind_dn(),
                        "LDAPMANAGERPASS_B64": b64encode(backend_credentials.get_password())
                        })
            else:
                setup_add_ldif(secrets_ldb,
                    setup_path("secrets_sasl_ldap.ldif"), {
                        "LDAPADMINUSER": backend_credentials.get_username(),
                        "LDAPADMINREALM": backend_credentials.get_realm(),
                        "LDAPADMINPASS_B64": b64encode(backend_credentials.get_password())
                        })
    except:
        secrets_ldb.transaction_cancel()
        raise
    return secrets_ldb


def setup_privileges(path, session_info, lp):
    """Setup the privileges database.

    :param path: Path to the privileges database.
    :param session_info: Session info.
    :param credentials: Credentials
    :param lp: Loadparm context
    :return: LDB handle for the created secrets database
    """
    if os.path.exists(path):
        os.unlink(path)
    privilege_ldb = Ldb(path, session_info=session_info, lp=lp)
    privilege_ldb.erase()
    privilege_ldb.load_ldif_file_add(setup_path("provision_privilege.ldif"))


def setup_registry(path, session_info, lp):
    """Setup the registry.

    :param path: Path to the registry database
    :param session_info: Session information
    :param credentials: Credentials
    :param lp: Loadparm context
    """
    reg = samba.registry.Registry()
    hive = samba.registry.open_ldb(path, session_info=session_info, lp_ctx=lp)
    reg.mount_hive(hive, samba.registry.HKEY_LOCAL_MACHINE)
    provision_reg = setup_path("provision.reg")
    assert os.path.exists(provision_reg)
    reg.diff_apply(provision_reg)


def setup_idmapdb(path, session_info, lp):
    """Setup the idmap database.

    :param path: path to the idmap database
    :param session_info: Session information
    :param credentials: Credentials
    :param lp: Loadparm context
    """
    if os.path.exists(path):
        os.unlink(path)

    idmap_ldb = IDmapDB(path, session_info=session_info, lp=lp)
    idmap_ldb.erase()
    idmap_ldb.load_ldif_file_add(setup_path("idmap_init.ldif"))
    return idmap_ldb


def setup_samdb_rootdse(samdb, names):
    """Setup the SamDB rootdse.

    :param samdb: Sam Database handle
    """
    setup_add_ldif(samdb, setup_path("provision_rootdse_add.ldif"), {
        "SCHEMADN": names.schemadn,
        "DOMAINDN": names.domaindn,
        "ROOTDN"  : names.rootdn,
        "CONFIGDN": names.configdn,
        "SERVERDN": names.serverdn,
        })


def setup_self_join(samdb, admin_session_info, names, fill, machinepass,
        dns_backend, dnspass, domainsid, next_rid, invocationid,
        policyguid, policyguid_dc,
        domainControllerFunctionality, ntdsguid=None, dc_rid=None):
    """Join a host to its own domain."""
    assert isinstance(invocationid, str)
    if ntdsguid is not None:
        ntdsguid_line = "objectGUID: %s\n"%ntdsguid
    else:
        ntdsguid_line = ""

    if dc_rid is None:
        dc_rid = next_rid

    setup_add_ldif(samdb, setup_path("provision_self_join.ldif"), {
              "CONFIGDN": names.configdn,
              "SCHEMADN": names.schemadn,
              "DOMAINDN": names.domaindn,
              "SERVERDN": names.serverdn,
              "INVOCATIONID": invocationid,
              "NETBIOSNAME": names.netbiosname,
              "DNSNAME": "%s.%s" % (names.hostname, names.dnsdomain),
              "MACHINEPASS_B64": b64encode(machinepass.encode('utf-16-le')),
              "DOMAINSID": str(domainsid),
              "DCRID": str(dc_rid),
              "SAMBA_VERSION_STRING": version,
              "NTDSGUID": ntdsguid_line,
              "DOMAIN_CONTROLLER_FUNCTIONALITY": str(
                  domainControllerFunctionality),
              "RIDALLOCATIONSTART": str(next_rid + 100),
              "RIDALLOCATIONEND": str(next_rid + 100 + 499)})

    setup_add_ldif(samdb, setup_path("provision_group_policy.ldif"), {
              "POLICYGUID": policyguid,
              "POLICYGUID_DC": policyguid_dc,
              "DNSDOMAIN": names.dnsdomain,
              "DOMAINDN": names.domaindn})

    # If we are setting up a subdomain, then this has been replicated in, so we
    # don't need to add it
    if fill == FILL_FULL:
        setup_add_ldif(samdb, setup_path("provision_self_join_config.ldif"), {
                "CONFIGDN": names.configdn,
                "SCHEMADN": names.schemadn,
                "DOMAINDN": names.domaindn,
                "SERVERDN": names.serverdn,
                "INVOCATIONID": invocationid,
                "NETBIOSNAME": names.netbiosname,
                "DNSNAME": "%s.%s" % (names.hostname, names.dnsdomain),
                "MACHINEPASS_B64": b64encode(machinepass.encode('utf-16-le')),
                "DOMAINSID": str(domainsid),
                "DCRID": str(dc_rid),
                "SAMBA_VERSION_STRING": version,
                "NTDSGUID": ntdsguid_line,
                "DOMAIN_CONTROLLER_FUNCTIONALITY": str(
                    domainControllerFunctionality)})

    # Setup fSMORoleOwner entries to point at the newly created DC entry
        setup_modify_ldif(samdb,
            setup_path("provision_self_join_modify_config.ldif"), {
                "CONFIGDN": names.configdn,
                "SCHEMADN": names.schemadn,
                "DEFAULTSITE": names.sitename,
                "NETBIOSNAME": names.netbiosname,
                "SERVERDN": names.serverdn,
                })

    system_session_info = system_session()
    samdb.set_session_info(system_session_info)
    # Setup fSMORoleOwner entries to point at the newly created DC entry to
    # modify a serverReference under cn=config when we are a subdomain, we must
    # be system due to ACLs
    setup_modify_ldif(samdb, setup_path("provision_self_join_modify.ldif"), {
              "DOMAINDN": names.domaindn,
              "SERVERDN": names.serverdn,
              "NETBIOSNAME": names.netbiosname,
              })

    samdb.set_session_info(admin_session_info)

    if dns_backend != "SAMBA_INTERNAL":
        # This is Samba4 specific and should be replaced by the correct
        # DNS AD-style setup
        setup_add_ldif(samdb, setup_path("provision_dns_add_samba.ldif"), {
              "DNSDOMAIN": names.dnsdomain,
              "DOMAINDN": names.domaindn,
              "DNSPASS_B64": b64encode(dnspass.encode('utf-16-le')),
              "HOSTNAME" : names.hostname,
              "DNSNAME" : '%s.%s' % (
                  names.netbiosname.lower(), names.dnsdomain.lower())
              })


def getpolicypath(sysvolpath, dnsdomain, guid):
    """Return the physical path of policy given its guid.

    :param sysvolpath: Path to the sysvol folder
    :param dnsdomain: DNS name of the AD domain
    :param guid: The GUID of the policy
    :return: A string with the complete path to the policy folder
    """
    if guid[0] != "{":
        guid = "{%s}" % guid
    policy_path = os.path.join(sysvolpath, dnsdomain, "Policies", guid)
    return policy_path


def create_gpo_struct(policy_path):
    if not os.path.exists(policy_path):
        os.makedirs(policy_path, 0775)
    f = open(os.path.join(policy_path, "GPT.INI"), 'w')
    try:
        f.write("[General]\r\nVersion=0")
    finally:
        f.close()
    p = os.path.join(policy_path, "MACHINE")
    if not os.path.exists(p):
        os.makedirs(p, 0775)
    p = os.path.join(policy_path, "USER")
    if not os.path.exists(p):
        os.makedirs(p, 0775)


def create_default_gpo(sysvolpath, dnsdomain, policyguid, policyguid_dc):
    """Create the default GPO for a domain

    :param sysvolpath: Physical path for the sysvol folder
    :param dnsdomain: DNS domain name of the AD domain
    :param policyguid: GUID of the default domain policy
    :param policyguid_dc: GUID of the default domain controler policy
    """
    policy_path = getpolicypath(sysvolpath,dnsdomain,policyguid)
    create_gpo_struct(policy_path)

    policy_path = getpolicypath(sysvolpath,dnsdomain,policyguid_dc)
    create_gpo_struct(policy_path)


def setup_samdb(path, session_info, provision_backend, lp, names,
        logger, fill, serverrole, schema, am_rodc=False):
    """Setup a complete SAM Database.

    :note: This will wipe the main SAM database file!
    """

    # Also wipes the database
    setup_samdb_partitions(path, logger=logger, lp=lp,
        provision_backend=provision_backend, session_info=session_info,
        names=names, serverrole=serverrole, schema=schema)

    # Load the database, but don's load the global schema and don't connect
    # quite yet
    samdb = SamDB(session_info=session_info, url=None, auto_connect=False,
                  credentials=provision_backend.credentials, lp=lp,
                  global_schema=False, am_rodc=am_rodc)

    logger.info("Pre-loading the Samba 4 and AD schema")

    # Load the schema from the one we computed earlier
    samdb.set_schema(schema, write_indices_and_attributes=False)

    # Set the NTDS settings DN manually - in order to have it already around
    # before the provisioned tree exists and we connect
    samdb.set_ntds_settings_dn("CN=NTDS Settings,%s" % names.serverdn)

    # And now we can connect to the DB - the schema won't be loaded from the
    # DB
    samdb.connect(path)

    # But we have to give it one more kick to have it use the schema
    # during provision - it needs, now that it is connected, to write
    # the schema @ATTRIBUTES and @INDEXLIST records to the database.
    samdb.set_schema(schema, write_indices_and_attributes=True)

    return samdb


def fill_samdb(samdb, lp, names, logger, domainsid, domainguid, policyguid,
        policyguid_dc, fill, adminpass, krbtgtpass, machinepass, dns_backend,
        dnspass, invocationid, ntdsguid, serverrole, am_rodc=False,
        dom_for_fun_level=None, schema=None, next_rid=None, dc_rid=None):

    if next_rid is None:
        next_rid = 1000

    # Provision does not make much sense values larger than 1000000000
    # as the upper range of the rIDAvailablePool is 1073741823 and
    # we don't want to create a domain that cannot allocate rids.
    if next_rid < 1000 or next_rid > 1000000000:
        error = "You want to run SAMBA 4 with a next_rid of %u, " % (next_rid)
        error += "the valid range is %u-%u. The default is %u." % (
            1000, 1000000000, 1000)
        raise ProvisioningError(error)

    # ATTENTION: Do NOT change these default values without discussion with the
    # team and/or release manager. They have a big impact on the whole program!
    domainControllerFunctionality = DS_DOMAIN_FUNCTION_2008_R2

    if dom_for_fun_level is None:
        dom_for_fun_level = DS_DOMAIN_FUNCTION_2003

    if dom_for_fun_level > domainControllerFunctionality:
        raise ProvisioningError("You want to run SAMBA 4 on a domain and forest function level which itself is higher than its actual DC function level (2008_R2). This won't work!")

    domainFunctionality = dom_for_fun_level
    forestFunctionality = dom_for_fun_level

    # Set the NTDS settings DN manually - in order to have it already around
    # before the provisioned tree exists and we connect
    samdb.set_ntds_settings_dn("CN=NTDS Settings,%s" % names.serverdn)

    samdb.transaction_start()
    try:
        # Set the domain functionality levels onto the database.
        # Various module (the password_hash module in particular) need
        # to know what level of AD we are emulating.

        # These will be fixed into the database via the database
        # modifictions below, but we need them set from the start.
        samdb.set_opaque_integer("domainFunctionality", domainFunctionality)
        samdb.set_opaque_integer("forestFunctionality", forestFunctionality)
        samdb.set_opaque_integer("domainControllerFunctionality",
            domainControllerFunctionality)

        samdb.set_domain_sid(str(domainsid))
        samdb.set_invocation_id(invocationid)

        logger.info("Adding DomainDN: %s" % names.domaindn)

        # impersonate domain admin
        admin_session_info = admin_session(lp, str(domainsid))
        samdb.set_session_info(admin_session_info)
        if domainguid is not None:
            domainguid_line = "objectGUID: %s\n-" % domainguid
        else:
            domainguid_line = ""

        descr = b64encode(get_domain_descriptor(domainsid))
        setup_add_ldif(samdb, setup_path("provision_basedn.ldif"), {
                "DOMAINDN": names.domaindn,
                "DOMAINSID": str(domainsid),
                "DESCRIPTOR": descr,
                "DOMAINGUID": domainguid_line
                })

        setup_modify_ldif(samdb, setup_path("provision_basedn_modify.ldif"), {
            "DOMAINDN": names.domaindn,
            "CREATTIME": str(samba.unix2nttime(int(time.time()))),
            "NEXTRID": str(next_rid),
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "POLICYGUID": policyguid,
            "DOMAIN_FUNCTIONALITY": str(domainFunctionality),
            "SAMBA_VERSION_STRING": version
            })

        # If we are setting up a subdomain, then this has been replicated in, so we don't need to add it
        if fill == FILL_FULL:
            logger.info("Adding configuration container")
            descr = b64encode(get_config_descriptor(domainsid))
            setup_add_ldif(samdb, setup_path("provision_configuration_basedn.ldif"), {
                    "CONFIGDN": names.configdn,
                    "DESCRIPTOR": descr,
                    })

            # The LDIF here was created when the Schema object was constructed
            logger.info("Setting up sam.ldb schema")
            samdb.add_ldif(schema.schema_dn_add, controls=["relax:0"])
            samdb.modify_ldif(schema.schema_dn_modify)
            samdb.write_prefixes_from_schema()
            samdb.add_ldif(schema.schema_data, controls=["relax:0"])
            setup_add_ldif(samdb, setup_path("aggregate_schema.ldif"),
                           {"SCHEMADN": names.schemadn})

        # Now register this container in the root of the forest
        msg = ldb.Message(ldb.Dn(samdb, names.domaindn))
        msg["subRefs"] = ldb.MessageElement(names.configdn , ldb.FLAG_MOD_ADD,
                    "subRefs")

    except:
        samdb.transaction_cancel()
        raise
    else:
        samdb.transaction_commit()

    samdb.transaction_start()
    try:
        samdb.invocation_id = invocationid

        # If we are setting up a subdomain, then this has been replicated in, so we don't need to add it
        if fill == FILL_FULL:
            logger.info("Setting up sam.ldb configuration data")

            partitions_descr = b64encode(get_config_partitions_descriptor(domainsid))
            sites_descr = b64encode(get_config_sites_descriptor(domainsid))
            ntdsquotas_descr = b64encode(get_config_ntds_quotas_descriptor(domainsid))
            protected1_descr = b64encode(get_config_delete_protected1_descriptor(domainsid))
            protected1wd_descr = b64encode(get_config_delete_protected1wd_descriptor(domainsid))
            protected2_descr = b64encode(get_config_delete_protected2_descriptor(domainsid))

            setup_add_ldif(samdb, setup_path("provision_configuration.ldif"), {
                    "CONFIGDN": names.configdn,
                    "NETBIOSNAME": names.netbiosname,
                    "DEFAULTSITE": names.sitename,
                    "DNSDOMAIN": names.dnsdomain,
                    "DOMAIN": names.domain,
                    "SCHEMADN": names.schemadn,
                    "DOMAINDN": names.domaindn,
                    "SERVERDN": names.serverdn,
                    "FOREST_FUNCTIONALITY": str(forestFunctionality),
                    "DOMAIN_FUNCTIONALITY": str(domainFunctionality),
                    "NTDSQUOTAS_DESCRIPTOR": ntdsquotas_descr,
                    "LOSTANDFOUND_DESCRIPTOR": protected1wd_descr,
                    "SERVICES_DESCRIPTOR": protected1_descr,
                    "PHYSICALLOCATIONS_DESCRIPTOR": protected1wd_descr,
                    "FORESTUPDATES_DESCRIPTOR": protected1wd_descr,
                    "EXTENDEDRIGHTS_DESCRIPTOR": protected2_descr,
                    "PARTITIONS_DESCRIPTOR": partitions_descr,
                    "SITES_DESCRIPTOR": sites_descr,
                    })

            logger.info("Setting up display specifiers")
            display_specifiers_ldif = read_ms_ldif(
                setup_path('display-specifiers/DisplaySpecifiers-Win2k8R2.txt'))
            display_specifiers_ldif = substitute_var(display_specifiers_ldif,
                                                     {"CONFIGDN": names.configdn})
            check_all_substituted(display_specifiers_ldif)
            samdb.add_ldif(display_specifiers_ldif)

            logger.info("Modifying display specifiers")
            setup_modify_ldif(samdb,
                setup_path("provision_configuration_modify.ldif"), {
                "CONFIGDN": names.configdn,
                "DISPLAYSPECIFIERS_DESCRIPTOR": protected2_descr
                })

        logger.info("Adding users container")
        users_desc = b64encode(get_domain_users_descriptor(domainsid))
        setup_add_ldif(samdb, setup_path("provision_users_add.ldif"), {
                "DOMAINDN": names.domaindn,
                "USERS_DESCRIPTOR": users_desc
                })
        logger.info("Modifying users container")
        setup_modify_ldif(samdb, setup_path("provision_users_modify.ldif"), {
                "DOMAINDN": names.domaindn})
        logger.info("Adding computers container")
        computers_desc = b64encode(get_domain_computers_descriptor(domainsid))
        setup_add_ldif(samdb, setup_path("provision_computers_add.ldif"), {
                "DOMAINDN": names.domaindn,
                "COMPUTERS_DESCRIPTOR": computers_desc
                })
        logger.info("Modifying computers container")
        setup_modify_ldif(samdb,
            setup_path("provision_computers_modify.ldif"), {
                "DOMAINDN": names.domaindn})
        logger.info("Setting up sam.ldb data")
        infrastructure_desc = b64encode(get_domain_infrastructure_descriptor(domainsid))
        lostandfound_desc = b64encode(get_domain_delete_protected2_descriptor(domainsid))
        system_desc = b64encode(get_domain_delete_protected1_descriptor(domainsid))
        builtin_desc = b64encode(get_domain_builtin_descriptor(domainsid))
        controllers_desc = b64encode(get_domain_controllers_descriptor(domainsid))
        setup_add_ldif(samdb, setup_path("provision.ldif"), {
            "CREATTIME": str(samba.unix2nttime(int(time.time()))),
            "DOMAINDN": names.domaindn,
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "SERVERDN": names.serverdn,
            "RIDAVAILABLESTART": str(next_rid + 600),
            "POLICYGUID_DC": policyguid_dc,
            "INFRASTRUCTURE_DESCRIPTOR": infrastructure_desc,
            "LOSTANDFOUND_DESCRIPTOR": lostandfound_desc,
            "SYSTEM_DESCRIPTOR": system_desc,
            "BUILTIN_DESCRIPTOR": builtin_desc,
            "DOMAIN_CONTROLLERS_DESCRIPTOR": controllers_desc,
            })

        # If we are setting up a subdomain, then this has been replicated in, so we don't need to add it
        if fill == FILL_FULL:
            setup_modify_ldif(samdb,
                              setup_path("provision_configuration_references.ldif"), {
                    "CONFIGDN": names.configdn,
                    "SCHEMADN": names.schemadn})

            logger.info("Setting up well known security principals")
            protected1wd_descr = b64encode(get_config_delete_protected1wd_descriptor(domainsid))
            setup_add_ldif(samdb, setup_path("provision_well_known_sec_princ.ldif"), {
                "CONFIGDN": names.configdn,
                "WELLKNOWNPRINCIPALS_DESCRIPTOR": protected1wd_descr,
                })

        if fill == FILL_FULL or fill == FILL_SUBDOMAIN:
            setup_modify_ldif(samdb,
                              setup_path("provision_basedn_references.ldif"),
                              {"DOMAINDN": names.domaindn})

            logger.info("Setting up sam.ldb users and groups")
            setup_add_ldif(samdb, setup_path("provision_users.ldif"), {
                "DOMAINDN": names.domaindn,
                "DOMAINSID": str(domainsid),
                "ADMINPASS_B64": b64encode(adminpass.encode('utf-16-le')),
                "KRBTGTPASS_B64": b64encode(krbtgtpass.encode('utf-16-le'))
                })

            logger.info("Setting up self join")
            setup_self_join(samdb, admin_session_info, names=names, fill=fill,
                invocationid=invocationid,
                dns_backend=dns_backend,
                dnspass=dnspass,
                machinepass=machinepass,
                domainsid=domainsid,
                next_rid=next_rid,
                dc_rid=dc_rid,
                policyguid=policyguid,
                policyguid_dc=policyguid_dc,
                domainControllerFunctionality=domainControllerFunctionality,
                ntdsguid=ntdsguid)

            ntds_dn = "CN=NTDS Settings,%s" % names.serverdn
            names.ntdsguid = samdb.searchone(basedn=ntds_dn,
                attribute="objectGUID", expression="", scope=ldb.SCOPE_BASE)
            assert isinstance(names.ntdsguid, str)
    except:
        samdb.transaction_cancel()
        raise
    else:
        samdb.transaction_commit()
        return samdb


FILL_FULL = "FULL"
FILL_SUBDOMAIN = "SUBDOMAIN"
FILL_NT4SYNC = "NT4SYNC"
FILL_DRS = "DRS"
SYSVOL_ACL = "O:LAG:BAD:P(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001200a9;;;SO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)"
POLICIES_ACL = "O:LAG:BAD:P(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001200a9;;;SO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001301bf;;;PA)"
SYSVOL_SERVICE="sysvol"

def set_dir_acl(path, acl, lp, domsid, use_ntvfs, passdb, service=SYSVOL_SERVICE):
    setntacl(lp, path, acl, domsid, use_ntvfs=use_ntvfs, skip_invalid_chown=True, passdb=passdb, service=service)
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            setntacl(lp, os.path.join(root, name), acl, domsid,
                    use_ntvfs=use_ntvfs, skip_invalid_chown=True, passdb=passdb, service=service)
        for name in dirs:
            setntacl(lp, os.path.join(root, name), acl, domsid,
                    use_ntvfs=use_ntvfs, skip_invalid_chown=True, passdb=passdb, service=service)


def set_gpos_acl(sysvol, dnsdomain, domainsid, domaindn, samdb, lp, use_ntvfs, passdb):
    """Set ACL on the sysvol/<dnsname>/Policies folder and the policy
    folders beneath.

    :param sysvol: Physical path for the sysvol folder
    :param dnsdomain: The DNS name of the domain
    :param domainsid: The SID of the domain
    :param domaindn: The DN of the domain (ie. DC=...)
    :param samdb: An LDB object on the SAM db
    :param lp: an LP object
    """

    # Set ACL for GPO root folder
    root_policy_path = os.path.join(sysvol, dnsdomain, "Policies")
    setntacl(lp, root_policy_path, POLICIES_ACL, str(domainsid),
            use_ntvfs=use_ntvfs, skip_invalid_chown=True, passdb=passdb, service=SYSVOL_SERVICE)

    res = samdb.search(base="CN=Policies,CN=System,%s"%(domaindn),
                        attrs=["cn", "nTSecurityDescriptor"],
                        expression="", scope=ldb.SCOPE_ONELEVEL)

    for policy in res:
        acl = ndr_unpack(security.descriptor,
                         str(policy["nTSecurityDescriptor"])).as_sddl()
        policy_path = getpolicypath(sysvol, dnsdomain, str(policy["cn"]))
        set_dir_acl(policy_path, dsacl2fsacl(acl, domainsid), lp,
                    str(domainsid), use_ntvfs,
                    passdb=passdb)


def setsysvolacl(samdb, netlogon, sysvol, uid, gid, domainsid, dnsdomain,
        domaindn, lp, use_ntvfs):
    """Set the ACL for the sysvol share and the subfolders

    :param samdb: An LDB object on the SAM db
    :param netlogon: Physical path for the netlogon folder
    :param sysvol: Physical path for the sysvol folder
    :param uid: The UID of the "Administrator" user
    :param gid: The GID of the "Domain adminstrators" group
    :param domainsid: The SID of the domain
    :param dnsdomain: The DNS name of the domain
    :param domaindn: The DN of the domain (ie. DC=...)
    """
    s4_passdb = None

    if not use_ntvfs:
        # This will ensure that the smbd code we are running when setting ACLs
        # is initialised with the smb.conf
        s3conf = s3param.get_context()
        s3conf.load(lp.configfile)
        # ensure we are using the right samba_dsdb passdb backend, no matter what
        s3conf.set("passdb backend", "samba_dsdb:%s" % samdb.url)
        passdb.reload_static_pdb()

        # ensure that we init the samba_dsdb backend, so the domain sid is
        # marked in secrets.tdb
        s4_passdb = passdb.PDB(s3conf.get("passdb backend"))

        # now ensure everything matches correctly, to avoid wierd issues
        if passdb.get_global_sam_sid() != domainsid:
            raise ProvisioningError('SID as seen by smbd [%s] does not match SID as seen by the provision script [%s]!' % (passdb.get_global_sam_sid(), domainsid))

        domain_info = s4_passdb.domain_info()
        if domain_info["dom_sid"] != domainsid:
            raise ProvisioningError('SID as seen by pdb_samba_dsdb [%s] does not match SID as seen by the provision script [%s]!' % (domain_info["dom_sid"], domainsid))

        if domain_info["dns_domain"].upper() != dnsdomain.upper():
            raise ProvisioningError('Realm as seen by pdb_samba_dsdb [%s] does not match Realm as seen by the provision script [%s]!' % (domain_info["dns_domain"].upper(), dnsdomain.upper()))


    try:
        if use_ntvfs:
            os.chown(sysvol, -1, gid)
    except OSError:
        canchown = False
    else:
        canchown = True

    # Set the SYSVOL_ACL on the sysvol folder and subfolder (first level)
    setntacl(lp,sysvol, SYSVOL_ACL, str(domainsid), use_ntvfs=use_ntvfs,
             skip_invalid_chown=True, passdb=s4_passdb,
             service=SYSVOL_SERVICE)
    for root, dirs, files in os.walk(sysvol, topdown=False):
        for name in files:
            if use_ntvfs and canchown:
                os.chown(os.path.join(root, name), -1, gid)
            setntacl(lp, os.path.join(root, name), SYSVOL_ACL, str(domainsid),
                     use_ntvfs=use_ntvfs, skip_invalid_chown=True,
                     passdb=s4_passdb, service=SYSVOL_SERVICE)
        for name in dirs:
            if use_ntvfs and canchown:
                os.chown(os.path.join(root, name), -1, gid)
            setntacl(lp, os.path.join(root, name), SYSVOL_ACL, str(domainsid),
                     use_ntvfs=use_ntvfs, skip_invalid_chown=True,
                     passdb=s4_passdb, service=SYSVOL_SERVICE)

    # Set acls on Policy folder and policies folders
    set_gpos_acl(sysvol, dnsdomain, domainsid, domaindn, samdb, lp, use_ntvfs, passdb=s4_passdb)

def acl_type(direct_db_access):
    if direct_db_access:
        return "DB"
    else:
        return "VFS"

def check_dir_acl(path, acl, lp, domainsid, direct_db_access):
    fsacl = getntacl(lp, path, direct_db_access=direct_db_access, service=SYSVOL_SERVICE)
    fsacl_sddl = fsacl.as_sddl(domainsid)
    if fsacl_sddl != acl:
        raise ProvisioningError('%s ACL on GPO directory %s %s does not match expected value %s from GPO object' % (acl_type(direct_db_access), path, fsacl_sddl, acl))

    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            fsacl = getntacl(lp, os.path.join(root, name),
                             direct_db_access=direct_db_access, service=SYSVOL_SERVICE)
            if fsacl is None:
                raise ProvisioningError('%s ACL on GPO file %s %s not found!' % (acl_type(direct_db_access), os.path.join(root, name)))
            fsacl_sddl = fsacl.as_sddl(domainsid)
            if fsacl_sddl != acl:
                raise ProvisioningError('%s ACL on GPO file %s %s does not match expected value %s from GPO object' % (acl_type(direct_db_access), os.path.join(root, name), fsacl_sddl, acl))

        for name in dirs:
            fsacl = getntacl(lp, os.path.join(root, name),
                             direct_db_access=direct_db_access, service=SYSVOL_SERVICE)
            if fsacl is None:
                raise ProvisioningError('%s ACL on GPO directory %s %s not found!' % (acl_type(direct_db_access), os.path.join(root, name)))
            fsacl_sddl = fsacl.as_sddl(domainsid)
            if fsacl_sddl != acl:
                raise ProvisioningError('%s ACL on GPO directory %s %s does not match expected value %s from GPO object' % (acl_type(direct_db_access), os.path.join(root, name), fsacl_sddl, acl))


def check_gpos_acl(sysvol, dnsdomain, domainsid, domaindn, samdb, lp,
        direct_db_access):
    """Set ACL on the sysvol/<dnsname>/Policies folder and the policy
    folders beneath.

    :param sysvol: Physical path for the sysvol folder
    :param dnsdomain: The DNS name of the domain
    :param domainsid: The SID of the domain
    :param domaindn: The DN of the domain (ie. DC=...)
    :param samdb: An LDB object on the SAM db
    :param lp: an LP object
    """

    # Set ACL for GPO root folder
    root_policy_path = os.path.join(sysvol, dnsdomain, "Policies")
    fsacl = getntacl(lp, root_policy_path,
                     direct_db_access=direct_db_access, service=SYSVOL_SERVICE)
    if fsacl is None:
        raise ProvisioningError('DB ACL on policy root %s %s not found!' % (acl_type(direct_db_access), root_policy_path))
    fsacl_sddl = fsacl.as_sddl(domainsid)
    if fsacl_sddl != POLICIES_ACL:
        raise ProvisioningError('%s ACL on policy root %s %s does not match expected value %s from provision' % (acl_type(direct_db_access), root_policy_path, fsacl_sddl, fsacl))
    res = samdb.search(base="CN=Policies,CN=System,%s"%(domaindn),
                        attrs=["cn", "nTSecurityDescriptor"],
                        expression="", scope=ldb.SCOPE_ONELEVEL)

    for policy in res:
        acl = ndr_unpack(security.descriptor,
                         str(policy["nTSecurityDescriptor"])).as_sddl()
        policy_path = getpolicypath(sysvol, dnsdomain, str(policy["cn"]))
        check_dir_acl(policy_path, dsacl2fsacl(acl, domainsid), lp,
                      domainsid, direct_db_access)


def checksysvolacl(samdb, netlogon, sysvol, domainsid, dnsdomain, domaindn,
    lp):
    """Set the ACL for the sysvol share and the subfolders

    :param samdb: An LDB object on the SAM db
    :param netlogon: Physical path for the netlogon folder
    :param sysvol: Physical path for the sysvol folder
    :param uid: The UID of the "Administrator" user
    :param gid: The GID of the "Domain adminstrators" group
    :param domainsid: The SID of the domain
    :param dnsdomain: The DNS name of the domain
    :param domaindn: The DN of the domain (ie. DC=...)
    """

    # This will ensure that the smbd code we are running when setting ACLs is initialised with the smb.conf
    s3conf = s3param.get_context()
    s3conf.load(lp.configfile)
    # ensure we are using the right samba_dsdb passdb backend, no matter what
    s3conf.set("passdb backend", "samba_dsdb:%s" % samdb.url)
    # ensure that we init the samba_dsdb backend, so the domain sid is marked in secrets.tdb
    s4_passdb = passdb.PDB(s3conf.get("passdb backend"))

    # now ensure everything matches correctly, to avoid wierd issues
    if passdb.get_global_sam_sid() != domainsid:
        raise ProvisioningError('SID as seen by smbd [%s] does not match SID as seen by the provision script [%s]!' % (passdb.get_global_sam_sid(), domainsid))

    domain_info = s4_passdb.domain_info()
    if domain_info["dom_sid"] != domainsid:
        raise ProvisioningError('SID as seen by pdb_samba_dsdb [%s] does not match SID as seen by the provision script [%s]!' % (domain_info["dom_sid"], domainsid))

    if domain_info["dns_domain"].upper() != dnsdomain.upper():
        raise ProvisioningError('Realm as seen by pdb_samba_dsdb [%s] does not match Realm as seen by the provision script [%s]!' % (domain_info["dns_domain"].upper(), dnsdomain.upper()))

    # Ensure we can read this directly, and via the smbd VFS
    for direct_db_access in [True, False]:
        # Check the SYSVOL_ACL on the sysvol folder and subfolder (first level)
        for dir_path in [os.path.join(sysvol, dnsdomain), netlogon]:
            fsacl = getntacl(lp, dir_path, direct_db_access=direct_db_access, service=SYSVOL_SERVICE)
            if fsacl is None:
                raise ProvisioningError('%s ACL on sysvol directory %s not found!' % (acl_type(direct_db_access), dir_path))
            fsacl_sddl = fsacl.as_sddl(domainsid)
            if fsacl_sddl != SYSVOL_ACL:
                raise ProvisioningError('%s ACL on sysvol directory %s %s does not match expected value %s from provision' % (acl_type(direct_db_access), dir_path, fsacl_sddl, SYSVOL_ACL))

        # Check acls on Policy folder and policies folders
        check_gpos_acl(sysvol, dnsdomain, domainsid, domaindn, samdb, lp,
                direct_db_access)


def interface_ips_v4(lp):
    """return only IPv4 IPs"""
    ips = samba.interface_ips(lp, False)
    ret = []
    for i in ips:
        if i.find(':') == -1:
            ret.append(i)
    return ret


def interface_ips_v6(lp):
    """return only IPv6 IPs"""
    ips = samba.interface_ips(lp, False)
    ret = []
    for i in ips:
        if i.find(':') != -1:
            ret.append(i)
    return ret


def provision_fill(samdb, secrets_ldb, logger, names, paths,
                   domainsid, schema=None,
                   targetdir=None, samdb_fill=FILL_FULL,
                   hostip=None, hostip6=None,
                   next_rid=1000, dc_rid=None, adminpass=None, krbtgtpass=None,
                   domainguid=None, policyguid=None, policyguid_dc=None,
                   invocationid=None, machinepass=None, ntdsguid=None,
                   dns_backend=None, dnspass=None,
                   serverrole=None, dom_for_fun_level=None,
                   am_rodc=False, lp=None, use_ntvfs=False, skip_sysvolacl=False):
    # create/adapt the group policy GUIDs
    # Default GUID for default policy are described at
    # "How Core Group Policy Works"
    # http://technet.microsoft.com/en-us/library/cc784268%28WS.10%29.aspx
    if policyguid is None:
        policyguid = DEFAULT_POLICY_GUID
    policyguid = policyguid.upper()
    if policyguid_dc is None:
        policyguid_dc = DEFAULT_DC_POLICY_GUID
    policyguid_dc = policyguid_dc.upper()

    if invocationid is None:
        invocationid = str(uuid.uuid4())

    if krbtgtpass is None:
        krbtgtpass = samba.generate_random_password(128, 255)
    if machinepass is None:
        machinepass  = samba.generate_random_password(128, 255)
    if dnspass is None:
        dnspass = samba.generate_random_password(128, 255)

    samdb = fill_samdb(samdb, lp, names, logger=logger,
                   domainsid=domainsid, schema=schema, domainguid=domainguid,
                   policyguid=policyguid, policyguid_dc=policyguid_dc,
                   fill=samdb_fill, adminpass=adminpass, krbtgtpass=krbtgtpass,
                   invocationid=invocationid, machinepass=machinepass,
                   dns_backend=dns_backend, dnspass=dnspass,
                   ntdsguid=ntdsguid, serverrole=serverrole,
                   dom_for_fun_level=dom_for_fun_level, am_rodc=am_rodc,
                   next_rid=next_rid, dc_rid=dc_rid)

    if serverrole == "active directory domain controller":

        # Set up group policies (domain policy and domain controller
        # policy)
        create_default_gpo(paths.sysvol, names.dnsdomain, policyguid,
                           policyguid_dc)
        if not skip_sysvolacl:
            setsysvolacl(samdb, paths.netlogon, paths.sysvol, paths.root_uid,
                         paths.root_gid, domainsid, names.dnsdomain,
                         names.domaindn, lp, use_ntvfs)
        else:
            logger.info("Setting acl on sysvol skipped")

        secretsdb_self_join(secrets_ldb, domain=names.domain,
                realm=names.realm, dnsdomain=names.dnsdomain,
                netbiosname=names.netbiosname, domainsid=domainsid,
                machinepass=machinepass, secure_channel_type=SEC_CHAN_BDC)

        # Now set up the right msDS-SupportedEncryptionTypes into the DB
        # In future, this might be determined from some configuration
        kerberos_enctypes = str(ENC_ALL_TYPES)

        try:
            msg = ldb.Message(ldb.Dn(samdb,
                                     samdb.searchone("distinguishedName",
                                                     expression="samAccountName=%s$" % names.netbiosname,
                                                     scope=ldb.SCOPE_SUBTREE)))
            msg["msDS-SupportedEncryptionTypes"] = ldb.MessageElement(
                elements=kerberos_enctypes, flags=ldb.FLAG_MOD_REPLACE,
                name="msDS-SupportedEncryptionTypes")
            samdb.modify(msg)
        except ldb.LdbError, (enum, estr):
            if enum != ldb.ERR_NO_SUCH_ATTRIBUTE:
                # It might be that this attribute does not exist in this schema
                raise

        setup_ad_dns(samdb, secrets_ldb, domainsid, names, paths, lp, logger,
                     hostip=hostip, hostip6=hostip6, dns_backend=dns_backend,
                     dnspass=dnspass, os_level=dom_for_fun_level,
                     targetdir=targetdir, site=DEFAULTSITE)

        domainguid = samdb.searchone(basedn=samdb.get_default_basedn(),
                                     attribute="objectGUID")
        assert isinstance(domainguid, str)

    lastProvisionUSNs = get_last_provision_usn(samdb)
    maxUSN = get_max_usn(samdb, str(names.rootdn))
    if lastProvisionUSNs is not None:
        update_provision_usn(samdb, 0, maxUSN, invocationid, 1)
    else:
        set_provision_usn(samdb, 0, maxUSN, invocationid)

    logger.info("Setting up sam.ldb rootDSE marking as synchronized")
    setup_modify_ldif(samdb, setup_path("provision_rootdse_modify.ldif"),
                      { 'NTDSGUID' : names.ntdsguid })

    # fix any dangling GUIDs from the provision
    logger.info("Fixing provision GUIDs")
    chk = dbcheck(samdb, samdb_schema=samdb, verbose=False, fix=True, yes=True,
            quiet=True)
    samdb.transaction_start()
    try:
        # a small number of GUIDs are missing because of ordering issues in the
        # provision code
        for schema_obj in ['CN=Domain', 'CN=Organizational-Person', 'CN=Contact', 'CN=inetOrgPerson']:
            chk.check_database(DN="%s,%s" % (schema_obj, names.schemadn),
                               scope=ldb.SCOPE_BASE,
                               attrs=['defaultObjectCategory'])
        chk.check_database(DN="CN=IP Security,CN=System,%s" % names.domaindn,
                           scope=ldb.SCOPE_ONELEVEL,
                           attrs=['ipsecOwnersReference',
                                  'ipsecFilterReference',
                                  'ipsecISAKMPReference',
                                  'ipsecNegotiationPolicyReference',
                                  'ipsecNFAReference'])
    except:
        samdb.transaction_cancel()
        raise
    else:
        samdb.transaction_commit()


_ROLES_MAP = {
    "ROLE_STANDALONE": "standalone server",
    "ROLE_DOMAIN_MEMBER": "member server",
    "ROLE_DOMAIN_BDC": "active directory domain controller",
    "ROLE_DOMAIN_PDC": "active directory domain controller",
    "dc": "active directory domain controller",
    "member": "member server",
    "domain controller": "active directory domain controller",
    "active directory domain controller": "active directory domain controller",
    "member server": "member server",
    "standalone": "standalone server",
    "standalone server": "standalone server",
    }


def sanitize_server_role(role):
    """Sanitize a server role name.

    :param role: Server role
    :raise ValueError: If the role can not be interpreted
    :return: Sanitized server role (one of "member server",
        "active directory domain controller", "standalone server")
    """
    try:
        return _ROLES_MAP[role]
    except KeyError:
        raise ValueError(role)


def provision_fake_ypserver(logger, samdb, domaindn, netbiosname, nisdomain,
        maxuid, maxgid):
    """Create AD entries for the fake ypserver.

    This is needed for being able to manipulate posix attrs via ADUC.
    """
    samdb.transaction_start()
    try:
        logger.info("Setting up fake yp server settings")
        setup_add_ldif(samdb, setup_path("ypServ30.ldif"), {
        "DOMAINDN": domaindn,
        "NETBIOSNAME": netbiosname,
        "NISDOMAIN": nisdomain,
         })
    except:
        samdb.transaction_cancel()
        raise
    else:
        samdb.transaction_commit()


def provision(logger, session_info, credentials, smbconf=None,
        targetdir=None, samdb_fill=FILL_FULL, realm=None, rootdn=None,
        domaindn=None, schemadn=None, configdn=None, serverdn=None,
        domain=None, hostname=None, hostip=None, hostip6=None, domainsid=None,
        next_rid=1000, dc_rid=None, adminpass=None, ldapadminpass=None,
        krbtgtpass=None, domainguid=None, policyguid=None, policyguid_dc=None,
        dns_backend=None, dns_forwarder=None, dnspass=None,
        invocationid=None, machinepass=None, ntdsguid=None,
        root=None, nobody=None, users=None, backup=None, aci=None,
        serverrole=None, dom_for_fun_level=None, backend_type=None,
        sitename=None, ol_mmr_urls=None, ol_olc=None, slapd_path="/bin/false",
        useeadb=False, am_rodc=False, lp=None, use_ntvfs=False,
        use_rfc2307=False, maxuid=None, maxgid=None, skip_sysvolacl=True):
    """Provision samba4

    :note: caution, this wipes all existing data!
    """

    try:
        serverrole = sanitize_server_role(serverrole)
    except ValueError:
        raise ProvisioningError('server role (%s) should be one of "active directory domain controller", "member server", "standalone server"' % serverrole)

    if ldapadminpass is None:
        # Make a new, random password between Samba and it's LDAP server
        ldapadminpass = samba.generate_random_password(128, 255)

    if backend_type is None:
        backend_type = "ldb"

    if domainsid is None:
        domainsid = security.random_sid()
    else:
        domainsid = security.dom_sid(domainsid)

    root_uid = findnss_uid([root or "root"])
    nobody_uid = findnss_uid([nobody or "nobody"])
    users_gid = findnss_gid([users or "users", 'users', 'other', 'staff'])
    root_gid = pwd.getpwuid(root_uid).pw_gid

    try:
        bind_gid = findnss_gid(["bind", "named"])
    except KeyError:
        bind_gid = None

    if targetdir is not None:
        smbconf = os.path.join(targetdir, "etc", "smb.conf")
    elif smbconf is None:
        smbconf = samba.param.default_path()
    if not os.path.exists(os.path.dirname(smbconf)):
        os.makedirs(os.path.dirname(smbconf))

    server_services = []
    global_param = {}
    if use_rfc2307:
        global_param["idmap_ldb:use rfc2307"] = ["yes"]

    if dns_backend != "SAMBA_INTERNAL":
        server_services.append("-dns")
    else:
        if dns_forwarder is not None:
            global_param["dns forwarder"] = [dns_forwarder]

    if use_ntvfs:
        server_services.append("+smb")
        server_services.append("-s3fs")
        global_param["dcerpc endpoint servers"] = ["+winreg", "+srvsvc"]

    if len(server_services) > 0:
        global_param["server services"] = server_services

    # only install a new smb.conf if there isn't one there already
    if os.path.exists(smbconf):
        # if Samba Team members can't figure out the weird errors
        # loading an empty smb.conf gives, then we need to be smarter.
        # Pretend it just didn't exist --abartlet
        f = open(smbconf, 'r')
        try:
            data = f.read().lstrip()
        finally:
            f.close()
        if data is None or data == "":
            make_smbconf(smbconf, hostname, domain, realm,
                         targetdir, serverrole=serverrole,
                         eadb=useeadb, use_ntvfs=use_ntvfs,
                         lp=lp, global_param=global_param)
    else:
        make_smbconf(smbconf, hostname, domain, realm, targetdir,
                     serverrole=serverrole,
                     eadb=useeadb, use_ntvfs=use_ntvfs, lp=lp, global_param=global_param)

    if lp is None:
        lp = samba.param.LoadParm()
    lp.load(smbconf)
    names = guess_names(lp=lp, hostname=hostname, domain=domain,
        dnsdomain=realm, serverrole=serverrole, domaindn=domaindn,
        configdn=configdn, schemadn=schemadn, serverdn=serverdn,
        sitename=sitename, rootdn=rootdn, domain_names_forced=(samdb_fill == FILL_DRS))
    paths = provision_paths_from_lp(lp, names.dnsdomain)

    paths.bind_gid = bind_gid
    paths.root_uid = root_uid;
    paths.root_gid = root_gid

    if hostip is None:
        logger.info("Looking up IPv4 addresses")
        hostips = interface_ips_v4(lp)
        if len(hostips) > 0:
            hostip = hostips[0]
            if len(hostips) > 1:
                logger.warning("More than one IPv4 address found. Using %s",
                    hostip)
    if hostip == "127.0.0.1":
        hostip = None
    if hostip is None:
        logger.warning("No IPv4 address will be assigned")

    if hostip6 is None:
        logger.info("Looking up IPv6 addresses")
        hostips = interface_ips_v6(lp)
        if hostips:
            hostip6 = hostips[0]
        if len(hostips) > 1:
            logger.warning("More than one IPv6 address found. Using %s", hostip6)
    if hostip6 is None:
        logger.warning("No IPv6 address will be assigned")

    names.hostip = hostip
    names.hostip6 = hostip6

    if serverrole is None:
        serverrole = lp.get("server role")

    if not os.path.exists(paths.private_dir):
        os.mkdir(paths.private_dir)
    if not os.path.exists(os.path.join(paths.private_dir, "tls")):
        os.makedirs(os.path.join(paths.private_dir, "tls"), 0700)
    if not os.path.exists(paths.state_dir):
        os.mkdir(paths.state_dir)

    if paths.sysvol and not os.path.exists(paths.sysvol):
        os.makedirs(paths.sysvol, 0775)

    if not use_ntvfs and serverrole == "active directory domain controller":
        s3conf = s3param.get_context()
        s3conf.load(lp.configfile)

        if paths.sysvol is None:
            raise MissingShareError("sysvol", paths.smbconf)

        file = tempfile.NamedTemporaryFile(dir=os.path.abspath(paths.sysvol))
        try:
            try:
                smbd.set_simple_acl(file.name, 0755, root_gid)
            except Exception:
                if not smbd.have_posix_acls():
                    # This clue is only strictly correct for RPM and
                    # Debian-like Linux systems, but hopefully other users
                    # will get enough clue from it.
                    raise ProvisioningError("Samba was compiled without the posix ACL support that s3fs requires.  Try installing libacl1-dev or libacl-devel, then re-run configure and make.")

                raise ProvisioningError("Your filesystem or build does not support posix ACLs, which s3fs requires.  Try the mounting the filesystem with the 'acl' option.")
            try:
                smbd.chown(file.name, root_uid, root_gid)
            except Exception:
                raise ProvisioningError("Unable to chown a file on your filesystem.  You may not be running provision as root.")
        finally:
            file.close()

    ldapi_url = "ldapi://%s" % urllib.quote(paths.s4_ldapi_path, safe="")

    schema = Schema(domainsid, invocationid=invocationid,
        schemadn=names.schemadn)

    if backend_type == "ldb":
        provision_backend = LDBBackend(backend_type, paths=paths,
            lp=lp, credentials=credentials,
            names=names, logger=logger)
    elif backend_type == "existing":
        # If support for this is ever added back, then the URI will need to be
        # specified again
        provision_backend = ExistingBackend(backend_type, paths=paths,
            lp=lp, credentials=credentials,
            names=names, logger=logger,
            ldap_backend_forced_uri=None)
    elif backend_type == "fedora-ds":
        provision_backend = FDSBackend(backend_type, paths=paths,
            lp=lp, credentials=credentials,
            names=names, logger=logger, domainsid=domainsid,
            schema=schema, hostname=hostname, ldapadminpass=ldapadminpass,
            slapd_path=slapd_path,
            root=root)
    elif backend_type == "openldap":
        provision_backend = OpenLDAPBackend(backend_type, paths=paths,
            lp=lp, credentials=credentials,
            names=names, logger=logger, domainsid=domainsid,
            schema=schema, hostname=hostname, ldapadminpass=ldapadminpass,
            slapd_path=slapd_path, ol_mmr_urls=ol_mmr_urls)
    else:
        raise ValueError("Unknown LDAP backend type selected")

    provision_backend.init()
    provision_backend.start()

    # only install a new shares config db if there is none
    if not os.path.exists(paths.shareconf):
        logger.info("Setting up share.ldb")
        share_ldb = Ldb(paths.shareconf, session_info=session_info, lp=lp)
        share_ldb.load_ldif_file_add(setup_path("share.ldif"))

    logger.info("Setting up secrets.ldb")
    secrets_ldb = setup_secretsdb(paths,
        session_info=session_info,
        backend_credentials=provision_backend.secrets_credentials, lp=lp)

    try:
        logger.info("Setting up the registry")
        setup_registry(paths.hklm, session_info, lp=lp)

        logger.info("Setting up the privileges database")
        setup_privileges(paths.privilege, session_info, lp=lp)

        logger.info("Setting up idmap db")
        idmap = setup_idmapdb(paths.idmapdb, session_info=session_info, lp=lp)

        setup_name_mappings(idmap, sid=str(domainsid),
                            root_uid=root_uid, nobody_uid=nobody_uid,
                            users_gid=users_gid, root_gid=root_gid)

        logger.info("Setting up SAM db")
        samdb = setup_samdb(paths.samdb, session_info,
                            provision_backend, lp, names, logger=logger,
                            serverrole=serverrole,
                            schema=schema, fill=samdb_fill, am_rodc=am_rodc)

        if serverrole == "active directory domain controller":
            if paths.netlogon is None:
                raise MissingShareError("netlogon", paths.smbconf)

            if paths.sysvol is None:
                raise MissingShareError("sysvol", paths.smbconf)

            if not os.path.isdir(paths.netlogon):
                os.makedirs(paths.netlogon, 0755)

        if adminpass is None:
            adminpass = samba.generate_random_password(12, 32)
            adminpass_generated = True
        else:
            adminpass = unicode(adminpass, 'utf-8')
            adminpass_generated = False

        if samdb_fill == FILL_FULL:
            provision_fill(samdb, secrets_ldb, logger, names, paths,
                    schema=schema, targetdir=targetdir, samdb_fill=samdb_fill,
                    hostip=hostip, hostip6=hostip6, domainsid=domainsid,
                    next_rid=next_rid, dc_rid=dc_rid, adminpass=adminpass,
                    krbtgtpass=krbtgtpass, domainguid=domainguid,
                    policyguid=policyguid, policyguid_dc=policyguid_dc,
                    invocationid=invocationid, machinepass=machinepass,
                    ntdsguid=ntdsguid, dns_backend=dns_backend,
                    dnspass=dnspass, serverrole=serverrole,
                    dom_for_fun_level=dom_for_fun_level, am_rodc=am_rodc,
                    lp=lp, use_ntvfs=use_ntvfs,
                           skip_sysvolacl=skip_sysvolacl)

        create_krb5_conf(paths.krb5conf,
                         dnsdomain=names.dnsdomain, hostname=names.hostname,
                         realm=names.realm)
        logger.info("A Kerberos configuration suitable for Samba 4 has been "
                    "generated at %s", paths.krb5conf)

        if serverrole == "active directory domain controller":
            create_dns_update_list(lp, logger, paths)

        backend_result = provision_backend.post_setup()
        provision_backend.shutdown()

    except:
        secrets_ldb.transaction_cancel()
        raise

    # Now commit the secrets.ldb to disk
    secrets_ldb.transaction_commit()

    # the commit creates the dns.keytab, now chown it
    dns_keytab_path = os.path.join(paths.private_dir, paths.dns_keytab)
    if os.path.isfile(dns_keytab_path) and paths.bind_gid is not None:
        try:
            os.chmod(dns_keytab_path, 0640)
            os.chown(dns_keytab_path, -1, paths.bind_gid)
        except OSError:
            if not os.environ.has_key('SAMBA_SELFTEST'):
                logger.info("Failed to chown %s to bind gid %u",
                            dns_keytab_path, paths.bind_gid)

    result = ProvisionResult()
    result.server_role = serverrole
    result.domaindn = domaindn
    result.paths = paths
    result.names = names
    result.lp = lp
    result.samdb = samdb
    result.idmap = idmap
    result.domainsid = str(domainsid)

    if samdb_fill == FILL_FULL:
        result.adminpass_generated = adminpass_generated
        result.adminpass = adminpass
    else:
        result.adminpass_generated = False
        result.adminpass = None

    result.backend_result = backend_result

    if use_rfc2307:
        provision_fake_ypserver(logger=logger, samdb=samdb,
                domaindn=names.domaindn, netbiosname=names.netbiosname,
                nisdomain=names.domain.lower(), maxuid=maxuid, maxgid=maxgid)

    return result


def provision_become_dc(smbconf=None, targetdir=None,
        realm=None, rootdn=None, domaindn=None, schemadn=None, configdn=None,
        serverdn=None, domain=None, hostname=None, domainsid=None,
        adminpass=None, krbtgtpass=None, domainguid=None, policyguid=None,
        policyguid_dc=None, invocationid=None, machinepass=None, dnspass=None,
        dns_backend=None, root=None, nobody=None, users=None,
        backup=None, serverrole=None, ldap_backend=None,
        ldap_backend_type=None, sitename=None, debuglevel=1, use_ntvfs=False):

    logger = logging.getLogger("provision")
    samba.set_debug_level(debuglevel)

    res = provision(logger, system_session(), None,
        smbconf=smbconf, targetdir=targetdir, samdb_fill=FILL_DRS,
        realm=realm, rootdn=rootdn, domaindn=domaindn, schemadn=schemadn,
        configdn=configdn, serverdn=serverdn, domain=domain,
        hostname=hostname, hostip=None, domainsid=domainsid,
        machinepass=machinepass,
        serverrole="active directory domain controller",
        sitename=sitename, dns_backend=dns_backend, dnspass=dnspass,
        use_ntvfs=use_ntvfs)
    res.lp.set("debuglevel", str(debuglevel))
    return res


def create_krb5_conf(path, dnsdomain, hostname, realm):
    """Write out a file containing zone statements suitable for inclusion in a
    named.conf file (including GSS-TSIG configuration).

    :param path: Path of the new named.conf file.
    :param dnsdomain: DNS Domain name
    :param hostname: Local hostname
    :param realm: Realm name
    """
    setup_file(setup_path("krb5.conf"), path, {
            "DNSDOMAIN": dnsdomain,
            "HOSTNAME": hostname,
            "REALM": realm,
        })


class ProvisioningError(Exception):
    """A generic provision error."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "ProvisioningError: " + self.value


class InvalidNetbiosName(Exception):
    """A specified name was not a valid NetBIOS name."""

    def __init__(self, name):
        super(InvalidNetbiosName, self).__init__(
            "The name '%r' is not a valid NetBIOS name" % name)


class MissingShareError(ProvisioningError):

    def __init__(self, name, smbconf):
        super(MissingShareError, self).__init__(
            "Existing smb.conf does not have a [%s] share, but you are "
            "configuring a DC. Please remove %s or add the share manually." %
            (name, smbconf))
