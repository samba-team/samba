#!/usr/bin/python
#
# Helpers for provision stuff
# Copyright (C) Matthieu Patou <mat@matws.net> 2009-2010
#
# Based on provision a Samba4 server by
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
#
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


import os
import string
import re
import shutil

from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
import ldb

from samba import Ldb
from samba.dcerpc import misc, security
from samba.dsdb import DS_DOMAIN_FUNCTION_2000
from samba.provision import (ProvisionNames, provision_paths_from_lp,
    FILL_FULL, provision, ProvisioningError)
from samba.ndr import ndr_unpack

# All the ldb related to registry are commented because the path for them is relative
# in the provisionPath object
# And so opening them create a file in the current directory which is not what we want
# I still keep them commented because I plan soon to make more cleaner

class ProvisionLDB(object):
    def __init__(self):
        self.sam = None
        self.secrets = None
        self.idmap = None
        self.privilege = None
        self.hkcr = None
        self.hkcu = None
        self.hku = None
        self.hklm = None

    def startTransactions(self):
        self.sam.transaction_start()
        self.secrets.transaction_start()
        self.idmap.transaction_start()
        self.privilege.transaction_start()
#        self.hkcr.transaction_start()
#        self.hkcu.transaction_start()
#        self.hku.transaction_start()
#        self.hklm.transaction_start()

    def groupedRollback(self):
        self.sam.transaction_cancel()
        self.secrets.transaction_cancel()
        self.idmap.transaction_cancel()
        self.privilege.transaction_cancel()
#        self.hkcr.transaction_cancel()
#        self.hkcu.transaction_cancel()
#        self.hku.transaction_cancel()
#        self.hklm.transaction_cancel()

    def groupedCommit(self):
        self.sam.transaction_prepare_commit()
        self.secrets.transaction_prepare_commit()
        self.idmap.transaction_prepare_commit()
        self.privilege.transaction_prepare_commit()
#        self.hkcr.transaction_prepare_commit()
#        self.hkcu.transaction_prepare_commit()
#        self.hku.transaction_prepare_commit()
#        self.hklm.transaction_prepare_commit()

        self.sam.transaction_commit()
        self.secrets.transaction_commit()
        self.idmap.transaction_commit()
        self.privilege.transaction_commit()
#        self.hkcr.transaction_commit()
#        self.hkcu.transaction_commit()
#        self.hku.transaction_commit()
#        self.hklm.transaction_commit()

def get_ldbs(paths, creds, session, lp):
    """Return LDB object mapped on most important databases

    :param paths: An object holding the different importants paths for provision object
    :param creds: Credential used for openning LDB files
    :param session: Session to use for openning LDB files
    :param lp: A loadparam object
    :return: A ProvisionLDB object that contains LDB object for the different LDB files of the provision"""

    ldbs = ProvisionLDB()

    ldbs.sam = Ldb(paths.samdb, session_info=session, credentials=creds, lp=lp, options=["modules:samba_dsdb"])
    ldbs.secrets = Ldb(paths.secrets, session_info=session, credentials=creds, lp=lp)
    ldbs.idmap = Ldb(paths.idmapdb, session_info=session, credentials=creds, lp=lp)
    ldbs.privilege = Ldb(paths.privilege, session_info=session, credentials=creds, lp=lp)
#    ldbs.hkcr = Ldb(paths.hkcr, session_info=session, credentials=creds, lp=lp)
#    ldbs.hkcu = Ldb(paths.hkcu, session_info=session, credentials=creds, lp=lp)
#    ldbs.hku = Ldb(paths.hku, session_info=session, credentials=creds, lp=lp)
#    ldbs.hklm = Ldb(paths.hklm, session_info=session, credentials=creds, lp=lp)

    return ldbs

def get_paths(param, targetdir=None, smbconf=None):
    """Get paths to important provision objects (smb.conf, ldb files, ...)

    :param param: Param object
    :param targetdir: Directory where the provision is (or will be) stored
    :param smbconf: Path to the smb.conf file
    :return: A list with the path of important provision objects"""
    if targetdir is not None:
        etcdir = os.path.join(targetdir, "etc")
        if not os.path.exists(etcdir):
            os.makedirs(etcdir)
        smbconf = os.path.join(etcdir, "smb.conf")
    if smbconf is None:
        smbconf = param.default_path()

    if not os.path.exists(smbconf):
        raise ProvisioningError("Unable to find smb.conf")

    lp = param.LoadParm()
    lp.load(smbconf)
    paths = provision_paths_from_lp(lp, lp.get("realm"))
    return paths


def find_provision_key_parameters(samdb, secretsdb, paths, smbconf, lp):
    """Get key provision parameters (realm, domain, ...) from a given provision

    :param samdb: An LDB object connected to the sam.ldb file
    :param secretsdb: An LDB object connected to the secrets.ldb file
    :param paths: A list of path to provision object
    :param smbconf: Path to the smb.conf file
    :param lp: A LoadParm object
    :return: A list of key provision parameters"""

    names = ProvisionNames()
    names.adminpass = None

    # NT domain, kerberos realm, root dn, domain dn, domain dns name
    names.domain = string.upper(lp.get("workgroup"))
    names.realm = lp.get("realm")
    basedn = "DC=" + names.realm.replace(".", ",DC=")
    names.dnsdomain = names.realm
    names.realm = string.upper(names.realm)
    # netbiosname
    # Get the netbiosname first (could be obtained from smb.conf in theory)
    res = secretsdb.search(expression="(flatname=%s)"%names.domain,base="CN=Primary Domains", scope=SCOPE_SUBTREE, attrs=["sAMAccountName"])
    names.netbiosname = str(res[0]["sAMAccountName"]).replace("$","")

    names.smbconf = smbconf

    # That's a bit simplistic but it's ok as long as we have only 3
    # partitions
    current = samdb.search(expression="(objectClass=*)", 
        base="", scope=SCOPE_BASE,
        attrs=["defaultNamingContext", "schemaNamingContext",
               "configurationNamingContext","rootDomainNamingContext"])

    names.configdn = current[0]["configurationNamingContext"]
    configdn = str(names.configdn)
    names.schemadn = current[0]["schemaNamingContext"]
    if ldb.Dn(samdb, basedn) != ldb.Dn(samdb, current[0]["defaultNamingContext"][0]):
        raise ProvisioningError("basedn in %s (%s) and from %s (%s) is not the same ..." % (paths.samdb, str(current[0]["defaultNamingContext"][0]), paths.smbconf, basedn))

    names.domaindn=current[0]["defaultNamingContext"]
    names.rootdn=current[0]["rootDomainNamingContext"]
    # default site name
    res3 = samdb.search(expression="(objectClass=*)", 
        base="CN=Sites,"+configdn, scope=SCOPE_ONELEVEL, attrs=["cn"])
    names.sitename = str(res3[0]["cn"])

    # dns hostname and server dn
    res4 = samdb.search(expression="(CN=%s)" % names.netbiosname,
        base="OU=Domain Controllers,"+basedn, scope=SCOPE_ONELEVEL, attrs=["dNSHostName"])
    names.hostname = str(res4[0]["dNSHostName"]).replace("."+names.dnsdomain,"")

    server_res = samdb.search(expression="serverReference=%s" % res4[0].dn,
            attrs=[], base=configdn)
    names.serverdn = server_res[0].dn

    # invocation id/objectguid
    res5 = samdb.search(expression="(objectClass=*)",
            base="CN=NTDS Settings,%s" % str(names.serverdn), scope=SCOPE_BASE,
            attrs=["invocationID", "objectGUID"])
    names.invocation = str(ndr_unpack(misc.GUID, res5[0]["invocationId"][0]))
    names.ntdsguid = str(ndr_unpack(misc.GUID, res5[0]["objectGUID"][0]))

    # domain guid/sid
    res6 = samdb.search(expression="(objectClass=*)",base=basedn,
            scope=SCOPE_BASE, attrs=["objectGUID",
                "objectSid","msDS-Behavior-Version" ])
    names.domainguid = str(ndr_unpack( misc.GUID,res6[0]["objectGUID"][0]))
    names.domainsid = ndr_unpack( security.dom_sid,res6[0]["objectSid"][0])
    if (res6[0].get("msDS-Behavior-Version") is None or
        int(res6[0]["msDS-Behavior-Version"][0]) < DS_DOMAIN_FUNCTION_2000):
        names.domainlevel = DS_DOMAIN_FUNCTION_2000
    else:
        names.domainlevel = int(res6[0]["msDS-Behavior-Version"][0])

    # policy guid
    res7 = samdb.search(expression="(displayName=Default Domain Policy)",
            base="CN=Policies,CN=System,"+basedn, scope=SCOPE_ONELEVEL,
            attrs=["cn","displayName"])
    names.policyid = str(res7[0]["cn"]).replace("{","").replace("}","")
    # dc policy guid
    res8 = samdb.search(expression="(displayName=Default Domain Controllers Policy)",
            base="CN=Policies,CN=System,"+basedn, scope=SCOPE_ONELEVEL,
            attrs=["cn","displayName"])
    if len(res8) == 1:
        names.policyid_dc = str(res8[0]["cn"]).replace("{","").replace("}","")
    else:
        names.policyid_dc = None

    return names


def newprovision(names, setup_dir, creds, session, smbconf, provdir, logger):
    """Create a new provision.

    This provision will be the reference for knowing what has changed in the
    since the latest upgrade in the current provision

    :param names: List of provision parameters
    :param setup_dis: Directory where the setup files are stored
    :param creds: Credentials for the authentification
    :param session: Session object
    :param smbconf: Path to the smb.conf file
    :param provdir: Directory where the provision will be stored
    :param logger: A `Logger`
    """
    if os.path.isdir(provdir):
        shutil.rmtree(provdir)
    os.chdir(os.path.join(setup_dir,".."))
    os.mkdir(provdir)
    logger.info("Provision stored in %s", provdir)
    provision(setup_dir, logger, session, creds, smbconf=smbconf,
            targetdir=provdir, samdb_fill=FILL_FULL, realm=names.realm,
            domain=names.domain, domainguid=names.domainguid,
            domainsid=str(names.domainsid), ntdsguid=names.ntdsguid,
            policyguid=names.policyid, policyguid_dc=names.policyid_dc,
            hostname=names.netbiosname, hostip=None, hostip6=None,
            invocationid=names.invocation, adminpass=names.adminpass,
            krbtgtpass=None, machinepass=None, dnspass=None, root=None,
            nobody=None, wheel=None, users=None,
            serverrole="domain controller", ldap_backend_extra_port=None,
            backend_type=None, ldapadminpass=None, ol_mmr_urls=None,
            slapd_path=None, setup_ds_path=None, nosync=None,
            dom_for_fun_level=names.domainlevel,
            ldap_dryrun_mode=None, useeadb=True)


def dn_sort(x, y):
    """Sorts two DNs in the lexicographical order it and put higher level DN
    before.

    So given the dns cn=bar,cn=foo and cn=foo the later will be return as
    smaller

    :param x: First object to compare
    :param y: Second object to compare
    """
    p = re.compile(r'(?<!\\),')
    tab1 = p.split(str(x))
    tab2 = p.split(str(y))
    minimum = min(len(tab1), len(tab2))
    len1 = len(tab1)-1
    len2 = len(tab2)-1
    # Note: python range go up to upper limit but do not include it
    for i in range(0, minimum):
        ret = cmp(tab1[len1-i], tab2[len2-i])
        if ret != 0:
            return ret
        else:
            if i == minimum-1:
                assert len1 != len2, "PB PB PB"+" ".join(tab1)+" / "+" ".join(tab2)
                if len1 > len2:
                    return 1
                else:
                    return -1
    return ret
