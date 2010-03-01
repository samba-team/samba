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

import samba
from samba import Ldb, DS_DOMAIN_FUNCTION_2000
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
import ldb
from samba.provision import ProvisionNames, provision_paths_from_lp, FILL_FULL, provision
from samba.provisionexceptions import ProvisioningError
from samba.dcerpc import misc, security
from samba.ndr import ndr_unpack


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
        raise ProvisioningError("Unable to find smb.conf ...")

    lp = param.LoadParm()
    lp.load(smbconf)
    paths = provision_paths_from_lp(lp,lp.get("realm"))
    return paths


def find_provision_key_parameters(param, credentials, session_info, paths, smbconf):
    """Get key provision parameters (realm, domain, ...) from a given provision

    :param param: Param object
    :param credentials: Credentials for the authentification
    :param session_info: Session object
    :param paths: A list of path to provision object
    :param smbconf: Path to the smb.conf file
    :return: A list of key provision parameters"""

    lp = param.LoadParm()
    lp.load(paths.smbconf)
    names = ProvisionNames()
    names.adminpass = None
    # NT domain, kerberos realm, root dn, domain dn, domain dns name
    names.domain = string.upper(lp.get("workgroup"))
    names.realm = lp.get("realm")
    basedn = "DC=" + names.realm.replace(".",",DC=")
    names.dnsdomain = names.realm
    names.realm = string.upper(names.realm)
    # netbiosname
    secrets_ldb = Ldb(paths.secrets, session_info=session_info, credentials=credentials,lp=lp, options=["modules:samba_secrets"])
    # Get the netbiosname first (could be obtained from smb.conf in theory)
    attrs = ["sAMAccountName"]
    res = secrets_ldb.search(expression="(flatname=%s)"%names.domain,base="CN=Primary Domains", scope=SCOPE_SUBTREE, attrs=attrs)
    names.netbiosname = str(res[0]["sAMAccountName"]).replace("$","")

    names.smbconf = smbconf
    # It's important here to let ldb load with the old module or it's quite
    # certain that the LDB won't load ...
    samdb = Ldb(paths.samdb, session_info=session_info,
            credentials=credentials, lp=lp, options=["modules:samba_dsdb"])

    # That's a bit simplistic but it's ok as long as we have only 3
    # partitions
    attrs2 = ["defaultNamingContext", "schemaNamingContext","configurationNamingContext","rootDomainNamingContext"]
    current = samdb.search(expression="(objectClass=*)",base="", scope=SCOPE_BASE, attrs=attrs2)

    names.configdn = current[0]["configurationNamingContext"]
    configdn = str(names.configdn)
    names.schemadn = current[0]["schemaNamingContext"]
    if not (ldb.Dn(samdb, basedn) == (ldb.Dn(samdb, current[0]["defaultNamingContext"][0]))):
        raise ProvisioningError(("basedn in %s (%s) and from %s (%s) is not the same ..." % (paths.samdb, str(current[0]["defaultNamingContext"][0]), paths.smbconf, basedn)))

    names.domaindn=current[0]["defaultNamingContext"]
    names.rootdn=current[0]["rootDomainNamingContext"]
    # default site name
    attrs3 = ["cn"]
    res3= samdb.search(expression="(objectClass=*)",base="CN=Sites,"+configdn, scope=SCOPE_ONELEVEL, attrs=attrs3)
    names.sitename = str(res3[0]["cn"])

    # dns hostname and server dn
    attrs4 = ["dNSHostName"]
    res4= samdb.search(expression="(CN=%s)"%names.netbiosname,base="OU=Domain Controllers,"+basedn, \
                        scope=SCOPE_ONELEVEL, attrs=attrs4)
    names.hostname = str(res4[0]["dNSHostName"]).replace("."+names.dnsdomain,"")

    server_res = samdb.search(expression="serverReference=%s"%res4[0].dn, attrs=[], base=configdn)
    names.serverdn = server_res[0].dn

    # invocation id/objectguid
    res5 = samdb.search(expression="(objectClass=*)",base="CN=NTDS Settings,%s" % str(names.serverdn), scope=SCOPE_BASE, attrs=["invocationID","objectGUID"])
    names.invocation = str(ndr_unpack( misc.GUID,res5[0]["invocationId"][0]))
    names.ntdsguid = str(ndr_unpack( misc.GUID,res5[0]["objectGUID"][0]))

    # domain guid/sid
    attrs6 = ["objectGUID", "objectSid","msDS-Behavior-Version" ]
    res6 = samdb.search(expression="(objectClass=*)",base=basedn, scope=SCOPE_BASE, attrs=attrs6)
    names.domainguid = str(ndr_unpack( misc.GUID,res6[0]["objectGUID"][0]))
    names.domainsid = ndr_unpack( security.dom_sid,res6[0]["objectSid"][0])
    if res6[0].get("msDS-Behavior-Version") == None or int(res6[0]["msDS-Behavior-Version"][0]) < DS_DOMAIN_FUNCTION_2000:
        names.domainlevel = DS_DOMAIN_FUNCTION_2000
    else:
        names.domainlevel = int(res6[0]["msDS-Behavior-Version"][0])

    # policy guid
    attrs7 = ["cn","displayName"]
    res7 = samdb.search(expression="(displayName=Default Domain Policy)",base="CN=Policies,CN=System,"+basedn, \
                            scope=SCOPE_ONELEVEL, attrs=attrs7)
    names.policyid = str(res7[0]["cn"]).replace("{","").replace("}","")
    # dc policy guid
    attrs8 = ["cn","displayName"]
    res8 = samdb.search(expression="(displayName=Default Domain Controllers Policy)",base="CN=Policies,CN=System,"+basedn, \
                            scope=SCOPE_ONELEVEL, attrs=attrs8)
    if len(res8) == 1:
        names.policyid_dc = str(res8[0]["cn"]).replace("{","").replace("}","")
    else:
        names.policyid_dc = None

    return names


def newprovision(names,setup_dir,creds,session,smbconf,provdir,messagefunc):
    """Create a new provision.

    This provision will be the reference for knowing what has changed in the
    since the latest upgrade in the current provision

    :param names: List of provision parameters
    :param setup_dis: Directory where the setup files are stored
    :param creds: Credentials for the authentification
    :param session: Session object
    :param smbconf: Path to the smb.conf file
    :param provdir: Directory where the provision will be stored
    :param messagefunc: A function for displaying the message of the provision"""
    if os.path.isdir(provdir):
        shutil.rmtree(provdir)
    os.chdir(os.path.join(setup_dir,".."))
    os.mkdir(provdir)
    messagefunc("Provision stored in %s"%provdir)
    provision(setup_dir, messagefunc,
        session, creds, smbconf=smbconf, targetdir=provdir,
        samdb_fill=FILL_FULL, realm=names.realm, domain=names.domain,
        domainguid=names.domainguid, domainsid=str(names.domainsid),ntdsguid=names.ntdsguid,
        policyguid=names.policyid,policyguid_dc=names.policyid_dc,hostname=names.netbiosname,
        hostip=None, hostip6=None,
        invocationid=names.invocation, adminpass=names.adminpass,
        krbtgtpass=None, machinepass=None,
        dnspass=None, root=None, nobody=None,
        wheel=None, users=None,
        serverrole="domain controller",
        ldap_backend_extra_port=None,
        backend_type=None,
        ldapadminpass=None,
        ol_mmr_urls=None,
        slapd_path=None,
        setup_ds_path=None,
        nosync=None,
        dom_for_fun_level=names.domainlevel,
        ldap_dryrun_mode=None,useeadb=True)


def dn_sort(x,y):
    """Sorts two DNs in the lexicographical order it and put higher level DN before.

    So given the dns cn=bar,cn=foo and cn=foo the later will be return as smaller
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
    for i in range(0,minimum):
        ret = cmp(tab1[len1-i],tab2[len2-i])
        if ret != 0:
            return ret
        else:
            if i == minimum-1:
                assert len1!=len2,"PB PB PB"+" ".join(tab1)+" / "+" ".join(tab2)
                if len1 > len2:
                    return 1
                else:
                    return -1
    return ret
