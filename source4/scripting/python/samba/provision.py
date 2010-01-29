#
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
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

from base64 import b64encode
import os
import pwd
import grp
import time
import uuid
import socket
import param
import registry
import urllib
import shutil

import ldb

from samba.auth import system_session, admin_session
from samba import glue, version, Ldb, substitute_var, valid_netbios_name
from samba import check_all_substituted, read_and_sub_file, setup_file
from samba import DS_DOMAIN_FUNCTION_2003, DS_DC_FUNCTION_2008
from samba.dcerpc import security
from samba.dcerpc.misc import SEC_CHAN_BDC, SEC_CHAN_WKSTA
from samba.idmap import IDmapDB
from samba.ntacls import setntacl, dsacl2fsacl
from samba.ndr import ndr_pack,ndr_unpack
from samba.schema import Schema
from ms_display_specifiers import read_ms_ldif
from samba.provisionbackend import LDBBackend, ExistingBackend, FDSBackend, OpenLDAPBackend
from provisionexceptions import ProvisioningError, InvalidNetbiosName

__docformat__ = "restructuredText"

def find_setup_dir():
    """Find the setup directory used by provision."""
    dirname = os.path.dirname(__file__)
    if "/site-packages/" in dirname:
        prefix = "/".join(dirname[:dirname.index("/site-packages/")].split("/")[:-2])
        for suffix in ["share/setup", "share/samba/setup", "setup"]:
            ret = os.path.join(prefix, suffix)
            if os.path.isdir(ret):
                return ret
    # In source tree
    ret = os.path.join(dirname, "../../../setup")
    if os.path.isdir(ret):
        return ret
    raise Exception("Unable to find setup directory.")

# descriptors of the naming contexts
# hard coded at this point, but will probably be changed when
# we enable different fsmo roles

def get_config_descriptor(domain_sid):
    sddl = "O:EAG:EAD:(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(A;;RPLCLORC;;;AU)(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
           "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;CIIO;RPWPCRCCLCLORCWOWDSDSW;;;DA)" \
           "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
           "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
           "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
           "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
           "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ER)" \
           "S:(AU;SA;WPWOWD;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)" \
           "(OU;SA;CR;45ec5156-db7e-47bb-b53f-dbeb2d03c40f;;WD)"
    sec = security.descriptor.from_sddl(sddl, domain_sid)
    return ndr_pack(sec)

def get_domain_descriptor(domain_sid):
    sddl= "O:BAG:BAD:AI(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
        "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ER)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)" \
    "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;IF)" \
    "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)" \
    "(OA;CIIO;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)" \
    "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)" \
    "(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)" \
    "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)" \
    "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)" \
    "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)" \
    "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)" \
    "(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)" \
    "(A;;RPWPCRCCLCLORCWOWDSW;;;DA)" \
    "(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)" \
    "(A;;RPRC;;;RU)" \
    "(A;CI;LC;;;RU)" \
    "(A;CI;RPWPCRCCLCLORCWOWDSDSW;;;BA)" \
    "(A;;RP;;;WD)" \
    "(A;;RPLCLORC;;;ED)" \
    "(A;;RPLCLORC;;;AU)" \
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)" \
    "S:AI(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)" \
    "(AU;SA;CR;;;DU)(AU;SA;CR;;;BA)(AU;SA;WPWOWD;;;WD)"
    sec = security.descriptor.from_sddl(sddl, domain_sid)
    return ndr_pack(sec)

DEFAULTSITE = "Default-First-Site-Name"

# Exception classes

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


class ProvisionNames(object):
    def __init__(self):
        self.rootdn = None
        self.domaindn = None
        self.configdn = None
        self.schemadn = None
        self.ldapmanagerdn = None
        self.dnsdomain = None
        self.realm = None
        self.netbiosname = None
        self.domain = None
        self.hostname = None
        self.sitename = None
        self.smbconf = None
    

class ProvisionResult(object):
    def __init__(self):
        self.paths = None
        self.domaindn = None
        self.lp = None
        self.samdb = None

def check_install(lp, session_info, credentials):
    """Check whether the current install seems ok.
    
    :param lp: Loadparm context
    :param session_info: Session information
    :param credentials: Credentials
    """
    if lp.get("realm") == "":
        raise Exception("Realm empty")
    ldb = Ldb(lp.get("sam database"), session_info=session_info, 
            credentials=credentials, lp=lp)
    if len(ldb.search("(cn=Administrator)")) != 1:
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
    raise KeyError("Unable to find user/group %r" % names)


findnss_uid = lambda names: findnss(pwd.getpwnam, names)[2]
findnss_gid = lambda names: findnss(grp.getgrnam, names)[2]


def setup_add_ldif(ldb, ldif_path, subst_vars=None,controls=["relax:0"]):
    """Setup a ldb in the private dir.
    
    :param ldb: LDB file to import data into
    :param ldif_path: Path of the LDIF file to load
    :param subst_vars: Optional variables to subsitute in LDIF.
    :param nocontrols: Optional list of controls, can be None for no controls
    """
    assert isinstance(ldif_path, str)
    data = read_and_sub_file(ldif_path, subst_vars)
    ldb.add_ldif(data,controls)


def setup_modify_ldif(ldb, ldif_path, subst_vars=None):
    """Modify a ldb in the private dir.
    
    :param ldb: LDB object.
    :param ldif_path: LDIF file path.
    :param subst_vars: Optional dictionary with substitution variables.
    """
    data = read_and_sub_file(ldif_path, subst_vars)

    ldb.modify_ldif(data)


def setup_ldb(ldb, ldif_path, subst_vars):
    """Import a LDIF a file into a LDB handle, optionally substituting variables.

    :note: Either all LDIF data will be added or none (using transactions).

    :param ldb: LDB file to import into.
    :param ldif_path: Path to the LDIF file.
    :param subst_vars: Dictionary with substitution variables.
    """
    assert ldb is not None
    ldb.transaction_start()
    try:
        setup_add_ldif(ldb, ldif_path, subst_vars)
    except:
        ldb.transaction_cancel()
        raise
    ldb.transaction_commit()


def provision_paths_from_lp(lp, dnsdomain):
    """Set the default paths for provisioning.

    :param lp: Loadparm context.
    :param dnsdomain: DNS Domain name
    """
    paths = ProvisionPaths()
    paths.private_dir = lp.get("private dir")
    paths.dns_keytab = "dns.keytab"

    paths.shareconf = os.path.join(paths.private_dir, "share.ldb")
    paths.samdb = os.path.join(paths.private_dir, lp.get("sam database") or "samdb.ldb")
    paths.idmapdb = os.path.join(paths.private_dir, lp.get("idmap database") or "idmap.ldb")
    paths.secrets = os.path.join(paths.private_dir, lp.get("secrets database") or "secrets.ldb")
    paths.privilege = os.path.join(paths.private_dir, "privilege.ldb")
    paths.dns = os.path.join(paths.private_dir, "dns", dnsdomain + ".zone")
    paths.dns_update_list = os.path.join(paths.private_dir, "dns_update_list")
    paths.namedconf = os.path.join(paths.private_dir, "named.conf")
    paths.namedconf_update = os.path.join(paths.private_dir, "named.conf.update")
    paths.namedtxt = os.path.join(paths.private_dir, "named.txt")
    paths.krb5conf = os.path.join(paths.private_dir, "krb5.conf")
    paths.winsdb = os.path.join(paths.private_dir, "wins.ldb")
    paths.s4_ldapi_path = os.path.join(paths.private_dir, "ldapi")
    paths.phpldapadminconfig = os.path.join(paths.private_dir, 
                                            "phpldapadmin-config.php")
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


def guess_names(lp=None, hostname=None, domain=None, dnsdomain=None,
                serverrole=None, rootdn=None, domaindn=None, configdn=None,
                schemadn=None, serverdn=None, sitename=None):
    """Guess configuration settings to use."""

    if hostname is None:
        hostname = socket.gethostname().split(".")[0]

    netbiosname = lp.get("netbios name")
    if netbiosname is None:
        netbiosname = hostname
    assert netbiosname is not None
    netbiosname = netbiosname.upper()
    if not valid_netbios_name(netbiosname):
        raise InvalidNetbiosName(netbiosname)

    if dnsdomain is None:
        dnsdomain = lp.get("realm")
        if dnsdomain is None or dnsdomain == "":
            raise ProvisioningError("guess_names: 'realm' not specified in supplied smb.conf!")

    dnsdomain = dnsdomain.lower()

    if serverrole is None:
        serverrole = lp.get("server role")
        if serverrole is None:
            raise ProvisioningError("guess_names: 'server role' not specified in supplied smb.conf!")

    serverrole = serverrole.lower()

    realm = dnsdomain.upper()

    if lp.get("realm").upper() != realm:
        raise ProvisioningError("guess_names: Realm '%s' in smb.conf must match chosen realm '%s'!", lp.get("realm").upper(), realm)

    if lp.get("server role").lower() != serverrole:
        raise ProvisioningError("guess_names: server role '%s' in smb.conf must match chosen server role '%s'!", lp.get("server role").upper(), serverrole)

    if serverrole == "domain controller":
        if domain is None:
            domain = lp.get("workgroup")
        if domain is None:
            raise ProvisioningError("guess_names: 'workgroup' not specified in supplied smb.conf!")
        domain = domain.upper()

        if lp.get("workgroup").upper() != domain:
            raise ProvisioningError("guess_names: Workgroup '%s' in smb.conf must match chosen domain '%s'!", lp.get("workgroup").upper(), domain)

        if domaindn is None:
            domaindn = "DC=" + dnsdomain.replace(".", ",DC=")
    else:
        domain = netbiosname
        if domaindn is None:
            domaindn = "DC=" + netbiosname
        
    if not valid_netbios_name(domain):
        raise InvalidNetbiosName(domain)
        
    if hostname.upper() == realm:
        raise ProvisioningError("guess_names: Realm '%s' must not be equal to hostname '%s'!", realm, hostname)
    if netbiosname == realm:
        raise ProvisioningError("guess_names: Realm '%s' must not be equal to netbios hostname '%s'!", realm, netbiosname)
    if domain == realm:
        raise ProvisioningError("guess_names: Realm '%s' must not be equal to short domain name '%s'!", realm, domain)

    if rootdn is None:
       rootdn = domaindn
       
    if configdn is None:
        configdn = "CN=Configuration," + rootdn
    if schemadn is None:
        schemadn = "CN=Schema," + configdn

    if sitename is None:
        sitename=DEFAULTSITE

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
    names.serverdn = "CN=%s,CN=Servers,CN=%s,CN=Sites,%s" % (netbiosname, sitename, configdn)
 
    return names
    

def make_smbconf(smbconf, setup_path, hostname, domain, realm, serverrole, 
                 targetdir, sid_generator,eadb):
    """Create a new smb.conf file based on a couple of basic settings.
    """
    assert smbconf is not None
    if hostname is None:
        hostname = socket.gethostname().split(".")[0]
    netbiosname = hostname.upper()

    if serverrole is None:
        serverrole = "standalone"

    assert serverrole in ("domain controller", "member server", "standalone")
    if serverrole == "domain controller":
        smbconfsuffix = "dc"
    elif serverrole == "member server":
        smbconfsuffix = "member"
    elif serverrole == "standalone":
        smbconfsuffix = "standalone"

    if sid_generator is None:
        sid_generator = "internal"

    assert domain is not None
    domain = domain.upper()

    assert realm is not None
    realm = realm.upper()

    default_lp = param.LoadParm()
    #Load non-existant file
    if os.path.exists(smbconf):
        default_lp.load(smbconf)
    if eadb:
        if targetdir is not None:
            privdir = os.path.join(targetdir, "private")
        else:
            privdir = default_lp.get("private dir")
        posixeadb_line = "posix:eadb = " + os.path.abspath(os.path.join(privdir,"eadb.tdb"))
    else:
        posixeadb_line = ""

    if targetdir is not None:
        privatedir_line = "private dir = " + os.path.abspath(os.path.join(targetdir, "private"))
        lockdir_line = "lock dir = " + os.path.abspath(targetdir)

        default_lp.set("lock dir", os.path.abspath(targetdir))
    else:
        privatedir_line = ""
        lockdir_line = ""

    if sid_generator == "internal":
        sid_generator_line = ""
    else:
        sid_generator_line = "sid generator = " + sid_generator

    sysvol = os.path.join(default_lp.get("lock dir"), "sysvol")
    netlogon = os.path.join(sysvol, realm.lower(), "scripts")

    setup_file(setup_path("provision.smb.conf.%s" % smbconfsuffix), 
               smbconf, {
            "NETBIOS_NAME": netbiosname,
            "DOMAIN": domain,
            "REALM": realm,
            "SERVERROLE": serverrole,
            "NETLOGONPATH": netlogon,
            "SYSVOLPATH": sysvol,
            "SIDGENERATOR_LINE": sid_generator_line,
            "PRIVATEDIR_LINE": privatedir_line,
            "LOCKDIR_LINE": lockdir_line,
			"POSIXEADB_LINE": posixeadb_line
            })


def setup_name_mappings(samdb, idmap, sid, domaindn, root_uid, nobody_uid,
                        users_gid, wheel_gid):
    """setup reasonable name mappings for sam names to unix names.

    :param samdb: SamDB object.
    :param idmap: IDmap db object.
    :param sid: The domain sid.
    :param domaindn: The domain DN.
    :param root_uid: uid of the UNIX root user.
    :param nobody_uid: uid of the UNIX nobody user.
    :param users_gid: gid of the UNIX users group.
    :param wheel_gid: gid of the UNIX wheel group."""

    idmap.setup_name_mapping("S-1-5-7", idmap.TYPE_UID, nobody_uid)
    idmap.setup_name_mapping("S-1-5-32-544", idmap.TYPE_GID, wheel_gid)
    
    idmap.setup_name_mapping(sid + "-500", idmap.TYPE_UID, root_uid)
    idmap.setup_name_mapping(sid + "-513", idmap.TYPE_GID, users_gid)

def setup_samdb_partitions(samdb_path, setup_path, message, lp, session_info, 
                           provision_backend, names, schema,
                           serverrole, 
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
    if provision_backend.type is not "ldb":
        ldap_backend_line = "ldapBackend: %s" % provision_backend.ldapi_uri

    samdb.transaction_start()
    try:
        message("Setting up sam.ldb partitions and settings")
        setup_add_ldif(samdb, setup_path("provision_partitions.ldif"), {
                "SCHEMADN": ldb.Dn(schema.ldb, names.schemadn).get_casefold(), 
                "CONFIGDN": ldb.Dn(schema.ldb, names.configdn).get_casefold(),
                "DOMAINDN": ldb.Dn(schema.ldb, names.domaindn).get_casefold(),
                "LDAP_BACKEND_LINE": ldap_backend_line,
        })

        
        setup_add_ldif(samdb, setup_path("provision_init.ldif"), {
                "BACKEND_TYPE": provision_backend.type,
                "SERVER_ROLE": serverrole
                })

        message("Setting up sam.ldb rootDSE")
        setup_samdb_rootdse(samdb, setup_path, names)

    except:
        samdb.transaction_cancel()
        raise

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
    attrs=["whenChanged",
           "secret",
           "priorSecret",
           "priorChanged",
           "krb5Keytab",
           "privateKeytab"]
    

    msg = ldb.Message(ldb.Dn(secretsdb, "flatname=%s,cn=Primary Domains" % domain))
    msg["secureChannelType"] = str(secure_channel_type)
    msg["flatname"] = [domain]
    msg["objectClass"] = ["top", "primaryDomain"]
    if realm is not None:
      if dnsdomain is None:
        dnsdomain = realm.lower()
      msg["objectClass"] = ["top", "primaryDomain", "kerberosSecret"]
      msg["realm"] = realm
      msg["saltPrincipal"] = "host/%s.%s@%s" % (netbiosname.lower(), dnsdomain.lower(), realm.upper())
      msg["msDS-KeyVersionNumber"] = [str(key_version_number)]
      msg["privateKeytab"] = ["secrets.keytab"]


    msg["secret"] = [machinepass]
    msg["samAccountName"] = ["%s$" % netbiosname]
    msg["secureChannelType"] = [str(secure_channel_type)]
    if domainsid is not None:
        msg["objectSid"] = [ndr_pack(domainsid)]
    
    res = secretsdb.search(base="cn=Primary Domains", 
                           attrs=attrs, 
                           expression=("(&(|(flatname=%s)(realm=%s)(objectSid=%s))(objectclass=primaryDomain))" % (domain, realm, str(domainsid))), 
                           scope=ldb.SCOPE_ONELEVEL)
    
    for del_msg in res:
      if del_msg.dn is not msg.dn:
        secretsdb.delete(del_msg.dn)

    res = secretsdb.search(base=msg.dn, attrs=attrs, scope=ldb.SCOPE_BASE)

    if len(res) == 1:
      msg["priorSecret"] = res[0]["secret"]
      msg["priorWhenChanged"] = res[0]["whenChanged"]

      if res["privateKeytab"] is not None:
        msg["privateKeytab"] = res[0]["privateKeytab"]

      if res["krb5Keytab"] is not None:
        msg["krb5Keytab"] = res[0]["krb5Keytab"]

      for el in msg:
        el.set_flags(ldb.FLAG_MOD_REPLACE)
        secretsdb.modify(msg)
    else:
      secretsdb.add(msg)


def secretsdb_setup_dns(secretsdb, setup_path, private_dir,
                        realm, dnsdomain,
                        dns_keytab_path, dnspass):
    """Add DNS specific bits to a secrets database.
    
    :param secretsdb: Ldb Handle to the secrets database
    :param setup_path: Setup path function
    :param machinepass: Machine password
    """
    try:
        os.unlink(os.path.join(private_dir, dns_keytab_path))
    except OSError:
        pass

    setup_ldb(secretsdb, setup_path("secrets_dns.ldif"), { 
            "REALM": realm,
            "DNSDOMAIN": dnsdomain,
            "DNS_KEYTAB": dns_keytab_path,
            "DNSPASS_B64": b64encode(dnspass),
            })


def setup_secretsdb(path, setup_path, session_info, backend_credentials, lp):
    """Setup the secrets database.

    :param path: Path to the secrets database.
    :param setup_path: Get the path to a setup file.
    :param session_info: Session info.
    :param credentials: Credentials
    :param lp: Loadparm context
    :return: LDB handle for the created secrets database
    """
    if os.path.exists(path):
        os.unlink(path)
    secrets_ldb = Ldb(path, session_info=session_info, 
                      lp=lp)
    secrets_ldb.erase()
    secrets_ldb.load_ldif_file_add(setup_path("secrets_init.ldif"))
    secrets_ldb = Ldb(path, session_info=session_info, 
                      lp=lp)
    secrets_ldb.transaction_start()
    secrets_ldb.load_ldif_file_add(setup_path("secrets.ldif"))

    if backend_credentials is not None and backend_credentials.authentication_requested():
        if backend_credentials.get_bind_dn() is not None:
            setup_add_ldif(secrets_ldb, setup_path("secrets_simple_ldap.ldif"), {
                    "LDAPMANAGERDN": backend_credentials.get_bind_dn(),
                    "LDAPMANAGERPASS_B64": b64encode(backend_credentials.get_password())
                    })
        else:
            setup_add_ldif(secrets_ldb, setup_path("secrets_sasl_ldap.ldif"), {
                    "LDAPADMINUSER": backend_credentials.get_username(),
                    "LDAPADMINREALM": backend_credentials.get_realm(),
                    "LDAPADMINPASS_B64": b64encode(backend_credentials.get_password())
                    })

    return secrets_ldb

def setup_privileges(path, setup_path, session_info, lp):
    """Setup the privileges database.

    :param path: Path to the privileges database.
    :param setup_path: Get the path to a setup file.
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


def setup_registry(path, setup_path, session_info, lp):
    """Setup the registry.
    
    :param path: Path to the registry database
    :param setup_path: Function that returns the path to a setup.
    :param session_info: Session information
    :param credentials: Credentials
    :param lp: Loadparm context
    """
    reg = registry.Registry()
    hive = registry.open_ldb(path, session_info=session_info, 
                         lp_ctx=lp)
    reg.mount_hive(hive, registry.HKEY_LOCAL_MACHINE)
    provision_reg = setup_path("provision.reg")
    assert os.path.exists(provision_reg)
    reg.diff_apply(provision_reg)


def setup_idmapdb(path, setup_path, session_info, lp):
    """Setup the idmap database.

    :param path: path to the idmap database
    :param setup_path: Function that returns a path to a setup file
    :param session_info: Session information
    :param credentials: Credentials
    :param lp: Loadparm context
    """
    if os.path.exists(path):
        os.unlink(path)

    idmap_ldb = IDmapDB(path, session_info=session_info,
                        lp=lp)

    idmap_ldb.erase()
    idmap_ldb.load_ldif_file_add(setup_path("idmap_init.ldif"))
    return idmap_ldb


def setup_samdb_rootdse(samdb, setup_path, names):
    """Setup the SamDB rootdse.

    :param samdb: Sam Database handle
    :param setup_path: Obtain setup path
    """
    setup_add_ldif(samdb, setup_path("provision_rootdse_add.ldif"), {
        "SCHEMADN": names.schemadn, 
        "NETBIOSNAME": names.netbiosname,
        "DNSDOMAIN": names.dnsdomain,
        "REALM": names.realm,
        "DNSNAME": "%s.%s" % (names.hostname, names.dnsdomain),
        "DOMAINDN": names.domaindn,
        "ROOTDN": names.rootdn,
        "CONFIGDN": names.configdn,
        "SERVERDN": names.serverdn,
        })
        

def setup_self_join(samdb, names,
                    machinepass, dnspass, 
                    domainsid, invocationid, setup_path,
                    policyguid, policyguid_dc, domainControllerFunctionality,
                    ntdsguid):
    """Join a host to its own domain."""
    assert isinstance(invocationid, str)
    if ntdsguid is not None:
        ntdsguid_line = "objectGUID: %s\n"%ntdsguid
    else:
        ntdsguid_line = ""
    setup_add_ldif(samdb, setup_path("provision_self_join.ldif"), { 
              "CONFIGDN": names.configdn, 
              "SCHEMADN": names.schemadn,
              "DOMAINDN": names.domaindn,
              "SERVERDN": names.serverdn,
              "INVOCATIONID": invocationid,
              "NETBIOSNAME": names.netbiosname,
              "DEFAULTSITE": names.sitename,
              "DNSNAME": "%s.%s" % (names.hostname, names.dnsdomain),
              "MACHINEPASS_B64": b64encode(machinepass),
              "REALM": names.realm,
              "DOMAIN": names.domain,
              "DOMAINSID": str(domainsid),
              "DNSDOMAIN": names.dnsdomain,
              "SAMBA_VERSION_STRING": version,
              "NTDSGUID": ntdsguid_line,
              "DOMAIN_CONTROLLER_FUNCTIONALITY": str(domainControllerFunctionality)})

    setup_add_ldif(samdb, setup_path("provision_group_policy.ldif"), { 
              "POLICYGUID": policyguid,
              "POLICYGUID_DC": policyguid_dc,
              "DNSDOMAIN": names.dnsdomain,
              "DOMAINSID": str(domainsid),
              "DOMAINDN": names.domaindn})
    
    # add the NTDSGUID based SPNs
    ntds_dn = "CN=NTDS Settings,CN=%s,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,%s" % (names.hostname, names.domaindn)
    names.ntdsguid = samdb.searchone(basedn=ntds_dn, attribute="objectGUID",
                                     expression="", scope=ldb.SCOPE_BASE)
    assert isinstance(names.ntdsguid, str)

    # Setup fSMORoleOwner entries to point at the newly created DC entry
    setup_modify_ldif(samdb, setup_path("provision_self_join_modify.ldif"), {
              "DOMAIN": names.domain,
              "DNSDOMAIN": names.dnsdomain,
              "DOMAINDN": names.domaindn,
              "CONFIGDN": names.configdn,
              "SCHEMADN": names.schemadn, 
              "DEFAULTSITE": names.sitename,
              "SERVERDN": names.serverdn,
              "NETBIOSNAME": names.netbiosname,
              "NTDSGUID": names.ntdsguid,
              "DNSPASS_B64": b64encode(dnspass),
              })


def setup_gpo(paths,names,samdb,policyguid,policyguid_dc,domainsid):
    policy_path = os.path.join(paths.sysvol, names.dnsdomain, "Policies",
                               "{" + policyguid + "}")
    os.makedirs(policy_path, 0755)
    open(os.path.join(policy_path, "GPT.INI"), 'w').write(
                      "[General]\r\nVersion=65543")
    os.makedirs(os.path.join(policy_path, "MACHINE"), 0755)
    os.makedirs(os.path.join(policy_path, "USER"), 0755)

    policy_path_dc = os.path.join(paths.sysvol, names.dnsdomain, "Policies",
                                  "{" + policyguid_dc + "}")
    os.makedirs(policy_path_dc, 0755)
    open(os.path.join(policy_path_dc, "GPT.INI"), 'w').write(
                      "[General]\r\nVersion=2")
    os.makedirs(os.path.join(policy_path_dc, "MACHINE"), 0755)
    os.makedirs(os.path.join(policy_path_dc, "USER"), 0755)


def setup_samdb(path, setup_path, session_info, provision_backend, lp, 
                names, message, 
                domainsid, domainguid, policyguid, policyguid_dc,
                fill, adminpass, krbtgtpass, 
                machinepass, invocationid, dnspass, ntdsguid,
                serverrole, dom_for_fun_level=None,
                schema=None):
    """Setup a complete SAM Database.
    
    :note: This will wipe the main SAM database file!
    """

    # ATTENTION: Do NOT change these default values without discussion with the
    # team and/or release manager. They have a big impact on the whole program!
    domainControllerFunctionality = DS_DC_FUNCTION_2008

    if dom_for_fun_level is None:
        dom_for_fun_level = DS_DOMAIN_FUNCTION_2003
    if dom_for_fun_level < DS_DOMAIN_FUNCTION_2003:
        message("You want to run SAMBA 4 on a domain and forest function level lower than Windows 2003 (Native). This is not recommended")

    if dom_for_fun_level > domainControllerFunctionality:
        raise ProvisioningError("You want to run SAMBA 4 on a domain and forest function level which itself is higher than its actual DC function level (2008). This won't work!")

    domainFunctionality = dom_for_fun_level
    forestFunctionality = dom_for_fun_level

    # Also wipes the database
    setup_samdb_partitions(path, setup_path, message=message, lp=lp,
                           provision_backend=provision_backend, session_info=session_info,
                           names=names, 
                           serverrole=serverrole, schema=schema)

    if (schema == None):
        schema = Schema(setup_path, domainsid, schemadn=names.schemadn, serverdn=names.serverdn)

    # Load the database, but importantly, use Ldb not SamDB as we don't want to load the global schema
    samdb = Ldb(session_info=session_info, 
                credentials=provision_backend.credentials, lp=lp)

    message("Pre-loading the Samba 4 and AD schema")

    # Load the schema from the one we computed earlier
    samdb.set_schema_from_ldb(schema.ldb)

    # And now we can connect to the DB - the schema won't be loaded from the DB
    samdb.connect(path)

    if fill == FILL_DRS:
        return samdb
        
    samdb.transaction_start()
    try:
        # Set the domain functionality levels onto the database.
        # Various module (the password_hash module in particular) need
        # to know what level of AD we are emulating.

        # These will be fixed into the database via the database
        # modifictions below, but we need them set from the start.
        samdb.set_opaque_integer("domainFunctionality", domainFunctionality)
        samdb.set_opaque_integer("forestFunctionality", forestFunctionality)
        samdb.set_opaque_integer("domainControllerFunctionality", domainControllerFunctionality)

        samdb.set_domain_sid(str(domainsid))
        samdb.set_invocation_id(invocationid)

        message("Adding DomainDN: %s" % names.domaindn)

#impersonate domain admin
        admin_session_info = admin_session(lp, str(domainsid))
        samdb.set_session_info(admin_session_info)
        if domainguid is not None:
            domainguid_line = "objectGUID: %s\n-" % domainguid
        else:
            domainguid_line = ""

        descr = b64encode(get_domain_descriptor(domainsid))
        setup_add_ldif(samdb, setup_path("provision_basedn.ldif"), {
                "DOMAINDN": names.domaindn,
                "DOMAINGUID": domainguid_line,
                "DESCRIPTOR": descr
                })


        setup_modify_ldif(samdb, setup_path("provision_basedn_modify.ldif"), {
            "CREATTIME": str(int(time.time() * 1e7)), # seconds -> ticks
            "DOMAINSID": str(domainsid),
            "SCHEMADN": names.schemadn, 
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "SERVERDN": names.serverdn,
            "POLICYGUID": policyguid,
            "DOMAINDN": names.domaindn,
            "DOMAIN_FUNCTIONALITY": str(domainFunctionality),
            "SAMBA_VERSION_STRING": version
            })

        message("Adding configuration container")
        descr = b64encode(get_config_descriptor(domainsid))
        setup_add_ldif(samdb, setup_path("provision_configuration_basedn.ldif"), {
            "CONFIGDN": names.configdn, 
            "DESCRIPTOR": descr,
            })

        # The LDIF here was created when the Schema object was constructed
        message("Setting up sam.ldb schema")
        samdb.add_ldif(schema.schema_dn_add, controls=["relax:0"])
        samdb.modify_ldif(schema.schema_dn_modify)
        samdb.write_prefixes_from_schema()
        samdb.add_ldif(schema.schema_data, controls=["relax:0"])
        setup_add_ldif(samdb, setup_path("aggregate_schema.ldif"), 
                       {"SCHEMADN": names.schemadn})

        message("Reopening sam.ldb with new schema")
        samdb.transaction_commit()
        samdb = Ldb(session_info=admin_session_info,
                    credentials=provision_backend.credentials, lp=lp)
        samdb.connect(path)
        samdb.transaction_start()
        samdb.set_invocation_id(invocationid)

        message("Setting up sam.ldb configuration data")
        setup_add_ldif(samdb, setup_path("provision_configuration.ldif"), {
            "CONFIGDN": names.configdn,
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "DNSDOMAIN": names.dnsdomain,
            "DOMAIN": names.domain,
            "SCHEMADN": names.schemadn,
            "DOMAINDN": names.domaindn,
            "SERVERDN": names.serverdn,
            "FOREST_FUNCTIONALALITY": str(forestFunctionality)
            })

        message("Setting up display specifiers")
        display_specifiers_ldif = read_ms_ldif(setup_path('display-specifiers/DisplaySpecifiers-Win2k8R2.txt'))
        display_specifiers_ldif = substitute_var(display_specifiers_ldif, {"CONFIGDN": names.configdn})
        check_all_substituted(display_specifiers_ldif)
        samdb.add_ldif(display_specifiers_ldif)

        message("Adding users container")
        setup_add_ldif(samdb, setup_path("provision_users_add.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Modifying users container")
        setup_modify_ldif(samdb, setup_path("provision_users_modify.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Adding computers container")
        setup_add_ldif(samdb, setup_path("provision_computers_add.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Modifying computers container")
        setup_modify_ldif(samdb, setup_path("provision_computers_modify.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Setting up sam.ldb data")
        setup_add_ldif(samdb, setup_path("provision.ldif"), {
            "CREATTIME": str(int(time.time() * 1e7)), # seconds -> ticks
            "DOMAINDN": names.domaindn,
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "SERVERDN": names.serverdn,
            "POLICYGUID_DC": policyguid_dc
            })

        setup_modify_ldif(samdb, setup_path("provision_basedn_references.ldif"), {
                "DOMAINDN": names.domaindn})

        setup_modify_ldif(samdb, setup_path("provision_configuration_references.ldif"), {
                "CONFIGDN": names.configdn,
                "SCHEMADN": names.schemadn})
        if fill == FILL_FULL:
            message("Setting up sam.ldb users and groups")
            setup_add_ldif(samdb, setup_path("provision_users.ldif"), {
                "DOMAINDN": names.domaindn,
                "DOMAINSID": str(domainsid),
                "CONFIGDN": names.configdn,
                "ADMINPASS_B64": b64encode(adminpass),
                "KRBTGTPASS_B64": b64encode(krbtgtpass),
                })

            message("Setting up self join")
            setup_self_join(samdb, names=names, invocationid=invocationid,
                            dnspass=dnspass,
                            machinepass=machinepass,
                            domainsid=domainsid, policyguid=policyguid,
                            policyguid_dc=policyguid_dc,
                            setup_path=setup_path,
                            domainControllerFunctionality=domainControllerFunctionality,
                            ntdsguid=ntdsguid)

            ntds_dn = "CN=NTDS Settings,CN=%s,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,%s" % (names.hostname, names.domaindn)
            names.ntdsguid = samdb.searchone(basedn=ntds_dn,
                attribute="objectGUID", expression="", scope=ldb.SCOPE_BASE)
            assert isinstance(names.ntdsguid, str)

    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()
    return samdb


FILL_FULL = "FULL"
FILL_NT4SYNC = "NT4SYNC"
FILL_DRS = "DRS"
SYSVOL_ACL = "O:LAG:BAD:P(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001200a9;;;SO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)"
POLICIES_ACL = "O:LAG:BAD:P(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001200a9;;;SO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)(A;OICI;0x001301bf;;;PA)"

def set_gpo_acl(path,acl,lp,domsid):
	setntacl(lp,path,acl,domsid)
	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			setntacl(lp,os.path.join(root, name),acl,domsid)
		for name in dirs:
			setntacl(lp,os.path.join(root, name),acl,domsid)

def setsysvolacl(samdb,names,netlogon,sysvol,gid,domainsid,lp):
	canchown = 1
	try:
		os.chown(sysvol,-1,gid)
	except:
		canchown = 0

	setntacl(lp,sysvol,SYSVOL_ACL,str(domainsid))
	for root, dirs, files in os.walk(sysvol, topdown=False):
		for name in files:
			if canchown:
				os.chown(os.path.join(root, name),-1,gid)
			setntacl(lp,os.path.join(root, name),SYSVOL_ACL,str(domainsid))
		for name in dirs:
			if canchown:
				os.chown(os.path.join(root, name),-1,gid)
			setntacl(lp,os.path.join(root, name),SYSVOL_ACL,str(domainsid))

	# Set ACL for GPO
	policy_path = os.path.join(sysvol, names.dnsdomain, "Policies")
	set_gpo_acl(policy_path,dsacl2fsacl(POLICIES_ACL,str(domainsid)),lp,str(domainsid))
	res = samdb.search(base="CN=Policies,CN=System,%s"%(names.domaindn),
						attrs=["cn","nTSecurityDescriptor"],
						expression="", scope=ldb.SCOPE_ONELEVEL)
	for policy in res:
		acl = ndr_unpack(security.descriptor,str(policy["nTSecurityDescriptor"])).as_sddl()
		policy_path = os.path.join(sysvol, names.dnsdomain, "Policies",
									 str(policy["cn"]))
		set_gpo_acl(policy_path,dsacl2fsacl(acl,str(domainsid)),lp,str(domainsid))



def provision(setup_dir, message, session_info, 
              credentials, smbconf=None, targetdir=None, samdb_fill=FILL_FULL,
              realm=None, 
              rootdn=None, domaindn=None, schemadn=None, configdn=None, 
              serverdn=None,
              domain=None, hostname=None, hostip=None, hostip6=None, 
              domainsid=None, adminpass=None, ldapadminpass=None, 
              krbtgtpass=None, domainguid=None, 
              policyguid=None, policyguid_dc=None, invocationid=None,
              machinepass=None, ntdsguid=None,
              dnspass=None, root=None, nobody=None, users=None, 
              wheel=None, backup=None, aci=None, serverrole=None,
              dom_for_fun_level=None,
              ldap_backend_extra_port=None, backend_type=None,
              sitename=None,
              ol_mmr_urls=None, ol_olc=None, 
              setup_ds_path=None, slapd_path=None, nosync=False,
              ldap_dryrun_mode=False,useeadb=False):
    """Provision samba4
    
    :note: caution, this wipes all existing data!
    """

    def setup_path(file):
      return os.path.join(setup_dir, file)

    if domainsid is None:
      domainsid = security.random_sid()
    else:
      domainsid = security.dom_sid(domainsid)

    # create/adapt the group policy GUIDs
    if policyguid is None:
        policyguid = str(uuid.uuid4())
    policyguid = policyguid.upper()
    if policyguid_dc is None:
        policyguid_dc = str(uuid.uuid4())
    policyguid_dc = policyguid_dc.upper()

    if adminpass is None:
        adminpass = glue.generate_random_password(12, 32)
    if krbtgtpass is None:
        krbtgtpass = glue.generate_random_password(128, 255)
    if machinepass is None:
        machinepass  = glue.generate_random_password(128, 255)
    if dnspass is None:
        dnspass = glue.generate_random_password(128, 255)
    if ldapadminpass is None:
        #Make a new, random password between Samba and it's LDAP server
        ldapadminpass=glue.generate_random_password(128, 255)

    if backend_type is None:
        backend_type = "ldb"

    sid_generator = "internal"
    if backend_type == "fedora-ds":
        sid_generator = "backend"

    root_uid = findnss_uid([root or "root"])
    nobody_uid = findnss_uid([nobody or "nobody"])
    users_gid = findnss_gid([users or "users"])
    if wheel is None:
        wheel_gid = findnss_gid(["wheel", "adm"])
    else:
        wheel_gid = findnss_gid([wheel])
    try:
        bind_gid = findnss_gid(["bind", "named"])
    except KeyError:
        bind_gid = None

    if targetdir is not None:
        if (not os.path.exists(os.path.join(targetdir, "etc"))):
            os.makedirs(os.path.join(targetdir, "etc"))
        smbconf = os.path.join(targetdir, "etc", "smb.conf")
    elif smbconf is None:
        smbconf = param.default_path()

    # only install a new smb.conf if there isn't one there already
    if os.path.exists(smbconf):
        # if Samba Team members can't figure out the weird errors
        # loading an empty smb.conf gives, then we need to be smarter.
        # Pretend it just didn't exist --abartlet
        data = open(smbconf, 'r').read()
        data = data.lstrip()
        if data is None or data == "":
            make_smbconf(smbconf, setup_path, hostname, domain, realm, serverrole, 
                         targetdir, sid_generator, useeadb)
    else: 
        make_smbconf(smbconf, setup_path, hostname, domain, realm, serverrole, 
                     targetdir, sid_generator, useeadb)

    lp = param.LoadParm()
    lp.load(smbconf)

    names = guess_names(lp=lp, hostname=hostname, domain=domain,
                        dnsdomain=realm, serverrole=serverrole,
                        domaindn=domaindn, configdn=configdn, schemadn=schemadn,
                        serverdn=serverdn, sitename=sitename)

    paths = provision_paths_from_lp(lp, names.dnsdomain)

    paths.bind_gid = bind_gid

    if hostip is None:
        try:
            for ip in socket.getaddrinfo(names.hostname, None, socket.AF_INET, socket.AI_CANONNAME, socket.IPPROTO_IP):
                if hostip is None:
                    hostip = ip[-1][0]
                if hostip.startswith('127.0.0.') and (not ip[-1][0].startswith('127.0.0.')):
                    hostip = ip[-1][0]
        except socket.gaierror, (socket.EAI_NODATA, msg):
            hostip = None

    if hostip6 is None:
        try:
            for ip in socket.getaddrinfo(names.hostname, None, socket.AF_INET6, socket.AI_CANONNAME, socket.IPPROTO_IP):
                if hostip6 is None:
                    hostip6 = ip[-1][0]
                if hostip6 == '::1' and ip[-1][0] != '::1':
                    hostip6 = ip[-1][0]
        except socket.gaierror, (socket.EAI_NODATA, msg): 
            hostip6 = None

    if serverrole is None:
        serverrole = lp.get("server role")

    assert serverrole in ("domain controller", "member server", "standalone")
    if invocationid is None:
        invocationid = str(uuid.uuid4())

    if not os.path.exists(paths.private_dir):
        os.mkdir(paths.private_dir)
    if not os.path.exists(os.path.join(paths.private_dir,"tls")):
        os.mkdir(os.path.join(paths.private_dir,"tls"))

    ldapi_url = "ldapi://%s" % urllib.quote(paths.s4_ldapi_path, safe="")
 
    schema = Schema(setup_path, domainsid, schemadn=names.schemadn, serverdn=names.serverdn)
    
    if backend_type == "ldb":
        provision_backend = LDBBackend(backend_type,
                                         paths=paths, setup_path=setup_path,
                                         lp=lp, credentials=credentials, 
                                         names=names,
                                         message=message)
    elif backend_type == "existing":
        provision_backend = ExistingBackend(backend_type,
                                         paths=paths, setup_path=setup_path,
                                         lp=lp, credentials=credentials, 
                                         names=names,
                                         message=message,
                                         ldapi_url=ldapi_url)
    elif backend_type == "fedora-ds":
        provision_backend = FDSBackend(backend_type,
                                         paths=paths, setup_path=setup_path,
                                         lp=lp, credentials=credentials, 
                                         names=names,
                                         message=message,
                                         domainsid=domainsid,
                                         schema=schema,
                                         hostname=hostname,
                                         ldapadminpass=ldapadminpass,
                                         slapd_path=slapd_path,
                                         ldap_backend_extra_port=ldap_backend_extra_port,
                                         ldap_dryrun_mode=ldap_dryrun_mode,
                                         root=root,
                                         setup_ds_path=setup_ds_path)
    elif backend_type == "openldap":
        provision_backend = OpenLDAPBackend(backend_type,
                                         paths=paths, setup_path=setup_path,
                                         lp=lp, credentials=credentials, 
                                         names=names,
                                         message=message,
                                         domainsid=domainsid,
                                         schema=schema,
                                         hostname=hostname,
                                         ldapadminpass=ldapadminpass,
                                         slapd_path=slapd_path,
                                         ldap_backend_extra_port=ldap_backend_extra_port,
                                         ldap_dryrun_mode=ldap_dryrun_mode,
                                         ol_mmr_urls=ol_mmr_urls, 
                                         nosync=nosync)
    else:
        raise ProvisioningError("Unknown LDAP backend type selected")

    provision_backend.init()
    provision_backend.start()

    # only install a new shares config db if there is none
    if not os.path.exists(paths.shareconf):
        message("Setting up share.ldb")
        share_ldb = Ldb(paths.shareconf, session_info=session_info, 
                        lp=lp)
        share_ldb.load_ldif_file_add(setup_path("share.ldif"))

     
    message("Setting up secrets.ldb")
    secrets_ldb = setup_secretsdb(paths.secrets, setup_path, 
                                  session_info=session_info, 
                                  backend_credentials=provision_backend.secrets_credentials, lp=lp)

    message("Setting up the registry")
    setup_registry(paths.hklm, setup_path, session_info, 
                   lp=lp)

    message("Setting up the privileges database")
    setup_privileges(paths.privilege, setup_path, session_info, lp=lp)

    message("Setting up idmap db")
    idmap = setup_idmapdb(paths.idmapdb, setup_path, session_info=session_info,
                          lp=lp)

    message("Setting up SAM db")
    samdb = setup_samdb(paths.samdb, setup_path, session_info, 
                        provision_backend, lp, names,
                        message, 
                        domainsid=domainsid, 
                        schema=schema, domainguid=domainguid,
                        policyguid=policyguid, policyguid_dc=policyguid_dc,
                        fill=samdb_fill, 
                        adminpass=adminpass, krbtgtpass=krbtgtpass,
                        invocationid=invocationid, 
                        machinepass=machinepass, dnspass=dnspass, 
                        ntdsguid=ntdsguid, serverrole=serverrole,
                        dom_for_fun_level=dom_for_fun_level)

    if serverrole == "domain controller":
        if paths.netlogon is None:
            message("Existing smb.conf does not have a [netlogon] share, but you are configuring a DC.")
            message("Please either remove %s or see the template at %s" % 
                    ( paths.smbconf, setup_path("provision.smb.conf.dc")))
            assert(paths.netlogon is not None)

        if paths.sysvol is None:
            message("Existing smb.conf does not have a [sysvol] share, but you are configuring a DC.")
            message("Please either remove %s or see the template at %s" % 
                    (paths.smbconf, setup_path("provision.smb.conf.dc")))
            assert(paths.sysvol is not None)            
            

        if not os.path.isdir(paths.netlogon):
            os.makedirs(paths.netlogon, 0755)

    if samdb_fill == FILL_FULL:
        setup_name_mappings(samdb, idmap, str(domainsid), names.domaindn,
                            root_uid=root_uid, nobody_uid=nobody_uid,
                            users_gid=users_gid, wheel_gid=wheel_gid)

        if serverrole == "domain controller":
            # Set up group policies (domain policy and domain controller policy)
            setup_gpo(paths,names,samdb,policyguid,policyguid_dc,domainsid)
            setsysvolacl(samdb,names,paths.netlogon,paths.sysvol,wheel_gid,domainsid,lp)

        message("Setting up sam.ldb rootDSE marking as synchronized")
        setup_modify_ldif(samdb, setup_path("provision_rootdse_modify.ldif"))

        secretsdb_self_join(secrets_ldb, domain=names.domain,
                            realm=names.realm,
                            dnsdomain=names.dnsdomain,
                            netbiosname=names.netbiosname,
                            domainsid=domainsid, 
                            machinepass=machinepass,
                            secure_channel_type=SEC_CHAN_BDC)

        if serverrole == "domain controller":
            secretsdb_setup_dns(secrets_ldb, setup_path,
                                paths.private_dir,
                                realm=names.realm, dnsdomain=names.dnsdomain,
                                dns_keytab_path=paths.dns_keytab,
                                dnspass=dnspass)

            domainguid = samdb.searchone(basedn=domaindn, attribute="objectGUID")
            assert isinstance(domainguid, str)

            # Only make a zone file on the first DC, it should be replicated
            # with DNS replication
            create_zone_file(lp, message, paths, targetdir, setup_path, dnsdomain=names.dnsdomain,
                             hostip=hostip,
                             hostip6=hostip6, hostname=names.hostname,
                             realm=names.realm,
                             domainguid=domainguid, ntdsguid=names.ntdsguid)

            create_named_conf(paths, setup_path, realm=names.realm,
                              dnsdomain=names.dnsdomain, private_dir=paths.private_dir)

            create_named_txt(paths.namedtxt, setup_path, realm=names.realm,
                              dnsdomain=names.dnsdomain, private_dir=paths.private_dir,
                              keytab_name=paths.dns_keytab)
            message("See %s for an example configuration include file for BIND" % paths.namedconf)
            message("and %s for further documentation required for secure DNS updates" % paths.namedtxt)

            create_krb5_conf(paths.krb5conf, setup_path,
                             dnsdomain=names.dnsdomain, hostname=names.hostname,
                             realm=names.realm)
            message("A Kerberos configuration suitable for Samba 4 has been generated at %s" % paths.krb5conf)

    if serverrole == "domain controller":
        create_dns_update_list(lp, message, paths, setup_path)

    provision_backend.post_setup()
    provision_backend.shutdown()
    
    create_phpldapadmin_config(paths.phpldapadminconfig, setup_path, 
                               ldapi_url)

    #Now commit the secrets.ldb to disk
    secrets_ldb.transaction_commit()

    # the commit creates the dns.keytab, now chown it
    dns_keytab_path = os.path.join(paths.private_dir, paths.dns_keytab)
    if (os.path.isfile(dns_keytab_path) and paths.bind_gid is not None):
        try:
            os.chmod(dns_keytab_path, 0640)
            os.chown(dns_keytab_path, -1, paths.bind_gid)
        except OSError:
            message("Failed to chown %s to bind gid %u" % (dns_keytab_path, paths.bind_gid))


    message("Please install the phpLDAPadmin configuration located at %s into /etc/phpldapadmin/config.php" % paths.phpldapadminconfig)

    message("Once the above files are installed, your Samba4 server will be ready to use")
    message("Server Role:           %s" % serverrole)
    message("Hostname:              %s" % names.hostname)
    message("NetBIOS Domain:        %s" % names.domain)
    message("DNS Domain:            %s" % names.dnsdomain)
    message("DOMAIN SID:            %s" % str(domainsid))
    if samdb_fill == FILL_FULL:
        message("Admin password:        %s" % adminpass)
    if provision_backend.type is not "ldb":
        if provision_backend.credentials.get_bind_dn() is not None:
            message("LDAP Backend Admin DN: %s" % provision_backend.credentials.get_bind_dn())
        else:
            message("LDAP Admin User:       %s" % provision_backend.credentials.get_username())

        message("LDAP Admin Password:   %s" % provision_backend.credentials.get_password())

        if provision_backend.slapd_command_escaped is not None:
            # now display slapd_command_file.txt to show how slapd must be started next time
            message("Use later the following commandline to start slapd, then Samba:")
            message(provision_backend.slapd_command_escaped)
            message("This slapd-Commandline is also stored under: " + provision_backend.ldapdir + "/ldap_backend_startup.sh")


    result = ProvisionResult()
    result.domaindn = domaindn
    result.paths = paths
    result.lp = lp
    result.samdb = samdb
    return result



def provision_become_dc(setup_dir=None,
                        smbconf=None, targetdir=None, realm=None, 
                        rootdn=None, domaindn=None, schemadn=None,
                        configdn=None, serverdn=None,
                        domain=None, hostname=None, domainsid=None, 
                        adminpass=None, krbtgtpass=None, domainguid=None, 
                        policyguid=None, policyguid_dc=None, invocationid=None,
                        machinepass=None, 
                        dnspass=None, root=None, nobody=None, users=None, 
                        wheel=None, backup=None, serverrole=None, 
                        ldap_backend=None, ldap_backend_type=None,
                        sitename=None, debuglevel=1):

    def message(text):
        """print a message if quiet is not set."""
        print text

    glue.set_debug_level(debuglevel)

    return provision(setup_dir, message, system_session(), None,
              smbconf=smbconf, targetdir=targetdir, samdb_fill=FILL_DRS,
              realm=realm, rootdn=rootdn, domaindn=domaindn, schemadn=schemadn,
              configdn=configdn, serverdn=serverdn, domain=domain,
              hostname=hostname, hostip="127.0.0.1", domainsid=domainsid,
              machinepass=machinepass, serverrole="domain controller",
              sitename=sitename)


def create_phpldapadmin_config(path, setup_path, ldapi_uri):
    """Create a PHP LDAP admin configuration file.

    :param path: Path to write the configuration to.
    :param setup_path: Function to generate setup paths.
    """
    setup_file(setup_path("phpldapadmin-config.php"), path, 
            {"S4_LDAPI_URI": ldapi_uri})


def create_zone_file(lp, message, paths, targetdir, setup_path, dnsdomain,
                     hostip, hostip6, hostname, realm, domainguid,
                     ntdsguid):
    """Write out a DNS zone file, from the info in the current database.

    :param paths: paths object
    :param setup_path: Setup path function.
    :param dnsdomain: DNS Domain name
    :param domaindn: DN of the Domain
    :param hostip: Local IPv4 IP
    :param hostip6: Local IPv6 IP
    :param hostname: Local hostname
    :param realm: Realm name
    :param domainguid: GUID of the domain.
    :param ntdsguid: GUID of the hosts nTDSDSA record.
    """
    assert isinstance(domainguid, str)

    if hostip6 is not None:
        hostip6_base_line = "            IN AAAA    " + hostip6
        hostip6_host_line = hostname + "        IN AAAA    " + hostip6
    else:
        hostip6_base_line = ""
        hostip6_host_line = ""

    if hostip is not None:
        hostip_base_line = "            IN A    " + hostip
        hostip_host_line = hostname + "        IN A    " + hostip
    else:
        hostip_base_line = ""
        hostip_host_line = ""

    dns_dir = os.path.dirname(paths.dns)

    try:
        shutil.rmtree(dns_dir, True)
    except OSError:
        pass

    os.mkdir(dns_dir, 0775)

    # we need to freeze the zone while we update the contents
    if targetdir is None:
        rndc = ' '.join(lp.get("rndc command"))
        os.system(rndc + " freeze " + lp.get("realm"))

    setup_file(setup_path("provision.zone"), paths.dns, {
            "HOSTNAME": hostname,
            "DNSDOMAIN": dnsdomain,
            "REALM": realm,
            "HOSTIP_BASE_LINE": hostip_base_line,
            "HOSTIP_HOST_LINE": hostip_host_line,
            "DOMAINGUID": domainguid,
            "DATESTRING": time.strftime("%Y%m%d%H"),
            "DEFAULTSITE": DEFAULTSITE,
            "NTDSGUID": ntdsguid,
            "HOSTIP6_BASE_LINE": hostip6_base_line,
            "HOSTIP6_HOST_LINE": hostip6_host_line,
        })

    # note that we use no variable substitution on this file
    # the substitution is done at runtime by samba_dnsupdate
    setup_file(setup_path("dns_update_list"), paths.dns_update_list, None)

    if paths.bind_gid is not None:
        try:
            os.chown(dns_dir, -1, paths.bind_gid)
            os.chown(paths.dns, -1, paths.bind_gid)
            # chmod needed to cope with umask
            os.chmod(dns_dir, 0775)
            os.chmod(paths.dns, 0664)
        except OSError:
            message("Failed to chown %s to bind gid %u" % (dns_dir, paths.bind_gid))

    if targetdir is None:
        os.system(rndc + " unfreeze " + lp.get("realm"))


def create_dns_update_list(lp, message, paths, setup_path):
    """Write out a dns_update_list file"""
    # note that we use no variable substitution on this file
    # the substitution is done at runtime by samba_dnsupdate
    setup_file(setup_path("dns_update_list"), paths.dns_update_list, None)


def create_named_conf(paths, setup_path, realm, dnsdomain,
                      private_dir):
    """Write out a file containing zone statements suitable for inclusion in a
    named.conf file (including GSS-TSIG configuration).
    
    :param paths: all paths
    :param setup_path: Setup path function.
    :param realm: Realm name
    :param dnsdomain: DNS Domain name
    :param private_dir: Path to private directory
    :param keytab_name: File name of DNS keytab file
    """

    setup_file(setup_path("named.conf"), paths.namedconf, {
            "DNSDOMAIN": dnsdomain,
            "REALM": realm,
            "ZONE_FILE": paths.dns,
            "REALM_WC": "*." + ".".join(realm.split(".")[1:]),
            "NAMED_CONF": paths.namedconf,
            "NAMED_CONF_UPDATE": paths.namedconf_update
            })

    setup_file(setup_path("named.conf.update"), paths.namedconf_update)

def create_named_txt(path, setup_path, realm, dnsdomain,
                      private_dir, keytab_name):
    """Write out a file containing zone statements suitable for inclusion in a
    named.conf file (including GSS-TSIG configuration).
    
    :param path: Path of the new named.conf file.
    :param setup_path: Setup path function.
    :param realm: Realm name
    :param dnsdomain: DNS Domain name
    :param private_dir: Path to private directory
    :param keytab_name: File name of DNS keytab file
    """

    setup_file(setup_path("named.txt"), path, {
            "DNSDOMAIN": dnsdomain,
            "REALM": realm,
            "DNS_KEYTAB": keytab_name,
            "DNS_KEYTAB_ABS": os.path.join(private_dir, keytab_name),
            "PRIVATE_DIR": private_dir
        })

def create_krb5_conf(path, setup_path, dnsdomain, hostname, realm):
    """Write out a file containing zone statements suitable for inclusion in a
    named.conf file (including GSS-TSIG configuration).
    
    :param path: Path of the new named.conf file.
    :param setup_path: Setup path function.
    :param dnsdomain: DNS Domain name
    :param hostname: Local hostname
    :param realm: Realm name
    """

    setup_file(setup_path("krb5.conf"), path, {
            "DNSDOMAIN": dnsdomain,
            "HOSTNAME": hostname,
            "REALM": realm,
        })


