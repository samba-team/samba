#
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
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
import sys
import pwd
import grp
import time
import uuid, glue
import socket
import param
import registry
import samba
from auth import system_session
from samba import Ldb, substitute_var, valid_netbios_name, check_all_substituted
from samba.samdb import SamDB
from samba.idmap import IDmapDB
from samba.dcerpc import security
import urllib
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError, \
        timestring, CHANGETYPE_MODIFY, CHANGETYPE_NONE

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


DEFAULTSITE = "Default-First-Site-Name"

class InvalidNetbiosName(Exception):
    """A specified name was not a valid NetBIOS name."""
    def __init__(self, name):
        super(InvalidNetbiosName, self).__init__("The name '%r' is not a valid NetBIOS name" % name)


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
        self.ldapdir = None
        self.slapdconf = None
        self.modulesconf = None
        self.memberofconf = None
        self.fedoradsinf = None
        self.fedoradspartitions = None
        self.olmmron = None
        self.olmmrserveridsconf = None
        self.olmmrsyncreplconf = None
        self.olcdir = None
        self.olslaptest = None
        self.olcseedldif = None


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
        raise "No administrator account found"


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


def read_and_sub_file(file, subst_vars):
    """Read a file and sub in variables found in it
    
    :param file: File to be read (typically from setup directory)
     param subst_vars: Optional variables to subsitute in the file.
    """
    data = open(file, 'r').read()
    if subst_vars is not None:
        data = substitute_var(data, subst_vars)
    check_all_substituted(data)
    return data


def setup_add_ldif(ldb, ldif_path, subst_vars=None):
    """Setup a ldb in the private dir.
    
    :param ldb: LDB file to import data into
    :param ldif_path: Path of the LDIF file to load
    :param subst_vars: Optional variables to subsitute in LDIF.
    """
    assert isinstance(ldif_path, str)

    data = read_and_sub_file(ldif_path, subst_vars)
    ldb.add_ldif(data)


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


def setup_file(template, fname, subst_vars):
    """Setup a file in the private dir.

    :param template: Path of the template file.
    :param fname: Path of the file to create.
    :param subst_vars: Substitution variables.
    """
    f = fname

    if os.path.exists(f):
        os.unlink(f)

    data = read_and_sub_file(template, subst_vars)
    open(f, 'w').write(data)


def provision_paths_from_lp(lp, dnsdomain):
    """Set the default paths for provisioning.

    :param lp: Loadparm context.
    :param dnsdomain: DNS Domain name
    """
    paths = ProvisionPaths()
    paths.private_dir = lp.get("private dir")
    paths.keytab = "secrets.keytab"
    paths.dns_keytab = "dns.keytab"

    paths.shareconf = os.path.join(paths.private_dir, "share.ldb")
    paths.samdb = os.path.join(paths.private_dir, lp.get("sam database") or "samdb.ldb")
    paths.idmapdb = os.path.join(paths.private_dir, lp.get("idmap database") or "idmap.ldb")
    paths.secrets = os.path.join(paths.private_dir, lp.get("secrets database") or "secrets.ldb")
    paths.templates = os.path.join(paths.private_dir, "templates.ldb")
    paths.dns = os.path.join(paths.private_dir, dnsdomain + ".zone")
    paths.namedconf = os.path.join(paths.private_dir, "named.conf")
    paths.namedtxt = os.path.join(paths.private_dir, "named.txt")
    paths.krb5conf = os.path.join(paths.private_dir, "krb5.conf")
    paths.winsdb = os.path.join(paths.private_dir, "wins.ldb")
    paths.s4_ldapi_path = os.path.join(paths.private_dir, "ldapi")
    paths.phpldapadminconfig = os.path.join(paths.private_dir, 
                                            "phpldapadmin-config.php")
    paths.ldapdir = os.path.join(paths.private_dir, 
                                 "ldap")
    paths.slapdconf = os.path.join(paths.ldapdir, 
                                   "slapd.conf")
    paths.modulesconf = os.path.join(paths.ldapdir, 
                                     "modules.conf")
    paths.memberofconf = os.path.join(paths.ldapdir, 
                                      "memberof.conf")
    paths.fedoradsinf = os.path.join(paths.ldapdir, 
                                     "fedorads.inf")
    paths.fedoradspartitions = os.path.join(paths.ldapdir, 
                                            "fedorads-partitions.ldif")
    paths.olmmrserveridsconf = os.path.join(paths.ldapdir, 
                                            "mmr_serverids.conf")
    paths.olmmrsyncreplconf = os.path.join(paths.ldapdir, 
                                           "mmr_syncrepl.conf")
    paths.olcdir = os.path.join(paths.ldapdir, 
                                 "slapd.d")
    paths.olcseedldif = os.path.join(paths.ldapdir, 
                                 "olc_seed.ldif")
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


def guess_names(lp=None, hostname=None, domain=None, dnsdomain=None, serverrole=None,
                rootdn=None, domaindn=None, configdn=None, schemadn=None, serverdn=None, 
                sitename=None):
    """Guess configuration settings to use."""

    if hostname is None:
        hostname = socket.gethostname().split(".")[0].lower()

    netbiosname = hostname.upper()
    if not valid_netbios_name(netbiosname):
        raise InvalidNetbiosName(netbiosname)

    hostname = hostname.lower()

    if dnsdomain is None:
        dnsdomain = lp.get("realm")

    if serverrole is None:
        serverrole = lp.get("server role")

    assert dnsdomain is not None
    realm = dnsdomain.upper()

    if lp.get("realm").upper() != realm:
        raise Exception("realm '%s' in %s must match chosen realm '%s'" %
                        (lp.get("realm"), lp.configfile, realm))
    
    dnsdomain = dnsdomain.lower()

    if serverrole == "domain controller":
        if domain is None:
            domain = lp.get("workgroup")
        if domaindn is None:
            domaindn = "DC=" + dnsdomain.replace(".", ",DC=")
        if lp.get("workgroup").upper() != domain.upper():
            raise Exception("workgroup '%s' in smb.conf must match chosen domain '%s'",
                        lp.get("workgroup"), domain)
    else:
        domain = netbiosname
        if domaindn is None:
            domaindn = "CN=" + netbiosname
        
    assert domain is not None
    domain = domain.upper()
    if not valid_netbios_name(domain):
        raise InvalidNetbiosName(domain)
        
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
                 targetdir):
    """Create a new smb.conf file based on a couple of basic settings.
    """
    assert smbconf is not None
    if hostname is None:
        hostname = socket.gethostname().split(".")[0].lower()

    if serverrole is None:
        serverrole = "standalone"

    assert serverrole in ("domain controller", "member server", "standalone")
    if serverrole == "domain controller":
        smbconfsuffix = "dc"
    elif serverrole == "member server":
        smbconfsuffix = "member"
    elif serverrole == "standalone":
        smbconfsuffix = "standalone"

    assert domain is not None
    assert realm is not None

    default_lp = param.LoadParm()
    #Load non-existant file
    if os.path.exists(smbconf):
        default_lp.load(smbconf)
    
    if targetdir is not None:
        privatedir_line = "private dir = " + os.path.abspath(os.path.join(targetdir, "private"))
        lockdir_line = "lock dir = " + os.path.abspath(targetdir)

        default_lp.set("lock dir", os.path.abspath(targetdir))
    else:
        privatedir_line = ""
        lockdir_line = ""

    sysvol = os.path.join(default_lp.get("lock dir"), "sysvol")
    netlogon = os.path.join(sysvol, realm.lower(), "scripts")

    setup_file(setup_path("provision.smb.conf.%s" % smbconfsuffix), 
               smbconf, {
            "HOSTNAME": hostname,
            "DOMAIN": domain,
            "REALM": realm,
            "SERVERROLE": serverrole,
            "NETLOGONPATH": netlogon,
            "SYSVOLPATH": sysvol,
            "PRIVATEDIR_LINE": privatedir_line,
            "LOCKDIR_LINE": lockdir_line
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
    # add some foreign sids if they are not present already
    samdb.add_stock_foreign_sids()

    idmap.setup_name_mapping("S-1-5-7", idmap.TYPE_UID, nobody_uid)
    idmap.setup_name_mapping("S-1-5-32-544", idmap.TYPE_GID, wheel_gid)

    idmap.setup_name_mapping(sid + "-500", idmap.TYPE_UID, root_uid)
    idmap.setup_name_mapping(sid + "-513", idmap.TYPE_GID, users_gid)


def setup_samdb_partitions(samdb_path, setup_path, message, lp, session_info, 
                           credentials, names,
                           serverrole, ldap_backend=None, 
                           ldap_backend_type=None, erase=False):
    """Setup the partitions for the SAM database. 
    
    Alternatively, provision() may call this, and then populate the database.
    
    :note: This will wipe the Sam Database!
    
    :note: This function always removes the local SAM LDB file. The erase 
        parameter controls whether to erase the existing data, which 
        may not be stored locally but in LDAP.
    """
    assert session_info is not None

    try:
        samdb = SamDB(samdb_path, session_info=session_info, 
                      credentials=credentials, lp=lp)
        # Wipes the database
        samdb.erase()
    except LdbError:
        os.unlink(samdb_path)
        samdb = SamDB(samdb_path, session_info=session_info, 
                      credentials=credentials, lp=lp)
         # Wipes the database
        samdb.erase()
        

    #Add modules to the list to activate them by default
    #beware often order is important
    #
    # Some Known ordering constraints:
    # - rootdse must be first, as it makes redirects from "" -> cn=rootdse
    # - objectclass must be before password_hash, because password_hash checks
    #   that the objectclass is of type person (filled in by objectclass
    #   module when expanding the objectclass list)
    # - partition must be last
    # - each partition has its own module list then
    modules_list = ["rootdse",
                    "paged_results",
                    "ranged_results",
                    "anr",
                    "server_sort",
                    "asq",
                    "extended_dn_store",
                    "extended_dn_in",
                    "rdn_name",
                    "objectclass",
                    "samldb",
                    "kludge_acl",
                    "password_hash",
                    "operational"]
    tdb_modules_list = [
                    "subtree_rename",
                    "subtree_delete",
                    "linked_attributes",
                    "extended_dn_out_ldb"]
    modules_list2 = ["show_deleted",
                    "partition"]
 
    domaindn_ldb = "users.ldb"
    if ldap_backend is not None:
        domaindn_ldb = ldap_backend
    configdn_ldb = "configuration.ldb"
    if ldap_backend is not None:
        configdn_ldb = ldap_backend
    schemadn_ldb = "schema.ldb"
    if ldap_backend is not None:
        schema_ldb = ldap_backend
        schemadn_ldb = ldap_backend
        
    if ldap_backend_type == "fedora-ds":
        backend_modules = ["nsuniqueid", "paged_searches"]
        # We can handle linked attributes here, as we don't have directory-side subtree operations
        tdb_modules_list = ["linked_attributes", "extended_dn_out_dereference"]
    elif ldap_backend_type == "openldap":
        backend_modules = ["entryuuid", "paged_searches"]
        # OpenLDAP handles subtree renames, so we don't want to do any of these things
        tdb_modules_list = ["extended_dn_out_dereference"]
    elif ldap_backend is not None:
        raise "LDAP Backend specified, but LDAP Backend Type not specified"
    elif serverrole == "domain controller":
        backend_modules = ["repl_meta_data"]
    else:
        backend_modules = ["objectguid"]

    if tdb_modules_list is None:
        tdb_modules_list_as_string = ""
    else:
        tdb_modules_list_as_string = ","+",".join(tdb_modules_list)
        
    samdb.transaction_start()
    try:
        setup_add_ldif(samdb, setup_path("provision_partitions.ldif"), {
                "SCHEMADN": names.schemadn, 
                "SCHEMADN_LDB": schemadn_ldb,
                "SCHEMADN_MOD2": ",objectguid",
                "CONFIGDN": names.configdn,
                "CONFIGDN_LDB": configdn_ldb,
                "DOMAINDN": names.domaindn,
                "DOMAINDN_LDB": domaindn_ldb,
                "SCHEMADN_MOD": "schema_fsmo,instancetype",
                "CONFIGDN_MOD": "naming_fsmo,instancetype",
                "DOMAINDN_MOD": "pdc_fsmo,instancetype",
                "MODULES_LIST": ",".join(modules_list),
                "TDB_MODULES_LIST": tdb_modules_list_as_string,
                "MODULES_LIST2": ",".join(modules_list2),
                "BACKEND_MOD": ",".join(backend_modules),
        })

    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()
    
    samdb = SamDB(samdb_path, session_info=session_info, 
                  credentials=credentials, lp=lp)

    samdb.transaction_start()
    try:
        message("Setting up sam.ldb attributes")
        samdb.load_ldif_file_add(setup_path("provision_init.ldif"))

        message("Setting up sam.ldb rootDSE")
        setup_samdb_rootdse(samdb, setup_path, names)

        if erase:
            message("Erasing data from partitions")
            samdb.erase_partitions()

    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()
    
    return samdb


def secretsdb_become_dc(secretsdb, setup_path, domain, realm, dnsdomain, 
                        netbiosname, domainsid, keytab_path, samdb_url, 
                        dns_keytab_path, dnspass, machinepass):
    """Add DC-specific bits to a secrets database.
    
    :param secretsdb: Ldb Handle to the secrets database
    :param setup_path: Setup path function
    :param machinepass: Machine password
    """
    setup_ldb(secretsdb, setup_path("secrets_dc.ldif"), { 
            "MACHINEPASS_B64": b64encode(machinepass),
            "DOMAIN": domain,
            "REALM": realm,
            "DNSDOMAIN": dnsdomain,
            "DOMAINSID": str(domainsid),
            "SECRETS_KEYTAB": keytab_path,
            "NETBIOSNAME": netbiosname,
            "SAM_LDB": samdb_url,
            "DNS_KEYTAB": dns_keytab_path,
            "DNSPASS_B64": b64encode(dnspass),
            })


def setup_secretsdb(path, setup_path, session_info, credentials, lp):
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
    secrets_ldb = Ldb(path, session_info=session_info, credentials=credentials,
                      lp=lp)
    secrets_ldb.erase()
    secrets_ldb.load_ldif_file_add(setup_path("secrets_init.ldif"))
    secrets_ldb = Ldb(path, session_info=session_info, credentials=credentials,
                      lp=lp)
    secrets_ldb.load_ldif_file_add(setup_path("secrets.ldif"))

    if credentials is not None and credentials.authentication_requested():
        if credentials.get_bind_dn() is not None:
            setup_add_ldif(secrets_ldb, setup_path("secrets_simple_ldap.ldif"), {
                    "LDAPMANAGERDN": credentials.get_bind_dn(),
                    "LDAPMANAGERPASS_B64": b64encode(credentials.get_password())
                    })
        else:
            setup_add_ldif(secrets_ldb, setup_path("secrets_sasl_ldap.ldif"), {
                    "LDAPADMINUSER": credentials.get_username(),
                    "LDAPADMINREALM": credentials.get_realm(),
                    "LDAPADMINPASS_B64": b64encode(credentials.get_password())
                    })

    return secrets_ldb


def setup_templatesdb(path, setup_path, session_info, credentials, lp):
    """Setup the templates database.

    :param path: Path to the database.
    :param setup_path: Function for obtaining the path to setup files.
    :param session_info: Session info
    :param credentials: Credentials
    :param lp: Loadparm context
    """
    templates_ldb = SamDB(path, session_info=session_info,
                          credentials=credentials, lp=lp)
    # Wipes the database
    try:
        templates_ldb.erase()
    # This should be 'except LdbError', but on a re-provision the assert in ldb.erase fires, and we need to catch that too
    except:
        os.unlink(path)

    templates_ldb.load_ldif_file_add(setup_path("provision_templates_init.ldif"))

    templates_ldb = SamDB(path, session_info=session_info,
                          credentials=credentials, lp=lp)

    templates_ldb.load_ldif_file_add(setup_path("provision_templates.ldif"))


def setup_registry(path, setup_path, session_info, credentials, lp):
    """Setup the registry.
    
    :param path: Path to the registry database
    :param setup_path: Function that returns the path to a setup.
    :param session_info: Session information
    :param credentials: Credentials
    :param lp: Loadparm context
    """
    reg = registry.Registry()
    hive = registry.open_ldb(path, session_info=session_info, 
                         credentials=credentials, lp_ctx=lp)
    reg.mount_hive(hive, registry.HKEY_LOCAL_MACHINE)
    provision_reg = setup_path("provision.reg")
    assert os.path.exists(provision_reg)
    reg.diff_apply(provision_reg)


def setup_idmapdb(path, setup_path, session_info, credentials, lp):
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
                        credentials=credentials, lp=lp)

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
                    policyguid):
    """Join a host to its own domain."""
    assert isinstance(invocationid, str)
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
              "DNSPASS_B64": b64encode(dnspass),
              "REALM": names.realm,
              "DOMAIN": names.domain,
              "DNSDOMAIN": names.dnsdomain})
    setup_add_ldif(samdb, setup_path("provision_group_policy.ldif"), { 
              "POLICYGUID": policyguid,
              "DNSDOMAIN": names.dnsdomain,
              "DOMAINSID": str(domainsid),
              "DOMAINDN": names.domaindn})


def setup_samdb(path, setup_path, session_info, credentials, lp, 
                names, message, 
                domainsid, aci, domainguid, policyguid, 
                fill, adminpass, krbtgtpass, 
                machinepass, invocationid, dnspass,
                serverrole, ldap_backend=None, 
                ldap_backend_type=None):
    """Setup a complete SAM Database.
    
    :note: This will wipe the main SAM database file!
    """

    erase = (fill != FILL_DRS)

    # Also wipes the database
    setup_samdb_partitions(path, setup_path, message=message, lp=lp,
                           credentials=credentials, session_info=session_info,
                           names=names, 
                           ldap_backend=ldap_backend, serverrole=serverrole,
                           ldap_backend_type=ldap_backend_type, erase=erase)

    samdb = SamDB(path, session_info=session_info, 
                  credentials=credentials, lp=lp)
    if fill == FILL_DRS:
        return samdb

    message("Pre-loading the Samba 4 and AD schema")
    samdb.set_domain_sid(str(domainsid))
    if serverrole == "domain controller":
        samdb.set_invocation_id(invocationid)

    load_schema(setup_path, samdb, names.schemadn, names.netbiosname, 
                names.configdn, names.sitename, names.serverdn,
                names.hostname)

    samdb.transaction_start()
        
    try:
        message("Adding DomainDN: %s (permitted to fail)" % names.domaindn)
        if serverrole == "domain controller":
            domain_oc = "domainDNS"
        else:
            domain_oc = "samba4LocalDomain"

        setup_add_ldif(samdb, setup_path("provision_basedn.ldif"), {
                "DOMAINDN": names.domaindn,
                "ACI": aci,
                "DOMAIN_OC": domain_oc
                })

        message("Modifying DomainDN: " + names.domaindn + "")
        if domainguid is not None:
            domainguid_mod = "replace: objectGUID\nobjectGUID: %s\n-" % domainguid
        else:
            domainguid_mod = ""

        setup_modify_ldif(samdb, setup_path("provision_basedn_modify.ldif"), {
            "LDAPTIME": timestring(int(time.time())),
            "DOMAINSID": str(domainsid),
            "SCHEMADN": names.schemadn, 
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "SERVERDN": names.serverdn,
            "POLICYGUID": policyguid,
            "DOMAINDN": names.domaindn,
            "DOMAINGUID_MOD": domainguid_mod,
            })

        message("Adding configuration container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_configuration_basedn.ldif"), {
            "CONFIGDN": names.configdn, 
            "ACI": aci,
            })
        message("Modifying configuration container")
        setup_modify_ldif(samdb, setup_path("provision_configuration_basedn_modify.ldif"), {
            "CONFIGDN": names.configdn, 
            "SCHEMADN": names.schemadn,
            })

        message("Adding schema container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_schema_basedn.ldif"), {
            "SCHEMADN": names.schemadn,
            "ACI": aci,
            })
        message("Modifying schema container")

        prefixmap = open(setup_path("prefixMap.txt"), 'r').read()

        setup_modify_ldif(samdb, 
            setup_path("provision_schema_basedn_modify.ldif"), {
            "SCHEMADN": names.schemadn,
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "SERVERDN": names.serverdn,
            "PREFIXMAP_B64": b64encode(prefixmap)
            })

        message("Setting up sam.ldb Samba4 schema")
        setup_add_ldif(samdb, setup_path("schema_samba4.ldif"), 
                       {"SCHEMADN": names.schemadn })
        message("Setting up sam.ldb AD schema")
        setup_add_ldif(samdb, setup_path("schema.ldif"), 
                       {"SCHEMADN": names.schemadn})
        setup_add_ldif(samdb, setup_path("aggregate_schema.ldif"), 
                       {"SCHEMADN": names.schemadn})

        message("Setting up sam.ldb configuration data")
        setup_add_ldif(samdb, setup_path("provision_configuration.ldif"), {
            "CONFIGDN": names.configdn,
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "DNSDOMAIN": names.dnsdomain,
            "DOMAIN": names.domain,
            "SCHEMADN": names.schemadn,
            "DOMAINDN": names.domaindn,
            "SERVERDN": names.serverdn
            })

        message("Setting up display specifiers")
        setup_add_ldif(samdb, setup_path("display_specifiers.ldif"), 
                       {"CONFIGDN": names.configdn})

        message("Adding users container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_users_add.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Modifying users container")
        setup_modify_ldif(samdb, setup_path("provision_users_modify.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Adding computers container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_computers_add.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Modifying computers container")
        setup_modify_ldif(samdb, setup_path("provision_computers_modify.ldif"), {
                "DOMAINDN": names.domaindn})
        message("Setting up sam.ldb data")
        setup_add_ldif(samdb, setup_path("provision.ldif"), {
            "DOMAINDN": names.domaindn,
            "NETBIOSNAME": names.netbiosname,
            "DEFAULTSITE": names.sitename,
            "CONFIGDN": names.configdn,
            "SERVERDN": names.serverdn
            })

        if fill == FILL_FULL:
            message("Setting up sam.ldb users and groups")
            setup_add_ldif(samdb, setup_path("provision_users.ldif"), {
                "DOMAINDN": names.domaindn,
                "DOMAINSID": str(domainsid),
                "CONFIGDN": names.configdn,
                "ADMINPASS_B64": b64encode(adminpass),
                "KRBTGTPASS_B64": b64encode(krbtgtpass),
                })

            if serverrole == "domain controller":
                message("Setting up self join")
                setup_self_join(samdb, names=names, invocationid=invocationid, 
                                dnspass=dnspass,  
                                machinepass=machinepass, 
                                domainsid=domainsid, policyguid=policyguid,
                                setup_path=setup_path)

    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()
    return samdb


FILL_FULL = "FULL"
FILL_NT4SYNC = "NT4SYNC"
FILL_DRS = "DRS"

def provision(setup_dir, message, session_info, 
              credentials, smbconf=None, targetdir=None, samdb_fill=FILL_FULL, realm=None, 
              rootdn=None, domaindn=None, schemadn=None, configdn=None, 
              serverdn=None,
              domain=None, hostname=None, hostip=None, hostip6=None, 
              domainsid=None, adminpass=None, krbtgtpass=None, domainguid=None, 
              policyguid=None, invocationid=None, machinepass=None, 
              dnspass=None, root=None, nobody=None, nogroup=None, users=None, 
              wheel=None, backup=None, aci=None, serverrole=None, 
              ldap_backend=None, ldap_backend_type=None, sitename=None):
    """Provision samba4
    
    :note: caution, this wipes all existing data!
    """

    def setup_path(file):
        return os.path.join(setup_dir, file)

    if domainsid is None:
        domainsid = security.random_sid()

    if policyguid is None:
        policyguid = str(uuid.uuid4())
    if adminpass is None:
        adminpass = glue.generate_random_str(12)
    if krbtgtpass is None:
        krbtgtpass = glue.generate_random_str(12)
    if machinepass is None:
        machinepass  = glue.generate_random_str(12)
    if dnspass is None:
        dnspass = glue.generate_random_str(12)
    root_uid = findnss_uid([root or "root"])
    nobody_uid = findnss_uid([nobody or "nobody"])
    users_gid = findnss_gid([users or "users"])
    if wheel is None:
        wheel_gid = findnss_gid(["wheel", "adm"])
    else:
        wheel_gid = findnss_gid([wheel])
    if aci is None:
        aci = "# no aci for local ldb"

    if targetdir is not None:
        if (not os.path.exists(os.path.join(targetdir, "etc"))):
            os.makedirs(os.path.join(targetdir, "etc"))
        smbconf = os.path.join(targetdir, "etc", "smb.conf")
    elif smbconf is None:
        smbconf = param.default_path()

    # only install a new smb.conf if there isn't one there already
    if not os.path.exists(smbconf):
        make_smbconf(smbconf, setup_path, hostname, domain, realm, serverrole, 
                     targetdir)

    lp = param.LoadParm()
    lp.load(smbconf)

    names = guess_names(lp=lp, hostname=hostname, domain=domain, 
                        dnsdomain=realm, serverrole=serverrole, sitename=sitename,
                        rootdn=rootdn, domaindn=domaindn, configdn=configdn, schemadn=schemadn,
                        serverdn=serverdn)

    paths = provision_paths_from_lp(lp, names.dnsdomain)

    if hostip is None:
        try:
            hostip = socket.getaddrinfo(names.hostname, None, socket.AF_INET, socket.AI_CANONNAME, socket.IPPROTO_IP)[0][-1][0]
        except socket.gaierror, (socket.EAI_NODATA, msg):
            hostip = None

    if hostip6 is None:
        try:
            hostip6 = socket.getaddrinfo(names.hostname, None, socket.AF_INET6, socket.AI_CANONNAME, socket.IPPROTO_IP)[0][-1][0]
        except socket.gaierror, (socket.EAI_NODATA, msg): 
            hostip6 = None

    if serverrole is None:
        serverrole = lp.get("server role")

    assert serverrole in ("domain controller", "member server", "standalone")
    if invocationid is None and serverrole == "domain controller":
        invocationid = str(uuid.uuid4())

    if not os.path.exists(paths.private_dir):
        os.mkdir(paths.private_dir)

    ldapi_url = "ldapi://%s" % urllib.quote(paths.s4_ldapi_path, safe="")
    
    if ldap_backend is not None:
        if ldap_backend == "ldapi":
            # provision-backend will set this path suggested slapd command line / fedorads.inf
            ldap_backend = "ldapi://%s" % urllib.quote(os.path.join(paths.private_dir, "ldap", "ldapi"), safe="")
             
    # only install a new shares config db if there is none
    if not os.path.exists(paths.shareconf):
        message("Setting up share.ldb")
        share_ldb = Ldb(paths.shareconf, session_info=session_info, 
                        credentials=credentials, lp=lp)
        share_ldb.load_ldif_file_add(setup_path("share.ldif"))

     
    message("Setting up secrets.ldb")
    secrets_ldb = setup_secretsdb(paths.secrets, setup_path, 
                                  session_info=session_info, 
                                  credentials=credentials, lp=lp)

    message("Setting up the registry")
    setup_registry(paths.hklm, setup_path, session_info, 
                   credentials=credentials, lp=lp)

    message("Setting up templates db")
    setup_templatesdb(paths.templates, setup_path, session_info=session_info, 
                      credentials=credentials, lp=lp)

    message("Setting up idmap db")
    idmap = setup_idmapdb(paths.idmapdb, setup_path, session_info=session_info,
                          credentials=credentials, lp=lp)

    samdb = setup_samdb(paths.samdb, setup_path, session_info=session_info, 
                        credentials=credentials, lp=lp, names=names,
                        message=message, 
                        domainsid=domainsid, 
                        aci=aci, domainguid=domainguid, policyguid=policyguid, 
                        fill=samdb_fill, 
                        adminpass=adminpass, krbtgtpass=krbtgtpass,
                        invocationid=invocationid, 
                        machinepass=machinepass, dnspass=dnspass,
                        serverrole=serverrole, ldap_backend=ldap_backend, 
                        ldap_backend_type=ldap_backend_type)

    if lp.get("server role") == "domain controller":
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
            
        policy_path = os.path.join(paths.sysvol, names.dnsdomain, "Policies", 
                                   "{" + policyguid + "}")
        os.makedirs(policy_path, 0755)
        open(os.path.join(policy_path, "GPT.INI"), 'w').write("")
        os.makedirs(os.path.join(policy_path, "Machine"), 0755)
        os.makedirs(os.path.join(policy_path, "User"), 0755)
        if not os.path.isdir(paths.netlogon):
            os.makedirs(paths.netlogon, 0755)

    if samdb_fill == FILL_FULL:
        setup_name_mappings(samdb, idmap, str(domainsid), names.domaindn,
                            root_uid=root_uid, nobody_uid=nobody_uid,
                            users_gid=users_gid, wheel_gid=wheel_gid)

        message("Setting up sam.ldb rootDSE marking as synchronized")
        setup_modify_ldif(samdb, setup_path("provision_rootdse_modify.ldif"))

        # Only make a zone file on the first DC, it should be replicated with DNS replication
        if serverrole == "domain controller":
            secrets_ldb = Ldb(paths.secrets, session_info=session_info, 
                              credentials=credentials, lp=lp)
            secretsdb_become_dc(secrets_ldb, setup_path, domain=domain, realm=names.realm,
                                netbiosname=names.netbiosname, domainsid=domainsid, 
                                keytab_path=paths.keytab, samdb_url=paths.samdb, 
                                dns_keytab_path=paths.dns_keytab, dnspass=dnspass, 
                                machinepass=machinepass, dnsdomain=names.dnsdomain)

            samdb = SamDB(paths.samdb, session_info=session_info, 
                      credentials=credentials, lp=lp)

            domainguid = samdb.searchone(basedn=domaindn, attribute="objectGUID")
            assert isinstance(domainguid, str)
            hostguid = samdb.searchone(basedn=domaindn, attribute="objectGUID",
                                       expression="(&(objectClass=computer)(cn=%s))" % names.hostname,
                                       scope=SCOPE_SUBTREE)
            assert isinstance(hostguid, str)

            create_zone_file(paths.dns, setup_path, dnsdomain=names.dnsdomain,
                             domaindn=names.domaindn, hostip=hostip,
                             hostip6=hostip6, hostname=names.hostname,
                             dnspass=dnspass, realm=names.realm,
                             domainguid=domainguid, hostguid=hostguid)

            create_named_conf(paths.namedconf, setup_path, realm=names.realm,
                              dnsdomain=names.dnsdomain, private_dir=paths.private_dir)

            create_named_txt(paths.namedtxt, setup_path, realm=names.realm,
                              dnsdomain=names.dnsdomain, private_dir=paths.private_dir,
                              keytab_name=paths.dns_keytab)
            message("See %s for an example configuration include file for BIND" % paths.namedconf)
            message("and %s for further documentation required for secure DNS updates" % paths.namedtxt)

            create_krb5_conf(paths.krb5conf, setup_path, dnsdomain=names.dnsdomain,
                             hostname=names.hostname, realm=names.realm)
            message("A Kerberos configuration suitable for Samba 4 has been generated at %s" % paths.krb5conf)

    create_phpldapadmin_config(paths.phpldapadminconfig, setup_path, 
                               ldapi_url)

    message("Please install the phpLDAPadmin configuration located at %s into /etc/phpldapadmin/config.php" % paths.phpldapadminconfig)

    message("Once the above files are installed, your Samba4 server will be ready to use")
    message("Server Role:    %s" % serverrole)
    message("Hostname:       %s" % names.hostname)
    message("NetBIOS Domain: %s" % names.domain)
    message("DNS Domain:     %s" % names.dnsdomain)
    message("DOMAIN SID:     %s" % str(domainsid))
    if samdb_fill == FILL_FULL:
        message("Admin password: %s" % adminpass)

    result = ProvisionResult()
    result.domaindn = domaindn
    result.paths = paths
    result.lp = lp
    result.samdb = samdb
    return result


def provision_become_dc(setup_dir=None,
                        smbconf=None, targetdir=None, realm=None, 
                        rootdn=None, domaindn=None, schemadn=None, configdn=None,
                        serverdn=None,
                        domain=None, hostname=None, domainsid=None, 
                        adminpass=None, krbtgtpass=None, domainguid=None, 
                        policyguid=None, invocationid=None, machinepass=None, 
                        dnspass=None, root=None, nobody=None, nogroup=None, users=None, 
                        wheel=None, backup=None, aci=None, serverrole=None, 
                        ldap_backend=None, ldap_backend_type=None, sitename=None):

    def message(text):
        """print a message if quiet is not set."""
        print text

    return provision(setup_dir, message, system_session(), None,
              smbconf=smbconf, targetdir=targetdir, samdb_fill=FILL_DRS, realm=realm, 
              rootdn=rootdn, domaindn=domaindn, schemadn=schemadn, configdn=configdn, serverdn=serverdn,
              domain=domain, hostname=hostname, hostip="127.0.0.1", domainsid=domainsid, machinepass=machinepass, serverrole="domain controller", sitename=sitename)
    

def setup_db_config(setup_path, dbdir):
    """Setup a Berkeley database.
    
    :param setup_path: Setup path function.
    :param dbdir: Database directory."""
    if not os.path.isdir(os.path.join(dbdir, "bdb-logs")):
        os.makedirs(os.path.join(dbdir, "bdb-logs"), 0700)
    if not os.path.isdir(os.path.join(dbdir, "tmp")):
        os.makedirs(os.path.join(dbdir, "tmp"), 0700)
    
    setup_file(setup_path("DB_CONFIG"), os.path.join(dbdir, "DB_CONFIG"),
               {"LDAPDBDIR": dbdir})
    


def provision_backend(setup_dir=None, message=None,
                      smbconf=None, targetdir=None, realm=None, 
                      rootdn=None, domaindn=None, schemadn=None, configdn=None,
                      domain=None, hostname=None, adminpass=None, root=None, serverrole=None, 
                      ldap_backend_type=None, ldap_backend_port=None,
                      ol_mmr_urls=None,ol_olc=None,ol_slaptest=None):

    def setup_path(file):
        return os.path.join(setup_dir, file)

    if hostname is None:
        hostname = socket.gethostname().split(".")[0].lower()

    if root is None:
        root = findnss(pwd.getpwnam, ["root"])[0]

    if adminpass is None:
        adminpass = glue.generate_random_str(12)

    if targetdir is not None:
        if (not os.path.exists(os.path.join(targetdir, "etc"))):
            os.makedirs(os.path.join(targetdir, "etc"))
        smbconf = os.path.join(targetdir, "etc", "smb.conf")
    elif smbconf is None:
        smbconf = param.default_path()
        assert smbconf is not None

    # only install a new smb.conf if there isn't one there already
    if not os.path.exists(smbconf):
        make_smbconf(smbconf, setup_path, hostname, domain, realm, serverrole, 
                     targetdir)

    # openldap-online-configuration: validation of olc and slaptest
    if ol_olc == "yes" and ol_slaptest is None: 
        sys.exit("Warning: OpenLDAP-Online-Configuration cant be setup without path to slaptest-Binary!")

    if ol_olc == "yes" and ol_slaptest is not None:
        ol_slaptest = ol_slaptest + "/slaptest"
        if not os.path.exists(ol_slaptest):
            message (ol_slaptest)
            sys.exit("Warning: Given Path to slaptest-Binary does not exist!")
    ###



    lp = param.LoadParm()
    lp.load(smbconf)

    if serverrole is None:
        serverrole = lp.get("server role")

    names = guess_names(lp=lp, hostname=hostname, domain=domain, 
                        dnsdomain=realm, serverrole=serverrole, 
                        rootdn=rootdn, domaindn=domaindn, configdn=configdn, 
                        schemadn=schemadn)

    paths = provision_paths_from_lp(lp, names.dnsdomain)

    if not os.path.isdir(paths.ldapdir):
        os.makedirs(paths.ldapdir, 0700)
    schemadb_path = os.path.join(paths.ldapdir, "schema-tmp.ldb")
    try:
        os.unlink(schemadb_path)
    except OSError:
        pass

    schemadb = Ldb(schemadb_path, lp=lp)
 
    prefixmap = open(setup_path("prefixMap.txt"), 'r').read()

    setup_add_ldif(schemadb, setup_path("provision_schema_basedn.ldif"), 
                   {"SCHEMADN": names.schemadn,
                    "ACI": "#",
                    })
    setup_modify_ldif(schemadb, 
                      setup_path("provision_schema_basedn_modify.ldif"), \
                          {"SCHEMADN": names.schemadn,
                           "NETBIOSNAME": names.netbiosname,
                           "DEFAULTSITE": DEFAULTSITE,
                           "CONFIGDN": names.configdn,
                           "SERVERDN": names.serverdn,
                           "PREFIXMAP_B64": b64encode(prefixmap)
                           })
    
    setup_add_ldif(schemadb, setup_path("schema_samba4.ldif"), 
                   {"SCHEMADN": names.schemadn })
    setup_add_ldif(schemadb, setup_path("schema.ldif"), 
                   {"SCHEMADN": names.schemadn})

    if ldap_backend_type == "fedora-ds":
        if ldap_backend_port is not None:
            serverport = "ServerPort=%d" % ldap_backend_port
        else:
            serverport = ""

        setup_file(setup_path("fedorads.inf"), paths.fedoradsinf, 
                   {"ROOT": root,
                    "HOSTNAME": hostname,
                    "DNSDOMAIN": names.dnsdomain,
                    "LDAPDIR": paths.ldapdir,
                    "DOMAINDN": names.domaindn,
                    "LDAPMANAGERDN": names.ldapmanagerdn,
                    "LDAPMANAGERPASS": adminpass, 
                    "SERVERPORT": serverport})
        
        setup_file(setup_path("fedorads-partitions.ldif"), paths.fedoradspartitions, 
                   {"CONFIGDN": names.configdn,
                    "SCHEMADN": names.schemadn,
                    })
        
        mapping = "schema-map-fedora-ds-1.0"
        backend_schema = "99_ad.ldif"
        
        slapdcommand="Initialise Fedora DS with: setup-ds.pl --file=%s" % paths.fedoradsinf
       
        ldapuser = "--simple-bind-dn=" + names.ldapmanagerdn

    elif ldap_backend_type == "openldap":
        attrs = ["linkID", "lDAPDisplayName"]
        res = schemadb.search(expression="(&(linkID=*)(!(linkID:1.2.840.113556.1.4.803:=1))(objectclass=attributeSchema)(attributeSyntax=2.5.5.1))", base=names.schemadn, scope=SCOPE_SUBTREE, attrs=attrs)

        memberof_config = "# Generated from schema in %s\n" % schemadb_path
        refint_attributes = ""
        for i in range (0, len(res)):
            expression = "(&(objectclass=attributeSchema)(linkID=%d)(attributeSyntax=2.5.5.1))" % (int(res[i]["linkID"][0])+1)
            target = schemadb.searchone(basedn=names.schemadn, 
                                        expression=expression, 
                                        attribute="lDAPDisplayName", 
                                        scope=SCOPE_SUBTREE)
            if target is not None:
                refint_attributes = refint_attributes + " " + target + " " + res[i]["lDAPDisplayName"][0]
            
                memberof_config += read_and_sub_file(setup_path("memberof.conf"),
                                                     { "MEMBER_ATTR" : str(res[i]["lDAPDisplayName"][0]),
                                                       "MEMBEROF_ATTR" : str(target) })

        refint_config = read_and_sub_file(setup_path("refint.conf"),
                                            { "LINK_ATTRS" : refint_attributes})

# generate serverids, ldap-urls and syncrepl-blocks for mmr hosts
        mmr_on_config = ""
        mmr_replicator_acl = ""
        mmr_serverids_config = ""
        mmr_syncrepl_schema_config = "" 
        mmr_syncrepl_config_config = "" 
        mmr_syncrepl_user_config = "" 
       
 
        if ol_mmr_urls is not None:
                # For now, make these equal
                mmr_pass = adminpass

                url_list=filter(None,ol_mmr_urls.split(' ')) 
                if (len(url_list) == 1):
                    url_list=filter(None,ol_mmr_urls.split(',')) 
                     

                mmr_on_config = "MirrorMode On"
                mmr_replicator_acl = "  by dn=cn=replicator,cn=samba read"
                serverid=0
                for url in url_list:
                        serverid=serverid+1
                        mmr_serverids_config += read_and_sub_file(setup_path("mmr_serverids.conf"),
                                                                     { "SERVERID" : str(serverid),
                                                                       "LDAPSERVER" : url })
                        rid=serverid*10
                        rid=rid+1
                        mmr_syncrepl_schema_config += read_and_sub_file(setup_path("mmr_syncrepl.conf"),
                                                                     {  "RID" : str(rid),
                                                                        "MMRDN": names.schemadn,
                                                                        "LDAPSERVER" : url,
                                                                        "MMR_PASSWORD": mmr_pass})

                        rid=rid+1
                        mmr_syncrepl_config_config += read_and_sub_file(setup_path("mmr_syncrepl.conf"),
                                                                     {  "RID" : str(rid),
                                                                        "MMRDN": names.configdn,
                                                                        "LDAPSERVER" : url,
                                                                        "MMR_PASSWORD": mmr_pass})

                        rid=rid+1
                        mmr_syncrepl_user_config += read_and_sub_file(setup_path("mmr_syncrepl.conf"),
                                                                     {  "RID" : str(rid),
                                                                        "MMRDN": names.domaindn,
                                                                        "LDAPSERVER" : url,
                                                                        "MMR_PASSWORD": mmr_pass })
        # olc = yes?
        olc_config_pass = ""
        olc_config_acl = ""
        olc_syncrepl_config = ""
        olc_mmr_config = "" 
        if ol_olc == "yes":
                olc_config_pass += read_and_sub_file(setup_path("olc_pass.conf"),
                                                                { "OLC_PW": adminpass })
                olc_config_acl += read_and_sub_file(setup_path("olc_acl.conf"),{})
                
            # if olc = yes + mmr = yes, generate cn=config-replication directives
            # and  olc_seed.lif for the other mmr-servers
                if ol_olc == "yes" and ol_mmr_urls is not None:
                        serverid=0
                        olc_serverids_config = ""
                        olc_syncrepl_config = ""
                        olc_syncrepl_seed_config = ""
                        olc_mmr_config = "" 
                        olc_mmr_config += read_and_sub_file(setup_path("olc_mmr.conf"),{})
                        rid=1000
                        for url in url_list:
                                serverid=serverid+1
                                olc_serverids_config += read_and_sub_file(setup_path("olc_serverid.conf"),
                                                                     { "SERVERID" : str(serverid),
                                                                       "LDAPSERVER" : url })
                        
                                rid=rid+1
                                olc_syncrepl_config += read_and_sub_file(setup_path("olc_syncrepl.conf"),
                                                                     {  "RID" : str(rid),
                                                                        "LDAPSERVER" : url,
                                                                        "MMR_PASSWORD": adminpass})

                                olc_syncrepl_seed_config += read_and_sub_file(setup_path("olc_syncrepl_seed.conf"),
                                                                     {  "RID" : str(rid),
                                                                        "LDAPSERVER" : url})

                                setup_file(setup_path("olc_seed.ldif"), paths.olcseedldif,
                                                                     {"OLC_SERVER_ID_CONF": olc_serverids_config,
                                                                      "OLC_PW": adminpass,
                                                                      "OLC_SYNCREPL_CONF": olc_syncrepl_seed_config})
        

                # end olc

        setup_file(setup_path("slapd.conf"), paths.slapdconf,
                   {"DNSDOMAIN": names.dnsdomain,
                    "LDAPDIR": paths.ldapdir,
                    "DOMAINDN": names.domaindn,
                    "CONFIGDN": names.configdn,
                    "SCHEMADN": names.schemadn,
                    "MEMBEROF_CONFIG": memberof_config,
                    "MIRRORMODE": mmr_on_config,
                    "REPLICATOR_ACL": mmr_replicator_acl,
                    "MMR_SERVERIDS_CONFIG": mmr_serverids_config,
                    "MMR_SYNCREPL_SCHEMA_CONFIG": mmr_syncrepl_schema_config,
                    "MMR_SYNCREPL_CONFIG_CONFIG": mmr_syncrepl_config_config,
                    "MMR_SYNCREPL_USER_CONFIG": mmr_syncrepl_user_config,
                    "OLC_CONFIG_PASS": olc_config_pass,
                    "OLC_SYNCREPL_CONFIG": olc_syncrepl_config,
                    "OLC_CONFIG_ACL": olc_config_acl,
                    "OLC_MMR_CONFIG": olc_mmr_config,
                    "REFINT_CONFIG": refint_config})
        setup_file(setup_path("modules.conf"), paths.modulesconf,
                   {"REALM": names.realm})
        
        setup_db_config(setup_path, os.path.join(paths.ldapdir, "db", "user"))
        setup_db_config(setup_path, os.path.join(paths.ldapdir, "db", "config"))
        setup_db_config(setup_path, os.path.join(paths.ldapdir, "db", "schema"))

        if not os.path.exists(os.path.join(paths.ldapdir, "db", "samba",  "cn=samba")):
            os.makedirs(os.path.join(paths.ldapdir, "db", "samba",  "cn=samba"), 0700)

        setup_file(setup_path("cn=samba.ldif"), 
                   os.path.join(paths.ldapdir, "db", "samba",  "cn=samba.ldif"),
                   { "UUID": str(uuid.uuid4()), 
                     "LDAPTIME": timestring(int(time.time()))} )
        setup_file(setup_path("cn=samba-admin.ldif"), 
                              os.path.join(paths.ldapdir, "db", "samba",  "cn=samba", "cn=samba-admin.ldif"),
                              {"LDAPADMINPASS_B64": b64encode(adminpass),
                               "UUID": str(uuid.uuid4()), 
                               "LDAPTIME": timestring(int(time.time()))} )
        
        if ol_mmr_urls is not None:
           setup_file(setup_path("cn=replicator.ldif"),
                              os.path.join(paths.ldapdir, "db", "samba",  "cn=samba", "cn=replicator.ldif"),
                              {"MMR_PASSWORD_B64": b64encode(mmr_pass),
                               "UUID": str(uuid.uuid4()),
                               "LDAPTIME": timestring(int(time.time()))} )


        mapping = "schema-map-openldap-2.3"
        backend_schema = "backend-schema.schema"

        ldapi_uri = "ldapi://" + urllib.quote(os.path.join(paths.private_dir, "ldap", "ldapi"), safe="")
        if ldap_backend_port is not None:
            server_port_string = " -h ldap://0.0.0.0:%d" % ldap_backend_port
        else:
            server_port_string = ""

        if ol_olc != "yes" and ol_mmr_urls is None:
          slapdcommand="Start slapd with:    slapd -f " + paths.ldapdir + "/slapd.conf -h " + ldapi_uri + server_port_string

        if ol_olc == "yes" and ol_mmr_urls is None:
          slapdcommand="Start slapd with:    slapd -F " + paths.olcdir + " -h \"" + ldapi_uri + " ldap://<FQHN>:<PORT>\"" 

        if ol_olc != "yes" and ol_mmr_urls is not None:
          slapdcommand="Start slapd with:    slapd -f " + paths.ldapdir + "/slapd.conf -h \"" + ldapi_uri + " ldap://<FQHN>:<PORT>\""

        if ol_olc == "yes" and ol_mmr_urls is not None:
          slapdcommand="Start slapd with:    slapd -F " + paths.olcdir + " -h \"" + ldapi_uri + " ldap://<FQHN>:<PORT>\""


        ldapuser = "--username=samba-admin"

            
    schema_command = "bin/ad2oLschema --option=convert:target=" + ldap_backend_type + " -I " + setup_path(mapping) + " -H tdb://" + schemadb_path + " -O " + os.path.join(paths.ldapdir, backend_schema)
            
    os.system(schema_command)

    message("Your %s Backend for Samba4 is now configured, and is ready to be started" % ldap_backend_type)
    message("Server Role:         %s" % serverrole)
    message("Hostname:            %s" % names.hostname)
    message("DNS Domain:          %s" % names.dnsdomain)
    message("Base DN:             %s" % names.domaindn)

    if ldap_backend_type == "openldap":
        message("LDAP admin user:     samba-admin")
    else:
        message("LDAP admin DN:       %s" % names.ldapmanagerdn)

    message("LDAP admin password: %s" % adminpass)
    message(slapdcommand)
    if ol_olc == "yes" or ol_mmr_urls is not None:
        message("Attention to slapd-Port: <PORT> must be different than 389!")
    assert isinstance(ldap_backend_type, str)
    assert isinstance(ldapuser, str)
    assert isinstance(adminpass, str)
    assert isinstance(names.dnsdomain, str)
    assert isinstance(names.domain, str)
    assert isinstance(serverrole, str)
    args = ["--ldap-backend=ldapi",
            "--ldap-backend-type=" + ldap_backend_type,
            "--password=" + adminpass,
            ldapuser,
            "--realm=" + names.dnsdomain,
            "--domain=" + names.domain,
            "--server-role='" + serverrole + "'"]
    message("Run provision with: " + " ".join(args))


    # if --ol-olc=yes, generate online-configuration in ../private/ldap/slapd.d 
    if ol_olc == "yes":
          if not os.path.isdir(paths.olcdir):
             os.makedirs(paths.olcdir, 0770)
          paths.olslaptest = str(ol_slaptest)
          olc_command = paths.olslaptest + " -f" + paths.slapdconf + " -F" +  paths.olcdir + " >/dev/null 2>&1"
          os.system(olc_command)
          os.remove(paths.slapdconf)        
          # use line below for debugging during olc-conversion with slaptest, instead of olc_command above 
          #olc_command = paths.olslaptest + " -f" + paths.slapdconf + " -F" +  paths.olcdir"


def create_phpldapadmin_config(path, setup_path, ldapi_uri):
    """Create a PHP LDAP admin configuration file.

    :param path: Path to write the configuration to.
    :param setup_path: Function to generate setup paths.
    """
    setup_file(setup_path("phpldapadmin-config.php"), path, 
            {"S4_LDAPI_URI": ldapi_uri})


def create_zone_file(path, setup_path, dnsdomain, domaindn, 
                     hostip, hostip6, hostname, dnspass, realm, domainguid, hostguid):
    """Write out a DNS zone file, from the info in the current database.

    :param path: Path of the new zone file.
    :param setup_path: Setup path function.
    :param dnsdomain: DNS Domain name
    :param domaindn: DN of the Domain
    :param hostip: Local IPv4 IP
    :param hostip6: Local IPv6 IP
    :param hostname: Local hostname
    :param dnspass: Password for DNS
    :param realm: Realm name
    :param domainguid: GUID of the domain.
    :param hostguid: GUID of the host.
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

    setup_file(setup_path("provision.zone"), path, {
            "DNSPASS_B64": b64encode(dnspass),
            "HOSTNAME": hostname,
            "DNSDOMAIN": dnsdomain,
            "REALM": realm,
            "HOSTIP_BASE_LINE": hostip_base_line,
            "HOSTIP_HOST_LINE": hostip_host_line,
            "DOMAINGUID": domainguid,
            "DATESTRING": time.strftime("%Y%m%d%H"),
            "DEFAULTSITE": DEFAULTSITE,
            "HOSTGUID": hostguid,
            "HOSTIP6_BASE_LINE": hostip6_base_line,
            "HOSTIP6_HOST_LINE": hostip6_host_line,
        })


def create_named_conf(path, setup_path, realm, dnsdomain,
                      private_dir):
    """Write out a file containing zone statements suitable for inclusion in a
    named.conf file (including GSS-TSIG configuration).
    
    :param path: Path of the new named.conf file.
    :param setup_path: Setup path function.
    :param realm: Realm name
    :param dnsdomain: DNS Domain name
    :param private_dir: Path to private directory
    :param keytab_name: File name of DNS keytab file
    """

    setup_file(setup_path("named.conf"), path, {
            "DNSDOMAIN": dnsdomain,
            "REALM": realm,
            "REALM_WC": "*." + ".".join(realm.split(".")[1:]),
            "PRIVATE_DIR": private_dir
            })

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


def load_schema(setup_path, samdb, schemadn, netbiosname, configdn, sitename,
                serverdn, servername):
    """Load schema for the SamDB.
    
    :param samdb: Load a schema into a SamDB.
    :param setup_path: Setup path function.
    :param schemadn: DN of the schema
    :param netbiosname: NetBIOS name of the host.
    :param configdn: DN of the configuration
    :param serverdn: DN of the server
    :param servername: Host name of the server
    """
    schema_data = open(setup_path("schema.ldif"), 'r').read()
    schema_data += open(setup_path("schema_samba4.ldif"), 'r').read()
    schema_data = substitute_var(schema_data, {"SCHEMADN": schemadn})
    check_all_substituted(schema_data)
    prefixmap = open(setup_path("prefixMap.txt"), 'r').read()
    prefixmap = b64encode(prefixmap)

    head_data = open(setup_path("provision_schema_basedn_modify.ldif"), 'r').read()
    head_data = substitute_var(head_data, {
                    "SCHEMADN": schemadn,
                    "NETBIOSNAME": netbiosname,
                    "CONFIGDN": configdn,
                    "DEFAULTSITE": sitename,
                    "PREFIXMAP_B64": prefixmap,
                    "SERVERDN": serverdn,
                    "SERVERNAME": servername,
    })
    check_all_substituted(head_data)
    samdb.attach_schema_from_ldif(head_data, schema_data)

