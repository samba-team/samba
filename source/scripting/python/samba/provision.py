#
# Unix SMB/CIFS implementation.
# backend code for provisioning a Samba4 server

# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2008
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

from base64 import b64encode
import os
import pwd
import grp
import time
import uuid, misc
from socket import gethostname, gethostbyname
import param
import registry
import samba
from samba import Ldb, substitute_var, valid_netbios_name, check_all_substituted
from samba.samdb import SamDB
import security
import urllib
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError, \
        LDB_ERR_NO_SUCH_OBJECT, timestring, CHANGETYPE_MODIFY, CHANGETYPE_NONE

"""Functions for setting up a Samba configuration."""

DEFAULTSITE = "Default-First-Site-Name"

class InvalidNetbiosName(Exception):
    def __init__(self, name):
        super(InvalidNetbiosName, self).__init__("The name '%r' is not a valid NetBIOS name" % name)


class ProvisionPaths:
    def __init__(self):
        self.smbconf = None
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


def check_install(lp, session_info, credentials):
    """Check whether the current install seems ok.
    
    :param lp: Loadparm context
    :param session_info: Session information
    :param credentials: Credentials
    """
    if lp.get("realm") == "":
        raise Error("Realm empty")
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


def open_ldb(session_info, credentials, lp, dbname):
    """Open a LDB, thrashing it if it is corrupt.

    :param session_info: auth session information
    :param credentials: credentials
    :param lp: Loadparm context
    :param dbname: Path of the database to open.
    :return: a Ldb object
    """
    assert session_info is not None
    try:
        return Ldb(dbname, session_info=session_info, credentials=credentials, 
                   lp=lp)
    except LdbError, e:
        print e
        os.unlink(dbname)
        return Ldb(dbname, session_info=session_info, credentials=credentials,
                   lp=lp)


def setup_add_ldif(ldb, ldif_path, subst_vars=None):
    """Setup a ldb in the private dir.
    
    :param ldb: LDB file to import data into
    :param ldif_path: Path of the LDIF file to load
    :param subst_vars: Optional variables to subsitute in LDIF.
    """
    assert isinstance(ldif_path, str)

    data = open(ldif_path, 'r').read()
    if subst_vars is not None:
        data = substitute_var(data, subst_vars)

    check_all_substituted(data)

    ldb.add_ldif(data)


def setup_modify_ldif(ldb, ldif_path, substvars=None):
    """Modify a ldb in the private dir.
    
    :param ldb: LDB object.
    :param ldif_path: LDIF file path.
    :param substvars: Optional dictionary with substitution variables.
    """
    data = open(ldif_path, 'r').read()
    if substvars is not None:
        data = substitute_var(data, substvars)

    check_all_substituted(data)

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


def setup_file(template, fname, substvars):
    """Setup a file in the private dir.

    :param template: Path of the template file.
    :param fname: Path of the file to create.
    :param substvars: Substitution variables.
    """
    f = fname

    if os.path.exists(f):
        os.unlink(f)

    data = open(template, 'r').read()
    if substvars:
        data = substitute_var(data, substvars)
    check_all_substituted(data)

    open(f, 'w').write(data)


def provision_paths_from_lp(lp, dnsdomain):
    """Set the default paths for provisioning.

    :param lp: Loadparm context.
    :param dnsdomain: DNS Domain name
    """
    paths = ProvisionPaths()
    private_dir = lp.get("private dir")
    paths.keytab = "secrets.keytab"
    paths.dns_keytab = "dns.keytab"

    paths.shareconf = os.path.join(private_dir, "share.ldb")
    paths.samdb = os.path.join(private_dir, lp.get("sam database") or "samdb.ldb")
    paths.idmapdb = os.path.join(private_dir, lp.get("idmap database") or "idmap.ldb")
    paths.secrets = os.path.join(private_dir, lp.get("secrets database") or "secrets.ldb")
    paths.templates = os.path.join(private_dir, "templates.ldb")
    paths.dns = os.path.join(private_dir, dnsdomain + ".zone")
    paths.winsdb = os.path.join(private_dir, "wins.ldb")
    paths.s4_ldapi_path = os.path.join(private_dir, "ldapi")
    paths.smbconf = os.path.join(private_dir, "smb.conf")
    paths.phpldapadminconfig = os.path.join(private_dir, 
                                            "phpldapadmin-config.php")
    paths.hklm = "hklm.ldb"
    paths.hkcr = "hkcr.ldb"
    paths.hkcu = "hkcu.ldb"
    paths.hku = "hku.ldb"
    paths.hkpd = "hkpd.ldb"
    paths.hkpt = "hkpt.ldb"

    paths.sysvol = lp.get("sysvol", "path")
    if paths.sysvol is None:
        paths.sysvol = os.path.join(lp.get("lock dir"), "sysvol")

    paths.netlogon = lp.get("netlogon", "path")
    if paths.netlogon is None:
        paths.netlogon = os.path.join(os.path.join(paths.sysvol, "scripts"))

    return paths


def setup_name_mappings(ldb, sid, domaindn, root, nobody, nogroup, users, 
                        wheel, backup):
    """setup reasonable name mappings for sam names to unix names.
    
    :param ldb: SamDB object.
    :param sid: The domain sid.
    :param domaindn: The domain DN.
    :param root: Name of the UNIX root user.
    :param nobody: Name of the UNIX nobody user.
    :param nogroup: Name of the unix nobody group.
    :param users: Name of the unix users group.
    :param wheel: Name of the wheel group (users that can become root).
    :param backup: Name of the backup group."""
    # add some foreign sids if they are not present already
    ldb.add_foreign(domaindn, "S-1-5-7", "Anonymous")
    ldb.add_foreign(domaindn, "S-1-1-0", "World")
    ldb.add_foreign(domaindn, "S-1-5-2", "Network")
    ldb.add_foreign(domaindn, "S-1-5-18", "System")
    ldb.add_foreign(domaindn, "S-1-5-11", "Authenticated Users")

    # some well known sids
    ldb.setup_name_mapping(domaindn, "S-1-5-7", nobody)
    ldb.setup_name_mapping(domaindn, "S-1-1-0", nogroup)
    ldb.setup_name_mapping(domaindn, "S-1-5-2", nogroup)
    ldb.setup_name_mapping(domaindn, "S-1-5-18", root)
    ldb.setup_name_mapping(domaindn, "S-1-5-11", users)
    ldb.setup_name_mapping(domaindn, "S-1-5-32-544", wheel)
    ldb.setup_name_mapping(domaindn, "S-1-5-32-545", users)
    ldb.setup_name_mapping(domaindn, "S-1-5-32-546", nogroup)
    ldb.setup_name_mapping(domaindn, "S-1-5-32-551", backup)

    # and some well known domain rids
    ldb.setup_name_mapping(domaindn, sid + "-500", root)
    ldb.setup_name_mapping(domaindn, sid + "-518", wheel)
    ldb.setup_name_mapping(domaindn, sid + "-519", wheel)
    ldb.setup_name_mapping(domaindn, sid + "-512", wheel)
    ldb.setup_name_mapping(domaindn, sid + "-513", users)
    ldb.setup_name_mapping(domaindn, sid + "-520", wheel)


def setup_samdb_partitions(samdb_path, setup_path, message, lp, session_info, 
                           credentials, configdn, schemadn, domaindn, 
                           hostname, netbiosname, dnsdomain, realm, 
                           rootdn, serverrole, sitename, ldap_backend=None, 
                           ldap_backend_type=None, erase=False):
    """Setup the partitions for the SAM database. 
    
    Alternatively, provision() may call this, and then populate the database.
    
    :param erase: Remove the existing data present in the database.
     
    :note: This will wipe the Sam Database!
    
    :note: This function always removes the local SAM LDB file. The erase 
        parameter controls whether to erase the existing data, which 
        may not be stored locally but in LDAP.
    """
    assert session_info is not None

    if os.path.exists(samdb_path):
        os.unlink(samdb_path)

    # Also wipes the database
    samdb = SamDB(samdb_path, session_info=session_info, 
                  credentials=credentials, lp=lp)

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
                    "extended_dn",
                    "asq",
                    "rdn_name",
                    "objectclass",
                    "samldb",
                    "kludge_acl",
                    "operational"]
    tdb_modules_list = [
                    "subtree_rename",
                    "subtree_delete",
                    "linked_attributes"]
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
    elif ldap_backend_type == "openldap":
        backend_modules = ["normalise", "entryuuid", "paged_searches"]
    elif serverrole == "domain controller":
        backend_modules = ["repl_meta_data"]
    else:
        backend_modules = ["objectguid"]
        
    samdb.transaction_start()
    try:
        setup_add_ldif(samdb, setup_path("provision_partitions.ldif"), {
                "SCHEMADN": schemadn, 
                "SCHEMADN_LDB": schemadn_ldb,
                "SCHEMADN_MOD2": ",objectguid",
                "CONFIGDN": configdn,
                "CONFIGDN_LDB": configdn_ldb,
                "DOMAINDN": domaindn,
                "DOMAINDN_LDB": domaindn_ldb,
                "SCHEMADN_MOD": "schema_fsmo,instancetype",
                "CONFIGDN_MOD": "naming_fsmo,instancetype",
                "DOMAINDN_MOD": "pdc_fsmo,password_hash,instancetype",
                "MODULES_LIST": ",".join(modules_list),
                "TDB_MODULES_LIST": ","+",".join(tdb_modules_list),
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
        setup_samdb_rootdse(samdb, setup_path, schemadn, domaindn, hostname, 
                            dnsdomain, realm, rootdn, configdn, netbiosname,
                            sitename)

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
    templates_ldb.erase()
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
    reg.mount_hive(hive, "HKEY_LOCAL_MACHINE")
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

    idmap_ldb = Ldb(path, session_info=session_info, credentials=credentials,
                    lp=lp)

    idmap_ldb.erase()
    idmap_ldb.load_ldif_file_add(setup_path("idmap_init.ldif"))
    return idmap_ldb

def setup_samdb_rootdse(samdb, setup_path, schemadn, domaindn, hostname, 
                        dnsdomain, realm, rootdn, configdn, netbiosname,
                        sitename):
    """Setup the SamDB rootdse.

    :param samdb: Sam Database handle
    :param setup_path: Obtain setup path
    """
    setup_add_ldif(samdb, setup_path("provision_rootdse_add.ldif"), {
        "SCHEMADN": schemadn, 
        "NETBIOSNAME": netbiosname,
        "DNSDOMAIN": dnsdomain,
        "DEFAULTSITE": sitename,
        "REALM": realm,
        "DNSNAME": "%s.%s" % (hostname, dnsdomain),
        "DOMAINDN": domaindn,
        "ROOTDN": rootdn,
        "CONFIGDN": configdn,
        "VERSION": samba.version(),
        })
        

def setup_self_join(samdb, configdn, schemadn, domaindn, 
                    netbiosname, hostname, dnsdomain, machinepass, dnspass, 
                    realm, domainname, domainsid, invocationid, setup_path,
                    policyguid, sitename, hostguid=None):
    """Join a host to its own domain."""
    if hostguid is not None:
        hostguid_add = "objectGUID: %s" % hostguid
    else:
        hostguid_add = ""

    setup_add_ldif(samdb, setup_path("provision_self_join.ldif"), { 
              "CONFIGDN": configdn, 
              "SCHEMADN": schemadn,
              "DOMAINDN": domaindn,
              "INVOCATIONID": invocationid,
              "NETBIOSNAME": netbiosname,
              "DEFAULTSITE": sitename,
              "DNSNAME": "%s.%s" % (hostname, dnsdomain),
              "MACHINEPASS_B64": b64encode(machinepass),
              "DNSPASS_B64": b64encode(dnspass),
              "REALM": realm,
              "DOMAIN": domainname,
              "HOSTGUID_ADD": hostguid_add,
              "DNSDOMAIN": dnsdomain})
    setup_add_ldif(samdb, setup_path("provision_group_policy.ldif"), { 
              "POLICYGUID": policyguid,
              "DNSDOMAIN": dnsdomain,
              "DOMAINSID": str(domainsid),
              "DOMAINDN": domaindn})


def setup_samdb(path, setup_path, session_info, credentials, lp, 
                schemadn, configdn, domaindn, dnsdomain, realm, 
                netbiosname, message, hostname, rootdn, erase, 
                domainsid, aci, domainguid, policyguid, 
                domainname, fill, adminpass, krbtgtpass, 
                machinepass, hostguid, invocationid, dnspass,
                serverrole, sitename, ldap_backend=None, 
                ldap_backend_type=None):
    """Setup a complete SAM Database.
    
    :note: This will wipe the main SAM database file!
    """

    assert serverrole in ("domain controller", "member server")

    # Also wipes the database
    setup_samdb_partitions(path, setup_path, schemadn=schemadn, configdn=configdn, 
                           domaindn=domaindn, message=message, lp=lp,
                           credentials=credentials, session_info=session_info,
                           hostname=hostname, netbiosname=netbiosname, 
                           dnsdomain=dnsdomain, realm=realm, rootdn=rootdn,
                           ldap_backend=ldap_backend, serverrole=serverrole,
                           ldap_backend_type=ldap_backend_type, erase=erase,
                           sitename=sitename)

    samdb = SamDB(path, session_info=session_info, 
                  credentials=credentials, lp=lp)

    if fill == FILL_DRS:
       # We want to finish here, but setup the index before we do so
        message("Setting up sam.ldb index")
        samdb.load_ldif_file_add(setup_path("provision_index.ldif"))
        return samdb

    message("Pre-loading the Samba 4 and AD schema")
    samdb = SamDB(path, session_info=session_info, 
                  credentials=credentials, lp=lp)
    samdb.set_domain_sid(domainsid)
    if lp.get("server role") == "domain controller":
        samdb.set_invocation_id(invocationid)

    load_schema(setup_path, samdb, schemadn, netbiosname, configdn, sitename)

    samdb.transaction_start()
        
    try:
        message("Adding DomainDN: %s (permitted to fail)" % domaindn)
        setup_add_ldif(samdb, setup_path("provision_basedn.ldif"), {
            "DOMAINDN": domaindn,
            "ACI": aci,
            })

        message("Modifying DomainDN: " + domaindn + "")
        if domainguid is not None:
            domainguid_mod = "replace: objectGUID\nobjectGUID: %s\n-" % domainguid
        else:
            domainguid_mod = ""

        setup_modify_ldif(samdb, setup_path("provision_basedn_modify.ldif"), {
            "LDAPTIME": timestring(int(time.time())),
            "DOMAINSID": str(domainsid),
            "SCHEMADN": schemadn, 
            "NETBIOSNAME": netbiosname,
            "DEFAULTSITE": sitename,
            "CONFIGDN": configdn,
            "POLICYGUID": policyguid,
            "DOMAINDN": domaindn,
            "DOMAINGUID_MOD": domainguid_mod,
            })

        message("Adding configuration container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_configuration_basedn.ldif"), {
            "CONFIGDN": configdn, 
            "ACI": aci,
            "EXTENSIBLEOBJECT": "# no objectClass: extensibleObject for local ldb",
            })
        message("Modifying configuration container")
        setup_modify_ldif(samdb, setup_path("provision_configuration_basedn_modify.ldif"), {
            "CONFIGDN": configdn, 
            "SCHEMADN": schemadn,
            })

        message("Adding schema container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_schema_basedn.ldif"), {
            "SCHEMADN": schemadn,
            "ACI": aci,
            "EXTENSIBLEOBJECT": "# no objectClass: extensibleObject for local ldb"
            })
        message("Modifying schema container")
        setup_modify_ldif(samdb, 
            setup_path("provision_schema_basedn_modify.ldif"), {
            "SCHEMADN": schemadn,
            "NETBIOSNAME": netbiosname,
            "DEFAULTSITE": sitename,
            "CONFIGDN": configdn,
            })

        message("Setting up sam.ldb Samba4 schema")
        setup_add_ldif(samdb, setup_path("schema_samba4.ldif"), 
                       {"SCHEMADN": schemadn })
        message("Setting up sam.ldb AD schema")
        setup_add_ldif(samdb, setup_path("schema.ldif"), 
                       {"SCHEMADN": schemadn})

        message("Setting up sam.ldb configuration data")
        setup_add_ldif(samdb, setup_path("provision_configuration.ldif"), {
            "CONFIGDN": configdn,
            "NETBIOSNAME": netbiosname,
            "DEFAULTSITE": sitename,
            "DNSDOMAIN": dnsdomain,
            "DOMAIN": domainname,
            "SCHEMADN": schemadn,
            "DOMAINDN": domaindn,
            })

        message("Setting up display specifiers")
        setup_add_ldif(samdb, setup_path("display_specifiers.ldif"), 
                       {"CONFIGDN": configdn})

        message("Adding users container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_users_add.ldif"), {
            "DOMAINDN": domaindn})
        message("Modifying users container")
        setup_modify_ldif(samdb, setup_path("provision_users_modify.ldif"), {
            "DOMAINDN": domaindn})
        message("Adding computers container (permitted to fail)")
        setup_add_ldif(samdb, setup_path("provision_computers_add.ldif"), {
            "DOMAINDN": domaindn})
        message("Modifying computers container")
        setup_modify_ldif(samdb, setup_path("provision_computers_modify.ldif"), {
            "DOMAINDN": domaindn})
        message("Setting up sam.ldb data")
        setup_add_ldif(samdb, setup_path("provision.ldif"), {
            "DOMAINDN": domaindn,
            "NETBIOSNAME": netbiosname,
            "DEFAULTSITE": sitename,
            "CONFIGDN": configdn,
            })

        if fill == FILL_FULL:
            message("Setting up sam.ldb users and groups")
            setup_add_ldif(samdb, setup_path("provision_users.ldif"), {
                "DOMAINDN": domaindn,
                "DOMAINSID": str(domainsid),
                "CONFIGDN": configdn,
                "ADMINPASS_B64": b64encode(adminpass),
                "KRBTGTPASS_B64": b64encode(krbtgtpass),
                })

            if lp.get("server role") == "domain controller":
                message("Setting up self join")
                setup_self_join(samdb, configdn=configdn, schemadn=schemadn, 
                                domaindn=domaindn, invocationid=invocationid, 
                                dnspass=dnspass, netbiosname=netbiosname, 
                                dnsdomain=dnsdomain, realm=realm, 
                                machinepass=machinepass, domainname=domainname, 
                                domainsid=domainsid, policyguid=policyguid,
                                hostname=hostname, hostguid=hostguid, 
                                setup_path=setup_path, sitename=sitename)

    #We want to setup the index last, as adds are faster unindexed
        message("Setting up sam.ldb index")
        samdb.load_ldif_file_add(setup_path("provision_index.ldif"))
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()
    return samdb


FILL_FULL = "FULL"
FILL_NT4SYNC = "NT4SYNC"
FILL_DRS = "DRS"

def provision(lp, setup_dir, message, paths, session_info, 
              credentials, samdb_fill=FILL_FULL, realm=None, rootdn=None,
              domain=None, hostname=None, hostip=None, domainsid=None, 
              hostguid=None, adminpass=None, krbtgtpass=None, domainguid=None, 
              policyguid=None, invocationid=None, machinepass=None, 
              dnspass=None, root=None, nobody=None, nogroup=None, users=None, 
              wheel=None, backup=None, aci=None, serverrole=None, erase=False,
              ldap_backend=None, ldap_backend_type=None, sitename=DEFAULTSITE):
    """Provision samba4
    
    :note: caution, this wipes all existing data!
    """

    def setup_path(file):
        return os.path.join(setup_dir, file)

    if domainsid is None:
        domainsid = security.random_sid()
    if policyguid is None:
        policyguid = uuid.random()
    if adminpass is None:
        adminpass = misc.random_password(12)
    if krbtgtpass is None:
        krbtgtpass = misc.random_password(12)
    if machinepass is None:
        machinepass  = misc.random_password(12)
    if dnspass is None:
        dnspass = misc.random_password(12)
    if root is None:
        root = findnss(pwd.getpwnam, ["root"])[0]
    if nobody is None:
        nobody = findnss(pwd.getpwnam, ["nobody"])[0]
    if nogroup is None:
        nogroup = findnss(grp.getgrnam, ["nogroup", "nobody"])[0]
    if users is None:
        users = findnss(grp.getgrnam, ["users", "guest", "other", "unknown", 
                        "usr"])[0]
    if wheel is None:
        wheel = findnss(grp.getgrnam, ["wheel", "root", "staff", "adm"])[0]
    if backup is None:
        backup = findnss(grp.getgrnam, ["backup", "wheel", "root", "staff"])[0]
    if aci is None:
        aci = "# no aci for local ldb"
    if serverrole is None:
        serverrole = lp.get("server role")
    assert serverrole in ("domain controller", "member server")
    if invocationid is None and serverrole == "domain controller":
        invocationid = uuid.random()

    if realm is None:
        realm = lp.get("realm")

    if lp.get("realm").upper() != realm.upper():
        raise Exception("realm '%s' in smb.conf must match chosen realm '%s'" %
                (lp.get("realm"), realm))

    ldapi_url = "ldapi://%s" % urllib.quote(paths.s4_ldapi_path, safe="")
    
    if ldap_backend == "ldapi":
        # provision-backend will set this path suggested slapd command line / fedorads.inf
        ldap_backend = "ldapi://" % urllib.quote(os.path.join(lp.get("private dir"), "ldap", "ldapi"), safe="")

    assert realm is not None
    realm = realm.upper()

    if hostname is None:
        hostname = gethostname().split(".")[0].lower()

    if hostip is None:
        hostip = gethostbyname(hostname)

    netbiosname = hostname.upper()
    if not valid_netbios_name(netbiosname):
        raise InvalidNetbiosName(netbiosname)

    dnsdomain = realm.lower()
    if serverrole == "domain controller":
        domaindn = "DC=" + dnsdomain.replace(".", ",DC=")
        if domain is None:
            domain = lp.get("workgroup")
    
        if lp.get("workgroup").upper() != domain.upper():
            raise Error("workgroup '%s' in smb.conf must match chosen domain '%s'",
                lp.get("workgroup"), domain)

        assert domain is not None
        domain = domain.upper()
        if not valid_netbios_name(domain):
            raise InvalidNetbiosName(domain)
    else:
        domaindn = "CN=" + netbiosname
        domain = netbiosname
    
    if rootdn is None:
       rootdn = domaindn
       
    configdn = "CN=Configuration," + rootdn
    schemadn = "CN=Schema," + configdn

    message("set DOMAIN SID: %s" % str(domainsid))
    message("Provisioning for %s in realm %s" % (domain, realm))
    message("Using administrator password: %s" % adminpass)

    assert paths.smbconf is not None

    # only install a new smb.conf if there isn't one there already
    if not os.path.exists(paths.smbconf):
        message("Setting up smb.conf")
        if serverrole == "domain controller":
            smbconfsuffix = "dc"
        elif serverrole == "member":
            smbconfsuffix = "member"
        setup_file(setup_path("provision.smb.conf.%s" % smbconfsuffix), 
                   paths.smbconf, {
            "HOSTNAME": hostname,
            "DOMAIN_CONF": domain,
            "REALM_CONF": realm,
            "SERVERROLE": serverrole,
            "NETLOGONPATH": paths.netlogon,
            "SYSVOLPATH": paths.sysvol,
            })
        lp.load(paths.smbconf)

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
    setup_idmapdb(paths.idmapdb, setup_path, session_info=session_info,
                  credentials=credentials, lp=lp)

    samdb = setup_samdb(paths.samdb, setup_path, session_info=session_info, 
                        credentials=credentials, lp=lp, schemadn=schemadn, 
                        configdn=configdn, domaindn=domaindn,
                        dnsdomain=dnsdomain, netbiosname=netbiosname, 
                        realm=realm, message=message, hostname=hostname, 
                        rootdn=rootdn, erase=erase, domainsid=domainsid, 
                        aci=aci, domainguid=domainguid, policyguid=policyguid, 
                        domainname=domain, fill=samdb_fill, 
                        adminpass=adminpass, krbtgtpass=krbtgtpass,
                        hostguid=hostguid, invocationid=invocationid, 
                        machinepass=machinepass, dnspass=dnspass,
                        serverrole=serverrole, ldap_backend=ldap_backend, 
                        ldap_backend_type=ldap_backend_type, sitename=sitename)

    if lp.get("server role") == "domain controller":
       policy_path = os.path.join(paths.sysvol, dnsdomain, "Policies", 
                                  "{" + policyguid + "}")
       os.makedirs(policy_path, 0755)
       os.makedirs(os.path.join(policy_path, "Machine"), 0755)
       os.makedirs(os.path.join(policy_path, "User"), 0755)
       if not os.path.isdir(paths.netlogon):
            os.makedirs(paths.netlogon, 0755)
       secrets_ldb = Ldb(paths.secrets, session_info=session_info, 
                         credentials=credentials, lp=lp)
       secretsdb_become_dc(secrets_ldb, setup_path, domain=domain, realm=realm,
                           netbiosname=netbiosname, domainsid=domainsid, 
                           keytab_path=paths.keytab, samdb_url=paths.samdb, 
                           dns_keytab_path=paths.dns_keytab, dnspass=dnspass, 
                           machinepass=machinepass, dnsdomain=dnsdomain)

    if samdb_fill == FILL_FULL:
        setup_name_mappings(samdb, str(domainsid), domaindn, root=root, 
                            nobody=nobody, nogroup=nogroup, wheel=wheel, 
                            users=users, backup=backup)
   
        message("Setting up sam.ldb rootDSE marking as synchronized")
        setup_modify_ldif(samdb, setup_path("provision_rootdse_modify.ldif"))

    message("Setting up phpLDAPadmin configuration")
    create_phpldapadmin_config(paths.phpldapadminconfig, setup_path, 
                               ldapi_url)

    message("Please install the phpLDAPadmin configuration located at %s into /etc/phpldapadmin/config.php" % paths.phpldapadminconfig)

    if lp.get("server role") == "domain controller":
        samdb = SamDB(paths.samdb, session_info=session_info, 
                      credentials=credentials, lp=lp)

        domainguid = samdb.searchone(basedn=domaindn, attribute="objectGUID")
        assert isinstance(domainguid, str)
        hostguid = samdb.searchone(basedn=domaindn, attribute="objectGUID",
                expression="(&(objectClass=computer)(cn=%s))" % hostname,
                scope=SCOPE_SUBTREE)
        assert isinstance(hostguid, str)

        message("Setting up DNS zone: %s" % dnsdomain)
        create_zone_file(paths.dns, setup_path, samdb, 
                      hostname=hostname, hostip=hostip, dnsdomain=dnsdomain,
                      domaindn=domaindn, dnspass=dnspass, realm=realm, 
                      domainguid=domainguid, hostguid=hostguid)
        message("Please install the zone located in %s into your DNS server" % paths.dns)

    return domaindn


def create_phpldapadmin_config(path, setup_path, ldapi_uri):
    """Create a PHP LDAP admin configuration file.

    :param path: Path to write the configuration to.
    :param setup_path: Function to generate setup paths.
    """
    setup_file(setup_path("phpldapadmin-config.php"), path, 
            {"S4_LDAPI_URI": ldapi_uri})


def create_zone_file(path, setup_path, samdb, dnsdomain, domaindn, 
                  hostip, hostname, dnspass, realm, domainguid, hostguid):
    """Write out a DNS zone file, from the info in the current database.
    
    :param path: Path of the new file.
    :param setup_path": Setup path function.
    :param samdb: SamDB object
    :param dnsdomain: DNS Domain name
    :param domaindn: DN of the Domain
    :param hostip: Local IP
    :param hostname: Local hostname
    :param dnspass: Password for DNS
    :param realm: Realm name
    :param domainguid: GUID of the domain.
    :param hostguid: GUID of the host.
    """
    assert isinstance(domainguid, str)

    setup_file(setup_path("provision.zone"), path, {
            "DNSPASS_B64": b64encode(dnspass),
            "HOSTNAME": hostname,
            "DNSDOMAIN": dnsdomain,
            "REALM": realm,
            "HOSTIP": hostip,
            "DOMAINGUID": domainguid,
            "DATESTRING": time.strftime("%Y%m%d%H"),
            "DEFAULTSITE": DEFAULTSITE,
            "HOSTGUID": hostguid,
        })


def load_schema(setup_path, samdb, schemadn, netbiosname, configdn, sitename):
    """Load schema for the SamDB.
    
    :param samdb: Load a schema into a SamDB.
    :param setup_path: Setup path function.
    :param schemadn: DN of the schema
    :param netbiosname: NetBIOS name of the host.
    :param configdn: DN of the configuration
    """
    schema_data = open(setup_path("schema.ldif"), 'r').read()
    schema_data += open(setup_path("schema_samba4.ldif"), 'r').read()
    schema_data = substitute_var(schema_data, {"SCHEMADN": schemadn})
    head_data = open(setup_path("provision_schema_basedn_modify.ldif"), 'r').read()
    head_data = substitute_var(head_data, {
                    "SCHEMADN": schemadn,
                    "NETBIOSNAME": netbiosname,
                    "CONFIGDN": configdn,
                    "DEFAULTSITE":sitename 
    })
    samdb.attach_schema_from_ldif(head_data, schema_data)

