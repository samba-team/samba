#
#    backend code for provisioning a Samba4 server
#    Copyright Andrew Tridgell 2005
#    Copyright Jelmer Vernooij 2007
#    Released under the GNU GPL v2 or later
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
from samba import Ldb, substitute_var, valid_netbios_name
from samba.samdb import SamDB
import security
from ldb import Dn, SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, LdbError, \
        LDB_ERR_NO_SUCH_OBJECT, timestring


class InvalidNetbiosName(Exception):
    def __init__(self, name):
        super(InvalidNetbiosName, self).__init__("The name '%r' is not a valid NetBIOS name" % name)


class ProvisionSettings(object):
    def __init__(self, realm=None, domain=None, hostname=None, hostip=None):
        self.realm = realm
        self.domain = domain
        self.hostname = hostname
        self.hostip = hostip
        self.domainsid = None
        self.invocationid = None
        self.krbtgtpass = None
        self.machinepass = None
        self.adminpass = None
        self.defaultsite  = "Default-First-Site-Name"
        self.root = None
        self.nobody = None
        self.nogroup = None
        self.wheel = None
        self.backup = None
        self.users = None
        self.dnsdomain = None
        self.dnsname = None
        self.domaindn = None
        self.rootdn = None
        self.configdn = None
        self.schemedn = None
        self.schemedn_ldb = None
        self.s4_ldapi_path = None
        self.policyguid = None

    def fix(self, paths):
        self.realm       = self.realm.upper()
        self.hostname    = self.hostname.lower()
        self.domain      = self.domain.upper()
        if not valid_netbios_name(self.domain):
            raise InvalidNetbiosName(self.domain)
        self.netbiosname = self.hostname.upper()
        if not valid_netbios_name(self.netbiosname):
            raise InvalidNetbiosName(self.netbiosname)
        rdns = self.domaindn.split(",")
        self.rdn_dc = rdns[0][len("DC="):]

    def validate(self, lp):
        if not valid_netbios_name(self.domain):
            raise InvalidNetbiosName(self.domain)

        if not valid_netbios_name(self.netbiosname):
            raise InvalidNetbiosName(self.netbiosname)

        if lp.get("workgroup").upper() != self.domain.upper():
            raise Error("workgroup '%s' in smb.conf must match chosen domain '%s'\n",
                lp.get("workgroup"), self.domain)

        if lp.get("realm").upper() != self.realm.upper():
            raise Error("realm '%s' in smb.conf must match chosen realm '%s'\n" %
                (lp.get("realm"), self.realm))


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
        self.secrets = None
        self.keytab = None
        self.dns_keytab = None
        self.dns = None
        self.winsdb = None
        self.ldap_basedn_ldif = None
        self.ldap_config_basedn_ldif = None
        self.ldap_schema_basedn_ldif = None


def install_ok(lp, session_info, credentials):
    """Check whether the current install seems ok."""
    if lp.get("realm") == "":
        return False
    ldb = Ldb(lp.get("sam database"), session_info=session_info, 
            credentials=credentials, lp=lp)
    if len(ldb.search("(cn=Administrator)")) != 1:
        return False
    return True


def findnss(nssfn, *names):
    """Find a user or group from a list of possibilities."""
    for name in names:
        try:
            return nssfn(name)
        except KeyError:
            pass
    raise Exception("Unable to find user/group for %s" % arguments[1])


def hostip():
    """return first host IP."""
    return gethostbyname(hostname())


def hostname():
    """return first part of hostname."""
    return gethostname().split(".")[0]


def ldb_delete(ldb):
    """Delete a LDB file.

    This may be necessary if the ldb is in bad shape, possibly due to being 
    built from an incompatible previous version of the code, so delete it
    completely.
    """
    print "Deleting %s\n" % ldb.filename
    os.unlink(ldb.filename)
    ldb.connect(ldb.filename)


def open_ldb(session_info, credentials, lp, dbname):
    assert session_info is not None
    try:
        return Ldb(dbname, session_info=session_info, credentials=credentials, 
                   lp=lp)
    except LdbError, e:
        print e
        os.unlink(dbname)
        return Ldb(dbname, session_info=session_info, credentials=credentials,
                   lp=lp)


def setup_add_ldif(ldb, setup_dir, ldif, subst_vars=None):
    """Setup a ldb in the private dir."""
    assert isinstance(ldif, str)
    assert isinstance(setup_dir, str)
    src = os.path.join(setup_dir, ldif)

    data = open(src, 'r').read()
    if subst_vars is not None:
        data = substitute_var(data, subst_vars)

    assert "${" not in data

    for msg in ldb.parse_ldif(data):
        ldb.add(msg[1])


def setup_modify_ldif(ldb, setup_dir, ldif, substvars=None):
    src = os.path.join(setup_dir, ldif)

    data = open(src, 'r').read()
    if substvars is not None:
        data = substitute_var(data, substvars)

    assert "${" not in data

    for (changetype, msg) in ldb.parse_ldif(data):
        ldb.modify(msg)


def setup_ldb(ldb, setup_dir, ldif, subst_vars=None):
    assert ldb is not None
    ldb.transaction_start()
    try:
        setup_add_ldif(ldb, setup_dir, ldif, subst_vars)
    except:
        ldb.transaction_cancel()
        raise
    ldb.transaction_commit()


def setup_ldb_modify(ldb, setup_dir, ldif, substvars=None):
    """Modify a ldb in the private dir."""
    src = os.path.join(setup_dir, ldif)

    data = open(src, 'r').read()
    if substvars is not None:
        data = substitute_var(data, substvars)
    assert not "${" in data

    for (changetype, msg) in ldb.parse_ldif(data):
        ldb.modify(msg)


def setup_file(setup_dir, template, fname, substvars):
    """Setup a file in the private dir."""
    f = fname
    src = os.path.join(setup_dir, template)

    if os.path.exists(f):
        os.unlink(f)

    data = open(src, 'r').read()
    if substvars:
        data = substitute_var(data, substvars)
    assert not "${" in data

    open(f, 'w').write(data)


def provision_default_paths(lp, subobj):
    """Set the default paths for provisioning.

    :param lp: Loadparm context.
    :param subobj: Object
    """
    paths = ProvisionPaths()
    private_dir = lp.get("private dir")
    paths.shareconf = os.path.join(private_dir, "share.ldb")
    paths.samdb = os.path.join(private_dir, lp.get("sam database") or "samdb.ldb")
    paths.secrets = os.path.join(private_dir, lp.get("secrets database") or "secrets.ldb")
    paths.templates = os.path.join(private_dir, "templates.ldb")
    paths.keytab = os.path.join(private_dir, "secrets.keytab")
    paths.dns_keytab = os.path.join(private_dir, "dns.keytab")
    paths.dns = os.path.join(private_dir, subobj.dnsdomain + ".zone")
    paths.winsdb = os.path.join(private_dir, "wins.ldb")
    paths.ldap_basedn_ldif = os.path.join(private_dir, 
                                          subobj.dnsdomain + ".ldif")
    paths.ldap_config_basedn_ldif = os.path.join(private_dir, 
                                             subobj.dnsdomain + "-config.ldif")
    paths.ldap_schema_basedn_ldif = os.path.join(private_dir, 
                                              subobj.dnsdomain + "-schema.ldif")
    paths.s4_ldapi_path = os.path.join(private_dir, "ldapi")
    paths.phpldapadminconfig = os.path.join(private_dir, 
                                            "phpldapadmin-config.php")
    paths.hklm = os.path.join(private_dir, "hklm.ldb")
    paths.sysvol = lp.get("sysvol", "path")
    if paths.sysvol is None:
        paths.sysvol = os.path.join(lp.get("lock dir"), "sysvol")

    paths.netlogon = lp.get("netlogon", "path")
    if paths.netlogon is None:
        paths.netlogon = os.path.join(os.path.join(paths.sysvol, "scripts"))

    return paths


def setup_name_mappings(subobj, ldb):
    """setup reasonable name mappings for sam names to unix names."""
    sid = str(subobj.domainsid)

    # add some foreign sids if they are not present already
    ldb.add_foreign(subobj.domaindn, "S-1-5-7", "Anonymous")
    ldb.add_foreign(subobj.domaindn, "S-1-1-0", "World")
    ldb.add_foreign(subobj.domaindn, "S-1-5-2", "Network")
    ldb.add_foreign(subobj.domaindn, "S-1-5-18", "System")
    ldb.add_foreign(subobj.domaindn, "S-1-5-11", "Authenticated Users")

    # some well known sids
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-7", subobj.nobody)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-1-0", subobj.nogroup)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-2", subobj.nogroup)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-18", subobj.root)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-11", subobj.users)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-32-544", subobj.wheel)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-32-545", subobj.users)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-32-546", subobj.nogroup)
    ldb.setup_name_mapping(subobj.domaindn, "S-1-5-32-551", subobj.backup)

    # and some well known domain rids
    ldb.setup_name_mapping(subobj.domaindn, sid + "-500", subobj.root)
    ldb.setup_name_mapping(subobj.domaindn, sid + "-518", subobj.wheel)
    ldb.setup_name_mapping(subobj.domaindn, sid + "-519", subobj.wheel)
    ldb.setup_name_mapping(subobj.domaindn, sid + "-512", subobj.wheel)
    ldb.setup_name_mapping(subobj.domaindn, sid + "-513", subobj.users)
    ldb.setup_name_mapping(subobj.domaindn, sid + "-520", subobj.wheel)


def provision_become_dc(setup_dir, subobj, message, paths, lp, session_info, 
                        credentials):
    assert session_info is not None
    subobj.fix(paths)

    message("Setting up templates into %s" % paths.templates)
    setup_templatesdb(paths.templates, setup_dir, session_info, 
                      credentials, lp)

    # Also wipes the database
    message("Setting up samdb")
    os.path.unlink(paths.samdb)
    samdb = SamDB(paths.samdb, credentials=credentials, 
                  session_info=session_info, lp=lp)
    samdb.erase()

    message("Setting up %s partitions" % paths.samdb)
    setup_samdb_partitions(samdb, setup_dir, subobj.schemadn, 
                           subobj.configdn, subobj.domaindn)

    samdb = SamDB(paths.samdb, credentials=credentials, 
                  session_info=session_info, lp=lp)

    ldb.transaction_start()
    try:
        message("Setting up %s attributes" % paths.samdb)
        setup_add_ldif(samdb, setup_dir, "provision_init.ldif")

        message("Setting up %s rootDSE" % paths.samdb)
        setup_samdb_rootdse(samdb, setup_dir, subobj)

        message("Erasing data from partitions")
        ldb_erase_partitions(subobj, message, samdb, None)

        message("Setting up %s indexes" % paths.samdb)
        setup_add_ldif(samdb, setup_dir, "provision_index.ldif")
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()

    message("Setting up %s" % paths.secrets)
    secrets_ldb = setup_secretsdb(paths.secrets, setup_dir, session_info, credentials, lp)
    setup_ldb(secrets_ldb, setup_dir, "secrets_dc.ldif", 
              { "MACHINEPASS_B64": b64encode(self.machinepass) })


def setup_secretsdb(path, setup_dir, session_info, credentials, lp):
    secrets_ldb = Ldb(path, session_info=session_info, credentials=credentials, lp=lp)
    secrets_ldb.erase()
    setup_ldb(secrets_ldb, setup_dir, "secrets_init.ldif")
    setup_ldb(secrets_ldb, setup_dir, "secrets.ldif")
    return secrets_ldb


def setup_templatesdb(path, setup_dir, session_info, credentials, lp):
    templates_ldb = Ldb(path, session_info=session_info,
                        credentials=credentials, lp=lp)
    templates_ldb.erase()
    setup_ldb(templates_ldb, setup_dir, "provision_templates.ldif", None)


def setup_registry(path, setup_dir, session_info, credentials, lp):
    reg = registry.Registry()
    hive = registry.Hive(path, session_info=session_info, 
                         credentials=credentials, lp_ctx=lp)
    reg.mount_hive(hive, "HKEY_LOCAL_MACHINE")
    provision_reg = os.path.join(setup_dir, "provision.reg")
    assert os.path.exists(provision_reg)
    reg.apply_patchfile(provision_reg)


def setup_samdb_rootdse(samdb, setup_dir, subobj):
    setup_add_ldif(samdb, setup_dir, "provision_rootdse_add.ldif", {
        "SCHEMADN": subobj.schemadn, 
        "NETBIOSNAME": subobj.netbiosname,
        "DNSDOMAIN": subobj.dnsdomain,
        "DEFAULTSITE": subobj.defaultsite,
        "REALM": subobj.realm,
        "DNSNAME": subobj.dnsname,
        "DOMAINDN": subobj.domaindn,
        "ROOTDN": subobj.rootdn,
        "CONFIGDN": subobj.configdn,
        "VERSION": samba.version(),
        })


def setup_samdb_partitions(samdb, setup_dir, schemadn, configdn, domaindn):
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
                    "samldb",
                    "rdn_name",
                    "objectclass",
                    "kludge_acl",
                    "operational"]
    tdb_modules_list = [
                    "subtree_rename",
                    "subtree_delete",
                    "linked_attributes"]
    modules_list2 = ["show_deleted",
                    "partition"]
 
    setup_ldb(samdb, setup_dir, "provision_partitions.ldif", {
        "SCHEMADN": schemadn, 
        "SCHEMADN_LDB": "schema.ldb",
        "SCHEMADN_MOD2": ",objectguid",
        "CONFIGDN": configdn,
        "CONFIGDN_LDB": "configuration.ldb",
        "DOMAINDN": domaindn,
        "DOMAINDN_LDB": "users.ldb",
        "SCHEMADN_MOD": "schema_fsmo",
        "CONFIGDN_MOD": "naming_fsmo",
        "CONFIGDN_MOD2": ",objectguid",
        "DOMAINDN_MOD": "pdc_fsmo,password_hash",
        "DOMAINDN_MOD2": ",objectguid",
        "MODULES_LIST": ",".join(modules_list),
        "TDB_MODULES_LIST": ","+",".join(tdb_modules_list),
        "MODULES_LIST2": ",".join(modules_list2),
        })



def provision(lp, setup_dir, subobj, message, blank, paths, session_info, 
              credentials, ldapbackend):
    """Provision samba4
    
    :note: caution, this wipes all existing data!
    """
    subobj.fix(paths)

    assert paths.smbconf is not None

    # only install a new smb.conf if there isn't one there already
    if not os.path.exists(paths.smbconf):
        message("Setting up smb.conf")
        if lp.get("server role") == "domain controller":
            smbconfsuffix = "dc"
        elif lp.get("server role") == "member":
            smbconfsuffix = "member"
        else:
            assert "Invalid server role setting: %s" % lp.get("server role")
        setup_file(setup_dir, "provision.smb.conf.%s" % smbconfsuffix, paths.smbconf, 
                None)
        lp.reload()

    # only install a new shares config db if there is none
    if not os.path.exists(paths.shareconf):
        message("Setting up share.ldb")
        share_ldb = Ldb(paths.shareconf, session_info=session_info, 
                        credentials=credentials, lp=lp)
        setup_ldb(share_ldb, setup_dir, "share.ldif", None)

    message("Setting up %s" % paths.secrets)
    secrets_ldb = setup_secretsdb(paths.secrets, setup_dir, session_info=session_info, 
                    credentials=credentials, lp=lp)

    message("Setting up registry")
    # FIXME: Still fails for some reason
    #setup_registry(paths.hklm, setup_dir, session_info, 
    #               credentials=credentials, lp=lp)

    message("Setting up templates into %s" % paths.templates)
    setup_templatesdb(paths.templates, setup_dir, session_info=session_info, 
                      credentials=credentials, lp=lp)

    samdb = SamDB(paths.samdb, session_info=session_info, 
                  credentials=credentials, lp=lp)
    samdb.erase()

    message("Setting up sam.ldb partitions")
    setup_samdb_partitions(samdb, setup_dir, subobj.schemadn,
                           subobj.configdn, subobj.domaindn)

    samdb = SamDB(paths.samdb, session_info=session_info, 
                  credentials=credentials, lp=lp)

    samdb.transaction_start()
    try:
        message("Setting up sam.ldb attributes")
        setup_add_ldif(samdb, setup_dir, "provision_init.ldif")

        message("Setting up sam.ldb rootDSE")
        setup_samdb_rootdse(samdb, setup_dir, subobj)

        message("Erasing data from partitions")
        ldb_erase_partitions(subobj, message, samdb, ldapbackend)
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()

    message("Pre-loading the Samba 4 and AD schema")
    samdb = SamDB(paths.samdb, session_info=session_info, 
                  credentials=credentials, lp=lp)
    samdb.set_domain_sid(subobj.domainsid)
    load_schema(setup_dir, samdb, subobj)

    samdb.transaction_start()
        
    try:
        message("Adding DomainDN: %s (permitted to fail)" % subobj.domaindn)
        setup_add_ldif(samdb, setup_dir, "provision_basedn.ldif", {
            "DOMAINDN": subobj.domaindn,
            "ACI": "# no aci for local ldb",
            "EXTENSIBLEOBJECT": "# no objectClass: extensibleObject for local ldb",
            "RDN_DC": subobj.rdn_dc,
            })

        message("Modifying DomainDN: " + subobj.domaindn + "")
        if subobj.domain_guid is not None:
            domainguid_mod = "replace: objectGUID\nobjectGUID: %s\n-" % subobj.domain_guid
        else:
            domainguid_mod = ""

        setup_ldb_modify(samdb, setup_dir, "provision_basedn_modify.ldif", {
            "RDN_DC": subobj.rdn_dc,
            "LDAPTIME": timestring(int(time.time())),
            "DOMAINSID": str(subobj.domainsid),
            "SCHEMADN": subobj.schemadn, 
            "NETBIOSNAME": subobj.netbiosname,
            "DEFAULTSITE": subobj.defaultsite,
            "CONFIGDN": subobj.configdn,
            "POLICYGUID": subobj.policyguid,
            "DOMAINDN": subobj.domaindn,
            "DOMAINGUID_MOD": domainguid_mod,
            })

        message("Adding configuration container (permitted to fail)")
        setup_add_ldif(samdb, setup_dir, "provision_configuration_basedn.ldif", {
            "CONFIGDN": subobj.configdn, 
            "ACI": "# no aci for local ldb",
            "EXTENSIBLEOBJECT": "# no objectClass: extensibleObject for local ldb",
            })
        message("Modifying configuration container")
        setup_ldb_modify(samdb, setup_dir, "provision_configuration_basedn_modify.ldif", {
            "CONFIGDN": subobj.configdn, 
            "SCHEMADN": subobj.schemadn,
            })

        message("Adding schema container (permitted to fail)")
        setup_add_ldif(samdb, setup_dir, "provision_schema_basedn.ldif", {
            "SCHEMADN": subobj.schemadn,
            "ACI": "# no aci for local ldb",
            "EXTENSIBLEOBJECT": "# no objectClass: extensibleObject for local ldb"
            })
        message("Modifying schema container")
        setup_ldb_modify(samdb, setup_dir, "provision_schema_basedn_modify.ldif", {
            "SCHEMADN": subobj.schemadn,
            "NETBIOSNAME": subobj.netbiosname,
            "DEFAULTSITE": subobj.defaultsite,
            "CONFIGDN": subobj.configdn,
            })

        message("Setting up sam.ldb Samba4 schema")
        setup_add_ldif(samdb, setup_dir, "schema_samba4.ldif", {
            "SCHEMADN": subobj.schemadn,
            })
        message("Setting up sam.ldb AD schema")
        setup_add_ldif(samdb, setup_dir, "schema.ldif", {
            "SCHEMADN": subobj.schemadn,
            })

        message("Setting up sam.ldb configuration data")
        setup_add_ldif(samdb, setup_dir, "provision_configuration.ldif", {
            "CONFIGDN": subobj.configdn,
            "NETBIOSNAME": subobj.netbiosname,
            "DEFAULTSITE": subobj.defaultsite,
            "DNSDOMAIN": subobj.dnsdomain,
            "DOMAIN": subobj.domain,
            "SCHEMADN": subobj.schemadn,
            "DOMAINDN": subobj.domaindn,
            })

        message("Setting up display specifiers")
        setup_add_ldif(samdb, setup_dir, "display_specifiers.ldif", {"CONFIGDN": subobj.configdn})

        message("Adding users container (permitted to fail)")
        setup_add_ldif(samdb, setup_dir, "provision_users_add.ldif", {
            "DOMAINDN": subobj.domaindn})
        message("Modifying users container")
        setup_ldb_modify(samdb, setup_dir, "provision_users_modify.ldif", {
            "DOMAINDN": subobj.domaindn})
        message("Adding computers container (permitted to fail)")
        setup_add_ldif(samdb, setup_dir, "provision_computers_add.ldif", {
            "DOMAINDN": subobj.domaindn})
        message("Modifying computers container")
        setup_ldb_modify(samdb, setup_dir, "provision_computers_modify.ldif", {
            "DOMAINDN": subobj.domaindn})
        message("Setting up sam.ldb data")
        setup_add_ldif(samdb, setup_dir, "provision.ldif", {
            "DOMAINDN": subobj.domaindn,
            "NETBIOSNAME": subobj.netbiosname,
            "DEFAULTSITE": subobj.defaultsite,
            "CONFIGDN": subobj.configdn,
            })

        if not blank:

    #    message("Activate schema module")
    #    setup_modify_ldif("schema_activation.ldif", info, samdb, False)
    #
    #    // (hack) Reload, now we have the schema loaded.  
    #    commit_ok = samdb.transaction_commit()
    #    if (!commit_ok) {
    #        message("samdb commit failed: " + samdb.errstring() + "\n")
    #        assert(commit_ok)
    #    }
    #    samdb.close()
    #
    #    samdb = open_ldb(info, paths.samdb, False)
    #
            message("Setting up sam.ldb users and groups")
            setup_add_ldif(samdb, setup_dir, "provision_users.ldif", {
                "DOMAINDN": subobj.domaindn,
                "DOMAINSID": str(subobj.domainsid),
                "CONFIGDN": subobj.configdn,
                "ADMINPASS_B64": b64encode(subobj.adminpass),
                "KRBTGTPASS_B64": b64encode(subobj.krbtgtpass),
                })

            if lp.get("server role") == "domain controller":
                message("Setting up self join")
                if subobj.host_guid is not None:
                    hostguid_add = "objectGUID: %s" % subobj.host_guid
                else:
                    hostguid_add = ""

                setup_add_ldif(samdb, setup_dir, "provision_self_join.ldif", { 
                          "CONFIGDN": subobj.configdn, 
                          "SCHEMADN": subobj.schemadn,
                          "DOMAINDN": subobj.domaindn,
                          "INVOCATIONID": subobj.invocationid,
                          "NETBIOSNAME": subobj.netbiosname,
                          "DEFAULTSITE": subobj.defaultsite,
                          "DNSNAME": subobj.dnsname,
                          "MACHINEPASS_B64": b64encode(subobj.machinepass),
                          "DNSPASS_B64": b64encode(subobj.dnspass),
                          "REALM": subobj.realm,
                          "DOMAIN": subobj.domain,
                          "HOSTGUID_ADD": hostguid_add,
                          "DNSDOMAIN": subobj.dnsdomain})
                setup_add_ldif(samdb, setup_dir, "provision_group_policy.ldif", { 
                          "POLICYGUID": subobj.policyguid,
                          "DNSDOMAIN": subobj.dnsdomain,
                          "DOMAINSID": str(subobj.domainsid),
                          "DOMAINDN": subobj.domaindn})

                os.makedirs(os.path.join(paths.sysvol, subobj.dnsdomain, "Policies", "{" + subobj.policyguid + "}"), 0755)
                os.makedirs(os.path.join(paths.sysvol, subobj.dnsdomain, "Policies", "{" + subobj.policyguid + "}", "Machine"), 0755)
                os.makedirs(os.path.join(paths.sysvol, subobj.dnsdomain, "Policies", "{" + subobj.policyguid + "}", "User"), 0755)
                if not os.path.isdir(paths.netlogon):
                    os.makedirs(paths.netlogon, 0755)
                setup_ldb(secrets_ldb, setup_dir, "secrets_dc.ldif", { 
                    "MACHINEPASS_B64": b64encode(subobj.machinepass),
                    "DOMAIN": subobj.domain,
                    "REALM": subobj.realm,
                    "LDAPTIME": timestring(int(time.time())),
                    "DNSDOMAIN": subobj.dnsdomain,
                    "DOMAINSID": str(subobj.domainsid),
                    "SECRETS_KEYTAB": paths.keytab,
                    "NETBIOSNAME": subobj.netbiosname,
                    "SAM_LDB": paths.samdb,
                    "DNS_KEYTAB": paths.dns_keytab,
                    "DNSPASS_B64": b64encode(subobj.dnspass),
                    })

            setup_name_mappings(subobj, samdb)

        message("Setting up sam.ldb index")
        setup_add_ldif(samdb, setup_dir, "provision_index.ldif")

        message("Setting up sam.ldb rootDSE marking as syncronized")
        setup_modify_ldif(samdb, setup_dir, "provision_rootdse_modify.ldif")
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()

    message("Setting up phpLDAPadmin configuration")
    create_phplpapdadmin_config(paths.phpldapadminconfig, setup_dir, paths.s4_ldapi_path)

    message("Please install the phpLDAPadmin configuration located at %s into /etc/phpldapadmin/config.php" % paths.phpldapadminconfig)


def create_phplpapdadmin_config(path, setup_dir, s4_ldapi_path):
    setup_file(setup_dir, "phpldapadmin-config.php", 
               path, {"S4_LDAPI_URI": "ldapi://%s" % s4_ldapi_path.replace("/", "%2F")})


def provision_dns(setup_dir, subobj, message, paths, session_info, credentials, lp):
    """Write out a DNS zone file, from the info in the current database."""
    message("Setting up DNS zone: %s" % subobj.dnsdomain)
    # connect to the sam
    ldb = SamDB(paths.samdb, session_info=session_info, credentials=credentials,
                lp=lp)

    # These values may have changed, due to an incoming SamSync,
    # or may not have been specified, so fetch them from the database
    domainguid = str(ldb.searchone(Dn(ldb, subobj.domaindn), "objectGUID"))

    hostguid = str(ldb.searchone(Dn(ldb, subobj.domaindn), "objectGUID" ,
                                 expression="(&(objectClass=computer)(cn=%s))" % subobj.netbiosname))

    setup_file(setup_dir, "provision.zone", paths.dns, {
            "DNSPASS_B64": b64encode(subobj.dnspass),
            "HOSTNAME": hostname(),
            "DNSDOMAIN": subobj.dnsdomain,
            "REALM": subobj.realm,
            "HOSTIP": hostip(),
            "DOMAINGUID": domainguid,
            "DATESTRING": time.strftime("%Y%m%d%H"),
            "DEFAULTSITE": subobj.defaultsite,
            "HOSTGUID": hostguid,
        })

    message("Please install the zone located in %s into your DNS server" % paths.dns)


def provision_ldapbase(setup_dir, subobj, message, paths):
    """Write out a DNS zone file, from the info in the current database."""
    message("Setting up LDAP base entry: %s" % subobj.domaindn)
    rdns = subobj.domaindn.split(",")

    subobj.rdn_dc = rdns[0][len("DC="):]

    setup_file(setup_dir, "provision_basedn.ldif", 
           paths.ldap_basedn_ldif, 
           None)

    setup_file(setup_dir, "provision_configuration_basedn.ldif", 
           paths.ldap_config_basedn_ldif, None)

    setup_file(setup_dir, "provision_schema_basedn.ldif", 
           paths.ldap_schema_basedn_ldif, {
            "SCHEMADN": subobj.schemadn,
            "ACI": "# no aci for local ldb",
            "EXTENSIBLEOBJECT": "objectClass: extensibleObject"})

    message("Please install the LDIF located in " + paths.ldap_basedn_ldif + ", " + paths.ldap_config_basedn_ldif + " and " + paths.ldap_schema_basedn_ldif + " into your LDAP server, and re-run with --ldap-backend=ldap://my.ldap.server")


def provision_guess(lp):
    """guess reasonably default options for provisioning."""
    subobj = ProvisionSettings(realm=lp.get("realm").upper(),
                               domain=lp.get("workgroup"),
                               hostname=hostname(), 
                               hostip=hostip())

    assert subobj.realm is not None
    assert subobj.domain is not None
    assert subobj.hostname is not None
    
    subobj.domainsid    = security.random_sid()
    subobj.invocationid = uuid.random()
    subobj.policyguid   = uuid.random()
    subobj.krbtgtpass   = misc.random_password(12)
    subobj.machinepass  = misc.random_password(12)
    subobj.adminpass    = misc.random_password(12)
    subobj.dnspass      = misc.random_password(12)
    subobj.root         = findnss(pwd.getpwnam, "root")[4]
    subobj.nobody       = findnss(pwd.getpwnam, "nobody")[4]
    subobj.nogroup      = findnss(grp.getgrnam, "nogroup", "nobody")[2]
    subobj.wheel        = findnss(grp.getgrnam, "wheel", "root", "staff", "adm")[2]
    subobj.backup       = findnss(grp.getgrnam, "backup", "wheel", "root", "staff")[2]
    subobj.users        = findnss(grp.getgrnam, "users", "guest", "other", "unknown", "usr")[2]

    subobj.dnsdomain    = subobj.realm.lower()
    subobj.dnsname      = "%s.%s" % (subobj.hostname.lower(), subobj.dnsdomain)
    subobj.domaindn     = "DC=" + subobj.dnsdomain.replace(".", ",DC=")
    subobj.rootdn       = subobj.domaindn
    subobj.configdn     = "CN=Configuration," + subobj.rootdn
    subobj.schemadn     = "CN=Schema," + subobj.configdn

    return subobj


def load_schema(setup_dir, samdb, subobj):
    """Load schema."""
    src = os.path.join(setup_dir, "schema.ldif")
    schema_data = open(src, 'r').read()
    src = os.path.join(setup_dir, "schema_samba4.ldif")
    schema_data += open(src, 'r').read()
    schema_data = substitute_var(schema_data, {"SCHEMADN": subobj.schemadn})
    src = os.path.join(setup_dir, "provision_schema_basedn_modify.ldif")
    head_data = open(src, 'r').read()
    head_data = substitute_var(head_data, {
                    "SCHEMADN": subobj.schemadn,
                    "NETBIOSNAME": subobj.netbiosname,
                    "CONFIGDN": subobj.configdn,
                    "DEFAULTSITE": subobj.defaultsite})
    samdb.attach_schema_from_ldif(head_data, schema_data)


def join_domain(domain, netbios_name, join_type, creds, message):
    ctx = NetContext(creds)
    joindom = object()
    joindom.domain = domain
    joindom.join_type = join_type
    joindom.netbios_name = netbios_name
    if not ctx.JoinDomain(joindom):
        raise Exception("Domain Join failed: " + joindom.error_string)


def vampire(domain, session_info, credentials, message):
    """Vampire a remote domain.  
    
    Session info and credentials are required for for
    access to our local database (might be remote ldap)
    """
    ctx = NetContext(credentials)
    vampire_ctx = object()
    machine_creds = credentials_init()
    machine_creds.set_domain(form.domain)
    if not machine_creds.set_machine_account():
        raise Exception("Failed to access domain join information!")
    vampire_ctx.machine_creds = machine_creds
    vampire_ctx.session_info = session_info
    if not ctx.SamSyncLdb(vampire_ctx):
        raise Exception("Migration of remote domain to Samba failed: %s " % vampire_ctx.error_string)


def ldb_erase_partitions(subobj, message, ldb, ldapbackend):
    """Erase an ldb, removing all records."""
    assert ldb is not None
    res = ldb.search(Dn(ldb, ""), SCOPE_BASE, "(objectClass=*)", 
                     ["namingContexts"])
    assert len(res) == 1
    if not "namingContexts" in res[0]:
        return
    for basedn in res[0]["namingContexts"]:
        anything = "(|(objectclass=*)(dn=*))"
        previous_remaining = 1
        current_remaining = 0

        if ldapbackend and (basedn == subobj.domaindn):
            # Only delete objects that were created by provision
            anything = "(objectcategory=*)"

        k = 0
        while ++k < 10 and (previous_remaining != current_remaining):
            # and the rest
            res2 = ldb.search(Dn(ldb, basedn), SCOPE_SUBTREE, anything, ["dn"])
            previous_remaining = current_remaining
            current_remaining = len(res2)
            for msg in res2:
                try:
                    ldb.delete(msg.dn)
                except LdbError, (_, text):
                    message("Unable to delete %s: %s" % (msg.dn, text))


