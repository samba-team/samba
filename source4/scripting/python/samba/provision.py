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
import uuid, sid, misc
from socket import gethostname, gethostbyname
import param
import registry
from samba import Ldb, substitute_var
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
        self.datestring = None
        self.root = None
        self.nobody = None
        self.nogroup = None
        self.wheel = None
        self.backup = None
        self.users = None
        self.dnsdomain = None
        self.dnsname = None
        self.domaindn = None
        self.domaindn_ldb = None
        self.rootdn = None
        self.configdn = None
        self.configdn_ldb = None
        self.schemedn = None
        self.schemedn_ldb = None
        self.s4_ldapi_path = None
        self.policyguid = None

    def subst_vars(self):
        return {"SCHEMADN": self.schemadn,
                "SCHEMADN_LDB": self.schemadn_ldb,
                "SCHEMADN_MOD": "schema_fsmo",
                "SCHEMADN_MOD2": ",objectguid",
                "CONFIGDN": self.configdn,
                "TDB_MODULES_LIST": ","+",".join(self.tdb_modules_list)
                "MODULES_LIST2": ",".join(self.modules_list2)
                "CONFIGDN_LDB": self.configdn_ldb,
                "DOMAINDN": self.domaindn,
                "DOMAINDN_LDB": self.domaindn_ldb,
                "DOMAINDN_MOD": "pdc_fsmo,password_hash",
                "DOMAINDN_MOD2": ",objectguid",
                "DOMAINSID": self.domainsid,
                "MODULES_LIST": ",".join(self.modules_list),
                "CONFIGDN_MOD": "naming_fsmo",
                "CONFIGDN_MOD2": ",objectguid",
                "NETBIOSNAME": self.netbiosname,
                "DNSNAME": self.dnsname,
                "ROOTDN": self.rootdn,
                "DNSDOMAIN": self.dnsdomain,
                "REALM": self.realm,
                "DEFAULTSITE": self.defaultsite,
                "MACHINEPASS_B64": b64encode(self.machinepass),
                "ADMINPASS_B64": b64encode(self.adminpass),
                "DNSPASS_B64": b64encode(self.dnspass),
                "KRBTGTPASS_B64": b64encode(self.krbtgtpass),
                "S4_LDAPI_URI": "ldapi://%s" % self.s4_ldapi_path.replace("/", "%2F"),
                "LDAPTIME": timestring(int(time.time())),
                "POLICYGUID": self.policyguid,
                "RDN_DC": self.rdn_dc,
                "DOMAINGUID_MOD": self.domainguid_mod,
                }

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

        self.sam_ldb        = paths.samdb
        self.secrets_ldb    = paths.secrets
        self.secrets_keytab    = paths.keytab
        
        self.s4_ldapi_path = paths.s4_ldapi_path

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
        self.dns = None
        self.winsdb = None
        self.ldap_basedn_ldif = None
        self.ldap_config_basedn_ldif = None
        self.ldap_schema_basedn_ldif = None
        self.s4_ldapi_path = None


def install_ok(lp, session_info, credentials):
    """Check whether the current install seems ok."""
    if lp.get("realm") == "":
        return False
    ldb = Ldb(lp.get("sam database"), session_info=session_info, 
            credentials=credentials)
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

def add_foreign(ldb, subobj, sid, desc):
    """Add a foreign security principle."""
    add = """
dn: CN=%s,CN=ForeignSecurityPrincipals,%s
objectClass: top
objectClass: foreignSecurityPrincipal
description: %s
""" % (sid, subobj.domaindn, desc)
    # deliberately ignore errors from this, as the records may
    # already exist
    for msg in ldb.parse_ldif(add):
        ldb.add(msg[1])

def setup_name_mapping(subobj, ldb, sid, unixname):
    """Setup a mapping between a sam name and a unix name."""
    res = ldb.search(Dn(ldb, subobj.domaindn), SCOPE_SUBTREE, 
                     "objectSid=%s" % sid, ["dn"])
    assert len(res) == 1, "Failed to find record for objectSid %s" % sid

    mod = """
dn: %s
changetype: modify
replace: unixName
unixName: %s
""" % (res[0].dn, unixname)
    ldb.modify(ldb.parse_ldif(mod).next()[1])

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


def ldb_erase(ldb):
    """Erase an ldb, removing all records."""
    # delete the specials
    for attr in ["@INDEXLIST", "@ATTRIBUTES", "@SUBCLASSES", "@MODULES", 
                 "@OPTIONS", "@PARTITION", "@KLUDGEACL"]:
        try:
            ldb.delete(Dn(ldb, attr))
        except LdbError, (LDB_ERR_NO_SUCH_OBJECT, _):
            # Ignore missing dn errors
            pass

    basedn = Dn(ldb, "")
    # and the rest
    for msg in ldb.search(basedn, SCOPE_SUBTREE, 
            "(&(|(objectclass=*)(dn=*))(!(dn=@BASEINFO)))", 
            ["dn"]):
        ldb.delete(msg.dn)

    res = ldb.search(basedn, SCOPE_SUBTREE, "(&(|(objectclass=*)(dn=*))(!(dn=@BASEINFO)))", ["dn"])
    assert len(res) == 0


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


def open_ldb(session_info, credentials, dbname):
    assert session_info is not None
    try:
        return Ldb(dbname, session_info=session_info, credentials=credentials)
    except LdbError, e:
        print e
        os.unlink(dbname)
        return Ldb(dbname, session_info=session_info, credentials=credentials)


def setup_add_ldif(setup_dir, ldif, subobj, ldb):
    """Setup a ldb in the private dir."""
    assert isinstance(ldif, str)
    assert isinstance(setup_dir, str)
    src = os.path.join(setup_dir, ldif)

    data = open(src, 'r').read()
    data = substitute_var(data, subobj.subst_vars())

    for msg in ldb.parse_ldif(data):
        ldb.add(msg[1])


def setup_modify_ldif(setup_dir, ldif, subobj, ldb):
    src = os.path.join(setup_dir, ldif)

    data = open(src, 'r').read()
    data = substitute_var(data, subobj.subst_vars())

    for (changetype, msg) in ldb.parse_ldif(data):
        ldb.modify(msg)


def setup_ldb(setup_dir, ldif, session_info, credentials, subobj, dbname, 
              erase=True):
    assert dbname is not None
    ldb = open_ldb(session_info, credentials, dbname)
    assert ldb is not None
    ldb.transaction_start()
    try:
        if erase:
            ldb_erase(ldb);    
        setup_add_ldif(setup_dir, ldif, subobj, ldb)
    except:
        ldb.transaction_cancel()
        raise
    ldb.transaction_commit()


def setup_ldb_modify(setup_dir, ldif, subobj, ldb):
    """Modify a ldb in the private dir."""
    src = os.path.join(setup_dir, ldif)

    data = open(src, 'r').read()
    data = substitute_var(data, subobj.subst_vars())
    assert not "${" in data

    for (changetype, msg) in ldb.parse_ldif(data):
        ldb.modify(msg)


def setup_file(setup_dir, template, message, fname, subobj):
    """Setup a file in the private dir."""
    f = fname
    src = os.path.join(setup_dir, template)

    os.unlink(f)

    data = open(src, 'r').read()
    data = substitute_var(data, subobj.subst_vars())
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
    paths.samdb = lp.get("sam database") or os.path.join(private_dir, "samdb.ldb")
    paths.secrets = lp.get("secrets database") or os.path.join(private_dir, "secrets.ldb")
    paths.templates = os.path.join(private_dir, "templates.ldb")
    paths.keytab = os.path.join(private_dir, "secrets.keytab")
    paths.dns = os.path.join(private_dir, subobj.dnsdomain + ".zone")
    paths.winsdb = os.path.join(private_dir, "wins.ldb")
    paths.ldap_basedn_ldif = os.path.join(private_dir, subobj.dnsdomain + ".ldif")
    paths.ldap_config_basedn_ldif = os.path.join(private_dir, subobj.dnsdomain + "-config.ldif")
    paths.ldap_schema_basedn_ldif = os.path.join(private_dir, subobj.dnsdomain + "-schema.ldif")
    paths.s4_ldapi_path = os.path.join(private_dir, "ldapi")
    paths.phpldapadminconfig = os.path.join(private_dir, "phpldapadmin-config.php")
    paths.hklm = os.path.join(private_dir, "hklm.ldb")
    return paths


def setup_name_mappings(subobj, ldb):
    """setup reasonable name mappings for sam names to unix names."""
    res = ldb.search(Dn(ldb, subobj.domaindn), SCOPE_BASE, "objectSid=*", 
                     ["objectSid"])
    assert len(res) == 1
    assert "objectSid" in res[0]
    sid = list(res[0]["objectSid"])[0]

    # add some foreign sids if they are not present already
    add_foreign(ldb, subobj, "S-1-5-7", "Anonymous")
    add_foreign(ldb, subobj, "S-1-1-0", "World")
    add_foreign(ldb, subobj, "S-1-5-2", "Network")
    add_foreign(ldb, subobj, "S-1-5-18", "System")
    add_foreign(ldb, subobj, "S-1-5-11", "Authenticated Users")

    # some well known sids
    setup_name_mapping(subobj, ldb, "S-1-5-7", subobj.nobody)
    setup_name_mapping(subobj, ldb, "S-1-1-0", subobj.nogroup)
    setup_name_mapping(subobj, ldb, "S-1-5-2", subobj.nogroup)
    setup_name_mapping(subobj, ldb, "S-1-5-18", subobj.root)
    setup_name_mapping(subobj, ldb, "S-1-5-11", subobj.users)
    setup_name_mapping(subobj, ldb, "S-1-5-32-544", subobj.wheel)
    setup_name_mapping(subobj, ldb, "S-1-5-32-545", subobj.users)
    setup_name_mapping(subobj, ldb, "S-1-5-32-546", subobj.nogroup)
    setup_name_mapping(subobj, ldb, "S-1-5-32-551", subobj.backup)

    # and some well known domain rids
    setup_name_mapping(subobj, ldb, sid + "-500", subobj.root)
    setup_name_mapping(subobj, ldb, sid + "-518", subobj.wheel)
    setup_name_mapping(subobj, ldb, sid + "-519", subobj.wheel)
    setup_name_mapping(subobj, ldb, sid + "-512", subobj.wheel)
    setup_name_mapping(subobj, ldb, sid + "-513", subobj.users)
    setup_name_mapping(subobj, ldb, sid + "-520", subobj.wheel)


def provision_become_dc(setup_dir, subobj, message, paths, session_info, 
                        credentials):
    assert session_info is not None
    subobj.fix(paths)

    message("Setting up templates into %s" % paths.templates)
    setup_ldb(setup_dir, "provision_templates.ldif", session_info,
              credentials, subobj, paths.templates)

    # Also wipes the database
    message("Setting up %s partitions" % paths.samdb)
    setup_ldb(setup_dir, "provision_partitions.ldif", session_info, 
              credentials, subobj, paths.samdb)

    samdb = open_ldb(session_info, credentials, paths.samdb)
    ldb.transaction_start()
    try:
        message("Setting up %s attributes" % paths.samdb)
        setup_add_ldif(setup_dir, "provision_init.ldif", subobj, samdb)

        message("Setting up %s rootDSE" % paths.samdb)
        setup_add_ldif(setup_dir, "provision_rootdse_add.ldif", subobj, samdb)

        message("Erasing data from partitions")
        ldb_erase_partitions(subobj, message, samdb, undefined)

        message("Setting up %s indexes" % paths.samdb)
        setup_add_ldif(setup_dir, "provision_index.ldif", subobj, samdb)
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()

    message("Setting up %s" % paths.secrets)
    setup_ldb(setup_dir, "secrets_init.ldif", session_info, credentials, 
              subobj, paths.secrets)

    setup_ldb(setup_dir, "secrets.ldif", session_info, credentials, subobj, 
              paths.secrets, False)


def provision(lp, setup_dir, subobj, message, blank, paths, session_info, 
              credentials, ldapbackend):
    """Provision samba4
    
    :note: caution, this wipes all existing data!
    """
    subobj.fix(paths)

    if subobj.domain_guid is not None:
        subobj.domainguid_mod = "replace: objectGUID\nobjectGUID: %s\n-" % subobj.domain_guid
    else:
        subobj.domainguid_mod = ""

    if subobj.host_guid is not None:
        subobj.hostguid_add = "objectGUID: %s" % subobj.host_guid
    else:
        subobj.hostguid_add = ""

    assert paths.smbconf is not None

    # only install a new smb.conf if there isn't one there already
    if not os.path.exists(paths.smbconf):
        message("Setting up smb.conf")
        setup_file(setup_dir, "provision.smb.conf", message, paths.smbconf, subobj)
        lp.reload()

    # only install a new shares config db if there is none
    if not os.path.exists(paths.shareconf):
        message("Setting up share.ldb")
        setup_ldb(setup_dir, "share.ldif", session_info, credentials, subobj, paths.shareconf)

    message("Setting up %s" % paths.secrets)
    setup_ldb(setup_dir, "secrets_init.ldif", session_info, credentials, subobj, paths.secrets)
    setup_ldb(setup_dir, "secrets.ldif", session_info, credentials, subobj, paths.secrets, False)

    message("Setting up registry")
    reg = registry.Registry()
    # FIXME: Still fails for some reason:
    #reg.mount(paths.hklm, registry.HKEY_LOCAL_MACHINE, [])
    #reg.apply_patchfile(os.path.join(setup_dir, "provision.reg"))

    message("Setting up templates into %s" % paths.templates)
    setup_ldb(setup_dir, "provision_templates.ldif", session_info, credentials, subobj, paths.templates)

    message("Setting up sam.ldb partitions")
    setup_ldb(setup_dir, "provision_partitions.ldif", session_info, 
              credentials, subobj, paths.samdb)

    samdb = open_ldb(session_info, credentials, paths.samdb)
    samdb.transaction_start()
    try:
        message("Setting up sam.ldb attributes")
        setup_add_ldif(setup_dir, "provision_init.ldif", subobj, samdb)

        message("Setting up sam.ldb rootDSE")
        setup_add_ldif(setup_dir, "provision_rootdse_add.ldif", subobj, samdb)

        message("Erasing data from partitions")
        ldb_erase_partitions(subobj, message, samdb, ldapbackend)
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()

    message("Pre-loading the Samba 4 and AD schema")

    samdb = open_ldb(session_info, credentials, paths.samdb)

    samdb.set_domain_sid(subobj.domainsid)

    load_schema(setup_dir, subobj, samdb)

    samdb.transaction_start()
        
    try:
        message("Adding DomainDN: %s (permitted to fail)" % subobj.domaindn)
        setup_add_ldif(setup_dir, "provision_basedn.ldif", subobj, samdb)
        message("Modifying DomainDN: " + subobj.domaindn + "")
        setup_ldb_modify(setup_dir, "provision_basedn_modify.ldif", subobj, samdb)

        message("Adding configuration container (permitted to fail)")
        setup_add_ldif(setup_dir, "provision_configuration_basedn.ldif", subobj, samdb)
        message("Modifying configuration container")
        setup_ldb_modify(setup_dir, "provision_configuration_basedn_modify.ldif", subobj, samdb)

        message("Adding schema container (permitted to fail)")
        setup_add_ldif(setup_dir, "provision_schema_basedn.ldif", subobj, samdb)
        message("Modifying schema container")
        setup_ldb_modify(setup_dir, "provision_schema_basedn_modify.ldif", subobj, samdb)
        message("Setting up sam.ldb Samba4 schema")
        setup_add_ldif(setup_dir, "schema_samba4.ldif", subobj, samdb)
        message("Setting up sam.ldb AD schema")
        setup_add_ldif(setup_dir, "schema.ldif", subobj, samdb)

        message("Setting up sam.ldb configuration data")
        setup_add_ldif(setup_dir, "provision_configuration.ldif", subobj, samdb)

        message("Setting up display specifiers")
        setup_add_ldif(setup_dir, "display_specifiers.ldif", subobj, samdb)

        message("Adding users container (permitted to fail)")
        setup_add_ldif(setup_dir, "provision_users_add.ldif", subobj, samdb)
        message("Modifying users container")
        setup_ldb_modify(setup_dir, "provision_users_modify.ldif", subobj, samdb)
        message("Adding computers container (permitted to fail)")
        setup_add_ldif(setup_dir, "provision_computers_add.ldif", subobj, samdb)
        message("Modifying computers container")
        setup_ldb_modify(setup_dir, "provision_computers_modify.ldif", subobj, samdb)
        message("Setting up sam.ldb data")
        setup_add_ldif(setup_dir, "provision.ldif", subobj, samdb)

        if blank:
            message("Setting up sam.ldb index")
            setup_add_ldif(setup_dir, "provision_index.ldif", subobj, samdb)

            message("Setting up sam.ldb rootDSE marking as syncronized")
            setup_modify_ldif(setup_dir, "provision_rootdse_modify.ldif", subobj, samdb)

            samdb.transaction_commit()
            return

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
        setup_add_ldif(setup_dir, "provision_users.ldif", subobj, samdb)

        setup_name_mappings(subobj, samdb)

        message("Setting up sam.ldb index")
        setup_add_ldif(setup_dir, "provision_index.ldif", subobj, samdb)

        message("Setting up sam.ldb rootDSE marking as syncronized")
        setup_modify_ldif(setup_dir, "provision_rootdse_modify.ldif", subobj, samdb)
    except:
        samdb.transaction_cancel()
        raise

    samdb.transaction_commit()

    message("Setting up phpLDAPadmin configuration")
    setup_file(setup_dir, "phpldapadmin-config.php", message, 
               paths.phpldapadminconfig, subobj)
    message("Please install the phpLDAPadmin configuration located at %s into /etc/phpldapadmin/config.php" % paths.phpldapadminconfig)


def provision_dns(setup_dir, subobj, message, paths, session_info, credentials):
    """Write out a DNS zone file, from the info in the current database."""
    message("Setting up DNS zone: %s" % subobj.dnsdomain)
    # connect to the sam
    ldb = Ldb(paths.samdb, session_info=session_info, credentials=credentials)

    # These values may have changed, due to an incoming SamSync,
    # or may not have been specified, so fetch them from the database

    res = ldb.search(Dn(ldb, subobj.domaindn), SCOPE_BASE, "objectGUID=*", 
                     ["objectGUID"])
    assert(len(res) == 1)
    assert(res[0]["objectGUID"] is not None)
    subobj.domainguid = res[0]["objectGUID"]

    subobj.host_guid = searchone(ldb, subobj.domaindn, 
                                 "(&(objectClass=computer)(cn=%s))" % subobj.netbiosname, "objectGUID")
    assert subobj.host_guid is not None

    setup_file(setup_dir, "provision.zone", message, paths.dns, subobj)

    message("Please install the zone located in %s into your DNS server" % paths.dns)


def provision_ldapbase(setup_dir, subobj, message, paths):
    """Write out a DNS zone file, from the info in the current database."""
    message("Setting up LDAP base entry: %s" % subobj.domaindn)
    rdns = subobj.domaindn.split(",")
    subobj.extensibleobject = "objectClass: extensibleObject"

    subobj.rdn_dc = rdns[0][len("DC="):]

    setup_file(setup_dir, "provision_basedn.ldif", 
           message, paths.ldap_basedn_ldif, 
           subobj)

    setup_file(setup_dir, "provision_configuration_basedn.ldif", 
           message, paths.ldap_config_basedn_ldif, 
           subobj)

    setup_file(setup_dir, "provision_schema_basedn.ldif", 
           message, paths.ldap_schema_basedn_ldif, 
           subobj)

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
    
    subobj.domainsid    = sid.random()
    subobj.invocationid = uuid.random()
    subobj.policyguid   = uuid.random()
    subobj.krbtgtpass   = misc.random_password(12)
    subobj.machinepass  = misc.random_password(12)
    subobj.adminpass    = misc.random_password(12)
    subobj.dnspass      = misc.random_password(12)
    subobj.datestring   = time.strftime("%Y%m%d%H")
    subobj.root         = findnss(pwd.getpwnam, "root")[4]
    subobj.nobody       = findnss(pwd.getpwnam, "nobody")[4]
    subobj.nogroup      = findnss(grp.getgrnam, "nogroup", "nobody")[2]
    subobj.wheel        = findnss(grp.getgrnam, "wheel", "root", "staff", "adm")[2]
    subobj.backup       = findnss(grp.getgrnam, "backup", "wheel", "root", "staff")[2]
    subobj.users        = findnss(grp.getgrnam, "users", "guest", "other", "unknown", "usr")[2]

    subobj.dnsdomain    = subobj.realm.lower()
    subobj.dnsname      = "%s.%s" % (subobj.hostname.lower(), subobj.dnsdomain)
    subobj.domaindn     = "DC=" + subobj.dnsdomain.replace(".", ",DC=")
    subobj.domaindn_ldb = "users.ldb"
    subobj.rootdn       = subobj.domaindn
    subobj.configdn     = "CN=Configuration," + subobj.rootdn
    subobj.configdn_ldb = "configuration.ldb"
    subobj.schemadn     = "CN=Schema," + subobj.configdn
    subobj.schemadn_ldb = "schema.ldb"

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
    subobj.modules_list = ["rootdse",
                    "paged_results",
                    "ranged_results",
                    "server_sort",
                    "extended_dn",
                    "asq",
                    "samldb",
                    "rdn_name",
                    "objectclass",
                    "kludge_acl",
                    "operational"]
    subobj.tdb_modules_list = [
                    "subtree_rename",
                    "subtree_delete",
                    "linked_attributes"]
    subobj.modules_list2 = ["show_deleted",
                    "partition"]

    subobj.extensibleobject = "# no objectClass: extensibleObject for local ldb"
    subobj.aci        = "# no aci for local ldb"
    return subobj


def searchone(ldb, basedn, expression, attribute):
    """search for one attribute as a string."""
    res = ldb.search(basedn, SCOPE_SUBTREE, expression, [attribute])
    if len(res) != 1 or res[0][attribute] is None:
        return None
    return res[0][attribute]


def load_schema(setup_dir, subobj, samdb):
    """Load schema."""
    src = os.path.join(setup_dir, "schema.ldif")

    schema_data = open(src, 'r').read()

    src = os.path.join(setup_dir, "schema_samba4.ldif")

    schema_data += open(src, 'r').read()

    schema_data = substitute_var(schema_data, subobj.subst_vars())

    src = os.path.join(setup_dir, "provision_schema_basedn_modify.ldif")

    head_data = open(src, 'r').read()

    head_data = substitute_var(head_data, subobj.subst_vars())

    samdb.attach_dsdb_schema_from_ldif(head_data, schema_data)


def enable_account(ldb, user_dn):
    """enable the account."""
    res = ldb.search(user_dn, SCOPE_ONELEVEL, None, ["userAccountControl"])
    assert len(res) == 1
    userAccountControl = res[0].userAccountControl
    userAccountControl = userAccountControl - 2 # remove disabled bit
    mod = """
dn: %s
changetype: modify
replace: userAccountControl
userAccountControl: %u
""" % (user_dn, userAccountControl)
    ldb.modify(mod)


def newuser(sam, username, unixname, password, message, session_info, 
            credentials):
    """add a new user record"""
    # connect to the sam 
    ldb.transaction_start()

    # find the DNs for the domain and the domain users group
    res = ldb.search("", SCOPE_BASE, "defaultNamingContext=*", 
                     ["defaultNamingContext"])
    assert(len(res) == 1 and res[0].defaultNamingContext is not None)
    domain_dn = res[0].defaultNamingContext
    assert(domain_dn is not None)
    dom_users = searchone(ldb, domain_dn, "name=Domain Users", "dn")
    assert(dom_users is not None)

    user_dn = "CN=%s,CN=Users,%s" % (username, domain_dn)

    #
    #  the new user record. note the reliance on the samdb module to fill
    #  in a sid, guid etc
    #
    ldif = """
dn: %s
sAMAccountName: %s
unixName: %s
sambaPassword: %s
objectClass: user
""" % (user_dn, username, unixname, password)
    #  add the user to the users group as well
    modgroup = """
dn: %s
changetype: modify
add: member
member: %s
""" % (dom_users, user_dn)


    #  now the real work
    message("Adding user %s" % user_dn)
    ldb.add(ldif)

    message("Modifying group %s" % dom_users)
    ldb.modify(modgroup)

    #  modify the userAccountControl to remove the disabled bit
    enable_account(ldb, user_dn)
    ldb.transaction_commit()


def valid_netbios_name(name):
    """Check whether a name is valid as a NetBIOS name. """
    # FIXME: There are probably more constraints here. 
    # crh has a paragraph on this in his book (1.4.1.1)
    if len(name) > 13:
        return False
    return True


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
