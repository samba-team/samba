#!/usr/bin/python
#
#	backend code for upgrading from Samba3
#	Copyright Jelmer Vernooij 2005-2007
#	Released under the GNU GPL v3 or later
#

"""Support code for upgrading from Samba 3 to Samba 4."""

from provision import findnss, provision
import grp
import pwd
import uuid
import registry

# Where prefix is any of:
# - HKLM
#   HKU
#   HKCR
#   HKPD
#   HKPT
#

def upgrade_sam_policy(policy,dn):
    ldif = """
dn: %s
changetype: modify
replace: minPwdLength
minPwdLength: %d
pwdHistoryLength: %d
minPwdAge: %d
maxPwdAge: %d
lockoutDuration: %d
samba3ResetCountMinutes: %d
samba3UserMustLogonToChangePassword: %d
samba3BadLockoutMinutes: %d
samba3DisconnectTime: %d

""" % (dn, policy.min_password_length, 
    policy.password_history, policy.minimum_password_age,
    policy.maximum_password_age, policy.lockout_duration,
    policy.reset_count_minutes, policy.user_must_logon_to_change_password,
    policy.bad_lockout_minutes, policy.disconnect_time)
    
    return ldif

def upgrade_sam_account(ldb,acc,domaindn,domainsid):
    """Upgrade a SAM account."""
    if acc.nt_username is None or acc.nt_username == "":
        acc.nt_username = acc.username

    if acc.fullname is None:
        acc.fullname = pwd.getpwnam(acc.fullname)[4]

    acc.fullname = acc.fullname.split(",")[0]

    if acc.fullname is None:
        acc.fullname = acc.username
    
    assert acc.fullname is not None
    assert acc.nt_username is not None

    ldif = """dn: cn=%s,%s
objectClass: top
objectClass: user
lastLogon: %d
lastLogoff: %d
unixName: %s
sAMAccountName: %s
cn: %s
description: %s
primaryGroupID: %d
badPwdcount: %d
logonCount: %d
samba3Domain: %s
samba3DirDrive: %s
samba3MungedDial: %s
samba3Homedir: %s
samba3LogonScript: %s
samba3ProfilePath: %s
samba3Workstations: %s
samba3KickOffTime: %d
samba3BadPwdTime: %d
samba3PassLastSetTime: %d
samba3PassCanChangeTime: %d
samba3PassMustChangeTime: %d
objectSid: %s-%d
lmPwdHash:: %s
ntPwdHash:: %s

""" % (ldb.dn_escape(acc.fullname), domaindn, acc.logon_time, acc.logoff_time, acc.username, acc.nt_username, acc.nt_username, 
acc.acct_desc, acc.group_rid, acc.bad_password_count, acc.logon_count,
acc.domain, acc.dir_drive, acc.munged_dial, acc.homedir, acc.logon_script, 
acc.profile_path, acc.workstations, acc.kickoff_time, acc.bad_password_time, 
acc.pass_last_set_time, acc.pass_can_change_time, acc.pass_must_change_time, domainsid, acc.user_rid,
    ldb.encode(acc.lm_pw), ldb.encode(acc.nt_pw))

    return ldif

def upgrade_sam_group(group,domaindn):
    """Upgrade a SAM group."""
    if group.sid_name_use == 5: # Well-known group
        return None

    if group.nt_name in ("Domain Guests", "Domain Users", "Domain Admins"):
        return None
    
    if group.gid == -1:
        gr = grp.getgrnam(grp.nt_name)
    else:
        gr = grp.getgrgid(grp.gid)

    if gr is None:
        group.unixname = "UNKNOWN"
    else:
        group.unixname = gr.gr_name

    assert group.unixname is not None
    
    ldif = """dn: cn=%s,%s
objectClass: top
objectClass: group
description: %s
cn: %s
objectSid: %s
unixName: %s
samba3SidNameUse: %d
""" % (group.nt_name, domaindn, 
group.comment, group.nt_name, group.sid, group.unixname, group.sid_name_use)

    return ldif

def import_idmap(samba4_idmap,samba3_idmap,domaindn):
    samba4_idmap.add({
        "dn": domaindn,
        "userHwm": str(samba3_idmap.get_user_hwm()),
        "groupHwm": str(samba3_idmap.get_group_hwm())})

    for uid in samba3_idmap.uids():
        samba4_idmap.add({"dn": "SID=%s,%s" % (samba3_idmap.get_user_sid(uid), domaindn),
                          "SID": samba3_idmap.get_user_sid(uid),
                          "type": "user",
                          "unixID": str(uid)})

    for gid in samba3_idmap.uids():
        samba4_idmap.add({"dn": "SID=%s,%s" % (samba3_idmap.get_group_sid(gid), domaindn),
                          "SID": samba3_idmap.get_group_sid(gid),
                          "type": "group",
                          "unixID": str(gid)})


def import_wins(samba4_winsdb, samba3_winsdb):
    """Import settings from a Samba3 WINS database."""
    version_id = 0
    import time

    for (name, (ttl, ips, nb_flags)) in samba3_winsdb.items():
        version_id+=1

        numIPs = len(e.ips)

        type = int(name.split("#", 1)[1], 16)

        if type == 0x1C:
            rType = 0x2
        elif type & 0x80:
            if len(ips) > 1:
                rType = 0x2
            else:
                rType = 0x1
        else:
            if len(ips) > 1:
                rType = 0x3
            else:
                rType = 0x0

        if ttl > time.time():
            rState = 0x0 # active
        else:
            rState = 0x1 # released

        nType = ((nb_flags & 0x60)>>5)

        samba4_winsdb.add({"dn": "name=%s,type=0x%s" % name.split("#"),
                           "type": name.split("#")[1],
                           "name": name.split("#")[0],
                           "objectClass": "winsRecord",
                           "recordType": str(rType),
                           "recordState": str(rState),
                           "nodeType": str(nType),
                           "expireTime": ldb.ldaptime(ttl),
                           "isStatic": "0",
                           "versionID": str(version_id),
                           "address": ips})

    samba4_winsdb.add({"dn": "CN=VERSION",
                       "objectClass": "winsMaxVersion",
                       "maxVersion": str(version_id)})

def upgrade_provision(samba3, setup_dir, message, credentials, session_info, lp, paths):
    oldconf = samba3.get_conf()

    if oldconf.get("domain logons") == "True":
        serverrole = "domain controller"
    else:
        if oldconf.get("security") == "user":
            serverrole = "standalone"
        else:
            serverrole = "member server"

    lp.set("server role", serverrole)
    domainname = oldconf.get("workgroup")
    if domainname:
        domainname = str(domainname)
    lp.set("workgroup", domainname)
    realm = oldconf.get("realm")
    netbiosname = oldconf.get("netbios name")

    secrets_db = samba3.get_secrets_db()
    
    if domainname is None:
        domainname = secrets_db.domains()[0]
        message("No domain specified in smb.conf file, assuming '%s'" % domainname)
    
    if realm is None:
        realm = domainname.lower()
        message("No realm specified in smb.conf file, assuming '%s'\n" % realm)
    lp.set("realm", realm)

    domainguid = secrets_db.get_domain_guid(domainname)
    domainsid = secrets_db.get_sid(domainname)
    if domainsid is None:
        message("Can't find domain secrets for '%s'; using random SID\n" % domainname)
    
    if netbiosname is not None:
        machinepass = secrets_db.get_machine_password(netbiosname)
    else:
        machinepass = None
    
    provision(lp=lp, setup_dir=setup_dir, message=message, blank=True, ldapbackend=None, paths=paths, session_info=session_info, 
              credentials=credentials, realm=realm, domain=domainname, 
              domainsid=domainsid, domainguid=domainguid, machinepass=machinepass, serverrole=serverrole)

smbconf_keep = [
    "dos charset", 
    "unix charset",
    "display charset",
    "comment",
    "path",
    "directory",
    "workgroup",
    "realm",
    "netbios name",
    "netbios aliases",
    "netbios scope",
    "server string",
    "interfaces",
    "bind interfaces only",
    "security",
    "auth methods",
    "encrypt passwords",
    "null passwords",
    "obey pam restrictions",
    "password server",
    "smb passwd file",
    "private dir",
    "passwd chat",
    "password level",
    "lanman auth",
    "ntlm auth",
    "client NTLMv2 auth",
    "client lanman auth",
    "client plaintext auth",
    "read only",
    "hosts allow",
    "hosts deny",
    "log level",
    "debuglevel",
    "log file",
    "smb ports",
    "large readwrite",
    "max protocol",
    "min protocol",
    "unicode",
    "read raw",
    "write raw",
    "disable netbios",
    "nt status support",
    "announce version",
    "announce as",
    "max mux",
    "max xmit",
    "name resolve order",
    "max wins ttl",
    "min wins ttl",
    "time server",
    "unix extensions",
    "use spnego",
    "server signing",
    "client signing",
    "max connections",
    "paranoid server security",
    "socket options",
    "strict sync",
    "max print jobs",
    "printable",
    "print ok",
    "printer name",
    "printer",
    "map system",
    "map hidden",
    "map archive",
    "preferred master",
    "prefered master",
    "local master",
    "browseable",
    "browsable",
    "wins server",
    "wins support",
    "csc policy",
    "strict locking",
    "preload",
    "auto services",
    "lock dir",
    "lock directory",
    "pid directory",
    "socket address",
    "copy",
    "include",
    "available",
    "volume",
    "fstype",
    "panic action",
    "msdfs root",
    "host msdfs",
    "winbind separator"]

def upgrade_smbconf(oldconf,mark):
    """Remove configuration variables not present in Samba4

    :param oldconf: Old configuration structure
    :param mark: Whether removed configuration variables should be 
        kept in the new configuration as "samba3:<name>"
    """
    data = oldconf.data()
    newconf = param_init()

    for s in data:
        for p in data[s]:
            keep = False
            for k in smbconf_keep:
                if smbconf_keep[k] == p:
                    keep = True
                    break

            if keep:
                newconf.set(s, p, oldconf.get(s, p))
            elif mark:
                newconf.set(s, "samba3:"+p, oldconf.get(s,p))

    return newconf

SAMBA3_PREDEF_NAMES = {
        'HKLM': registry.HKEY_LOCAL_MACHINE,
}

def import_registry(samba4_registry, samba3_regdb):
    """Import a Samba 3 registry database into the Samba 4 registry.

    :param samba4_registry: Samba 4 registry handle.
    :param samba3_regdb: Samba 3 registry database handle.
    """
    def ensure_key_exists(keypath):
        (predef_name, keypath) = keypath.split("/", 1)
        predef_id = SAMBA3_PREDEF_NAMES[predef_name]
        keypath = keypath.replace("/", "\\")
        return samba4_registry.create_key(predef_id, keypath)

    for key in samba3_regdb.keys():
        key_handle = ensure_key_exists(key)
        for subkey in samba3_regdb.subkeys(key):
            ensure_key_exists(subkey)
        for (value_name, (value_type, value_data)) in samba3_regdb.values(key).items():
            key_handle.set_value(value_name, value_type, value_data)


def upgrade(subobj, samba3, message, paths, session_info, credentials):
    ret = 0
    samdb = Ldb(paths.samdb, session_info=session_info, credentials=credentials)

    message("Writing configuration")
    newconf = upgrade_smbconf(samba3.configuration,True)
    newconf.save(paths.smbconf)

    message("Importing account policies")
    samdb.modify_ldif(upgrade_sam_policy(samba3,subobj.BASEDN))
    regdb = Ldb(paths.hklm)

    regdb.modify("""
dn: value=RefusePasswordChange,key=Parameters,key=Netlogon,key=Services,key=CurrentControlSet,key=System,HIVE=NONE
replace: type
type: 4
replace: data
data: %d
""" % policy.refuse_machine_password_change)

    message("Importing users")
    for account in samba3.samaccounts:
        msg = "... " + account.username
        ldif = upgrade_sam_account(samdb, accounts,subobj.BASEDN,subobj.DOMAINSID)
        try:
            samdb.add(ldif)
        except LdbError, e:
            # FIXME: Ignore 'Record exists' errors
            msg += "... error: " + str(e)
            ret += 1; 
        message(msg)

    message("Importing groups")
    for mapping in samba3.groupmappings:
        msg = "... " + mapping.nt_name
        ldif = upgrade_sam_group(mapping, subobj.BASEDN)
        if ldif is not None:
            try:
                samdb.add(ldif)
            except LdbError, e:
                # FIXME: Ignore 'Record exists' errors
                msg += "... error: " + str(e)
                ret += 1
        message(msg)

    message("Importing WINS data")
    winsdb = Ldb(paths.winsdb)
    ldb_erase(winsdb)

    ldif = upgrade_wins(samba3)
    winsdb.add(ldif)

    # figure out ldapurl, if applicable
    ldapurl = None
    pdb = samba3.configuration.get_list("passdb backend")
    if pdb is not None:
        for backend in pdb:
            if len(backend) >= 7 and backend[0:7] == "ldapsam":
                ldapurl = backend[7:]

    # URL was not specified in passdb backend but ldap /is/ used
    if ldapurl == "":
        ldapurl = "ldap://%s" % samba3.configuration.get("ldap server")

    # Enable samba3sam module if original passdb backend was ldap
    if ldapurl is not None:
        message("Enabling Samba3 LDAP mappings for SAM database")

        enable_samba3sam(samdb)

    return ret


def enable_samba3sam(samdb):
    samdb.modify("""
dn: @MODULES
changetype: modify
replace: @LIST
@LIST: samldb,operational,objectguid,rdn_name,samba3sam
""")

    samdb.add({"dn": "@MAP=samba3sam", "@MAP_URL": ldapurl})
