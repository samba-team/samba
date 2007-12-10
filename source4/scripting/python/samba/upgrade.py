#!/usr/bin/python
#
#	backend code for upgrading from Samba3
#	Copyright Jelmer Vernooij 2005-2007
#	Released under the GNU GPL v3 or later
#

"""Support code for upgrading from Samba 3 to Samba 4."""

from provision import findnss
import provision
import grp
import pwd
from uuid import uuid4
from param import default_configuration

def regkey_to_dn(name):
    """Convert a registry key to a DN."""
	dn = "hive=NONE"

    for el in name.split("/")[1:]:
        dn = "key=%s," % el + dn

	return dn

# Where prefix is any of:
# - HKLM
#   HKU
#   HKCR
#   HKPD
#   HKPT
#

def upgrade_registry(regdb,prefix,ldb):
    """Migrate registry contents."""
    assert regdb is not None:
	prefix_up = prefix.upper()
	ldif = []

    for rk in regdb.keys:
		pts = rk.name.split("/")

		# Only handle selected hive
        if pts[0].upper() != prefix_up:
			continue

		keydn = regkey_to_dn(rk.name)

		pts = rk.name.split("/")

		# Convert key name to dn
		ldif[rk.name] = """
dn: %s
name: %s

""" % (keydn, pts[0])
		
        for rv in rk.values:
			ldif[rk.name + " (" + rv.name + ")"] = """
dn: %s,value=%s
value: %s
type: %d
data:: %s""" % (keydn, rv.name, rv.name, rv.type, ldb.encode(rv.data))

	return ldif

def upgrade_sam_policy(samba3,dn):
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

""" % (dn, samba3.policy.min_password_length, 
	samba3.policy.password_history, samba3.policy.minimum_password_age,
	samba3.policy.maximum_password_age, samba3.policy.lockout_duration,
	samba3.policy.reset_count_minutes, samba3.policy.user_must_logon_to_change_password,
	samba3.policy.bad_lockout_minutes, samba3.policy.disconnect_time)
	
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

def upgrade_winbind(samba3,domaindn):
	ldif = """
		
dn: dc=none
userHwm: %d
groupHwm: %d

""" % (samba3.idmap.user_hwm, samba3.idmap.group_hwm)

    for m in samba3.idmap.mappings:
		ldif += """
dn: SID=%s,%s
SID: %s
type: %d
unixID: %d""" % (m.sid, domaindn, m.sid, m.type, m.unix_id)
	
	return ldif

def upgrade_wins(samba3):
    """Upgrade the WINS database."""
	ldif = ""
	version_id = 0

    for e in samba3.winsentries:
		now = sys.nttime()
		ttl = sys.unix2nttime(e.ttl)

		version_id+=1

        numIPs = len(e.ips)

        if e.type == 0x1C:
			rType = 0x2
        elif e.type & 0x80:
            if numIPs > 1:
				rType = 0x2
            else:
				rType = 0x1
        else:
            if numIPs > 1:
				rType = 0x3
            else:
				rType = 0x0

        if ttl > now:
			rState = 0x0 # active
        else:
			rState = 0x1 # released

		nType = ((e.nb_flags & 0x60)>>5)

		ldif += """
dn: name=%s,type=0x%02X
type: 0x%02X
name: %s
objectClass: winsRecord
recordType: %u
recordState: %u
nodeType: %u
isStatic: 0
expireTime: %s
versionID: %llu
""" % (e.name, e.type, e.type, e.name, 
   rType, rState, nType, 
   ldaptime(ttl), version_id)

        for ip in e.ips:
			ldif += "address: %s\n" % ip

	ldif += """
dn: CN=VERSION
objectClass: winsMaxVersion
maxVersion: %llu
""" % version_id

	return ldif

def upgrade_provision(lp, samba3):
	subobj = Object()

	domainname = samba3.configuration.get("workgroup")
	
    if domainname is None:
		domainname = samba3.secrets.domains[0].name
		print "No domain specified in smb.conf file, assuming '%s'\n" % domainname
	
	domsec = samba3.find_domainsecrets(domainname)
	hostsec = samba3.find_domainsecrets(hostname())
	realm = samba3.configuration.get("realm")

    if realm is None:
		realm = domainname
		print "No realm specified in smb.conf file, assuming '%s'\n" % realm
	random_init(local)

	subobj.realm        = realm
	subobj.domain       = domainname
	subobj.hostname     = hostname()

	assert subobj.realm is not None
	assert subobj.domain is not None
	assert subobj.hostname is not None

	subobj.HOSTIP       = hostip()
    if domsec is not None:
		subobj.DOMAINGUID   = domsec.guid
		subobj.DOMAINSID    = domsec.sid
    else:
		print "Can't find domain secrets for '%s'; using random SID and GUID\n" % domainname
		subobj.DOMAINGUID = uuid4()
		subobj.DOMAINSID = randsid()
	
    if hostsec:
		subobj.HOSTGUID     = hostsec.guid
    else:
		subobj.HOSTGUID = uuid4()
	subobj.invocationid = uuid4()
	subobj.krbtgtpass   = randpass(12)
	subobj.machinepass  = randpass(12)
	subobj.adminpass    = randpass(12)
	subobj.datestring   = datestring()
	subobj.root         = findnss(pwd.getpwnam, "root")[4]
	subobj.nobody       = findnss(pwd.getpwnam, "nobody")[4]
	subobj.nogroup      = findnss(grp.getgrnam, "nogroup", "nobody")[2]
	subobj.wheel        = findnss(grp.getgrnam, "wheel", "root")[2]
	subobj.users        = findnss(grp.getgrnam, "users", "guest", "other")[2]
	subobj.dnsdomain    = subobj.realm.lower()
	subobj.dnsname      = "%s.%s" % (subobj.hostname.lower(), subobj.dnsdomain)
	subobj.basedn       = "DC=" + ",DC=".join(subobj.realm.split("."))
	rdn_list = subobj.dnsdomain.split(".")
	subobj.domaindn     = "DC=" + ",DC=".join(rdn_list)
	subobj.domaindn_ldb = "users.ldb"
	subobj.rootdn       = subobj.domaindn

	modules_list        = ["rootdse",
					"kludge_acl",
					"paged_results",
					"server_sort",
					"extended_dn",
					"asq",
					"samldb",
					"password_hash",
					"operational",
					"objectclass",
					"rdn_name",
					"show_deleted",
					"partition"]
	subobj.modules_list = ",".join(modules_list)

	return subobj

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

#
#   Remove configuration variables not present in Samba4
#	oldconf: Old configuration structure
#	mark: Whether removed configuration variables should be 
#		kept in the new configuration as "samba3:<name>"
def upgrade_smbconf(oldconf,mark):
	data = oldconf.data()
	newconf = param_init()

	for (s in data) {
		for (p in data[s]) {
			keep = False
			for (k in smbconf_keep) { 
                if smbconf_keep[k] == p:
					keep = True
					break
			}

            if keep:
				newconf.set(s, p, oldconf.get(s, p))
            elif mark:
				newconf.set(s, "samba3:"+p, oldconf.get(s,p))
		}
	}

    if oldconf.get("domain logons") == "True":
		newconf.set("server role", "domain controller")
    else:
        if oldconf.get("security") == "user":
			newconf.set("server role", "standalone")
        else:
			newconf.set("server role", "member server")

	return newconf

def upgrade(subobj, samba3, message, paths, session_info, credentials):
	ret = 0
	lp = loadparm_init()
	samdb = Ldb(paths.samdb, session_info=session_info, credentials=credentials)

	message("Writing configuration")
	newconf = upgrade_smbconf(samba3.configuration,True)
	newconf.save(paths.smbconf)

	message("Importing account policies")
	ldif = upgrade_sam_policy(samba3,subobj.BASEDN)
	samdb.modify(ldif)
	regdb = Ldb(paths.hklm)

	regdb.modify("
dn: value=RefusePasswordChange,key=Parameters,key=Netlogon,key=Services,key=CurrentControlSet,key=System,HIVE=NONE
replace: type
type: 4
replace: data
data: %d
" % samba3.policy.refuse_machine_password_change)

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

	message("Importing registry data")
    for hive in ["hkcr","hkcu","hklm","hkpd","hku","hkpt"]:
		message("... " + hive)
		regdb = Ldb(paths[hive])
		ldif = upgrade_registry(samba3.registry, hive, regdb)
		for (var j in ldif) {
			var msg = "... ... " + j
            try:
                regdb.add(ldif[j])
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

		samdb.modify("""
dn: @MODULES
changetype: modify
replace: @LIST
@LIST: samldb,operational,objectguid,rdn_name,samba3sam
""")

		samdb.add("""
dn: @MAP=samba3sam
@MAP_URL: %s""", ldapurl))

	return ret

def upgrade_verify(subobj, samba3, paths, message):
	message("Verifying account policies")

	samldb = Ldb(paths.samdb)

    for account in samba3.samaccounts:
		msg = samldb.search("(&(sAMAccountName=" + account.nt_username + ")(objectclass=user))")
		assert(len(msg) >= 1)
	
	# FIXME
