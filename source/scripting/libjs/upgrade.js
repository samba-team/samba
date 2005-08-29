/*
	backend code for upgrading from Samba3
	Copyright Jelmer Vernooij 2005
	Released under the GNU GPL v2 or later
*/

libinclude("base.js");

function regkey_to_dn(name)
{
	var dn = "hive=NONE";
	var i = 0;

	var as = split("/", name);

	for (i in as) {
		if (i > 0) {
			dn = sprintf("key=%s,", as[i]) + dn;
		}
	}

	return dn;
}

/* Where prefix is any of:
 * - HKLM
 *   HKU
 *   HKCR
 *   HKPD
 *   HKPT
 */

function upgrade_registry(regdb,prefix)
{
	var prefix_up = strupper(prefix);

	var ldif = "";

	for (var i in regdb.keys) {
		var rk = regdb.keys[i];
		/* Only handle selected hive */
		if (strncmp(prefix_up, rk.name, strlen(prefix_up)) != 0) {
			continue;
		}

		var keydn = regkey_to_dn(rk.name);

		var pts = split("/", rk.name);

		/* Convert key name to dn */
		ldif = ldif + sprintf("
dn: %s
name: %s

", keydn, pts[0]);
		
		for (var j in rk.values) {
			var rv = rk.values[j];

			ldif = ldif + sprintf("
dn: %s,value=%s
value: %s
type: %d
data:: %s", keydn, rv.value, rv.type, base64(rv.data));
		}
	}

	return ldif;
}

function upgrade_sam_policy(samba3,dn)
{
	var ldif = sprintf("
dn: %s
minPwdLength: %d
pwdHistoryLength: %d
minPwdAge: %d
maxPwdAge: %d
lockoutDuration: %d
samba3ResetCountMinutes: %d
samba3UserMustLogonToChangePassword: %d
samba3BadLockoutMinutes: %d
samba3DisconnectTime: %d
samba3RefuseMachinePwdChange: %d

", dn, samba3.policy.min_password_length, 
	samba3.policy.password_history, samba3.policy.minimum_password_age,
	samba3.policy.maximum_password_age, samba3.policy.lockout_duration,
	samba3.policy.reset_count_minutes, samba3.policy.user_must_logon_to_change_password,
	samba3.policy.bad_lockout_minutes, samba3.policy.disconnect_time, 
	samba3.policy.refuse_machine_password_change
);

	return ldif;
}

function upgrade_sam_account(acc,domaindn)
{
	var ldif = sprintf(
"dn: cn=%s,%s
objectClass: top
objectClass: person
objectClass: user
lastLogon: %d
lastLogoff: %d
unixName: %s
name: %s
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
samba3Rid: %d

", acc.fullname, domaindn, sam.logon_time, acc.logoff_time, acc.username, acc.nt_username, 
acc.fullname, acc.acct_desc, acc.group_rid, acc.bad_password_count, acc.logon_count,
acc.domain, acc.dir_drive, acc.munged_dial, acc.homedir, acc.logon_script, 
acc.profile_path, acc.workstations, acc.kickoff_time, acc.bad_password_time, 
acc.pass_last_set_time, acc.pass_can_change_time, acc.pass_must_change_time, acc.user_rid); 

		/* FIXME: Passwords */

	return ldif;
}

function upgrade_sam_group(grp,domaindn)
{
	var ldif = sprintf(
"dn: cn=%s,%s
objectClass: top
objectClass: group
description: %s
cn: %s
objectSid: %s
unixName: FIXME
samba3SidNameUse: %d", grp.nt_name, domaindn, 
grp.comment, grp.nt_name, grp.sid, grp.sid_name_use);

	return ldif;
}

function upgrade_winbind(samba3,domaindn)
{
	var ldif = sprintf("
		
dn: dc=none
userHwm: %d
groupHwm: %d

", samba3.idmap.user_hwm, samba3.idmap.group_hwm);

	for (var i in samba3.idmap.mappings) {
		var m = samba3.idmap.mappings[i];
		ldif = ldif + sprintf("
dn: SID=%s,%s
SID: %s
type: %d
unixID: %d", m.sid, domaindn, m.sid, m.type, m.unix_id);
	}
	
	return ldif;
}
*/

function upgrade_wins(samba3)
{
	var ldif = "";
	for (i in samba3.winsentries) {
		var e = samba3.winsentries[i];
		
		ldif = ldif + sprintf("
dn: type=%d,name=%s
name: %s
objectClass: wins
nbFlags: %x
expires: %s", e.type, e.name, e.name, e.type, e.nb_flags, sys.ldap_time(e.ttl));

		for (var i in e.ips) {
			ldif = ldif + sprintf("address: %s\n", e.ips[i]);
		}
	}

	return ldif;
}

function upgrade_provision(samba3)
{
	var subobj = new Object();
	var nss = nss_init();
	var lp = loadparm_init();
	var rdn_list;

	var domainname = samba3.get_param("global", "workgroup");
	var domsec = samba3.find_domainsecrets(domainname);
	var hostsec = samba3.find_domainsecrets(hostname());
	var realm = samba3.get_param("global", "realm");
	random_init(local);

	subobj.REALM        = realm;
	subobj.DOMAIN       = domainname;
	subobj.HOSTNAME     = hostname();

	assert(subobj.REALM);
	assert(subobj.DOMAIN);
	assert(subobj.HOSTNAME);

	subobj.HOSTIP       = hostip();
	subobj.DOMAINGUID   = domsec.guid;
	subobj.DOMAINSID    = domsec.sid;
	subobj.HOSTGUID     = hostsec.guid;
	subobj.INVOCATIONID = randguid();
	subobj.KRBTGTPASS   = randpass(12);
	subobj.MACHINEPASS  = randpass(12);
	subobj.ADMINPASS    = randpass(12);
	subobj.DEFAULTSITE  = "Default-First-Site-Name";
	subobj.NEWGUID      = randguid;
	subobj.NTTIME       = nttime;
	subobj.LDAPTIME     = ldaptime;
	subobj.DATESTRING   = datestring;
	subobj.USN          = nextusn;
	subobj.ROOT         = findnss(nss.getpwnam, split(samba3.get_param("global", "admin users")));
	subobj.NOBODY       = findnss(nss.getpwnam, "nobody");
	subobj.NOGROUP      = findnss(nss.getgrnam, "nogroup", "nobody");
	subobj.WHEEL        = findnss(nss.getgrnam, "wheel", "root");
	subobj.USERS        = findnss(nss.getgrnam, "users", "guest", "other");
	subobj.DNSDOMAIN    = strlower(subobj.REALM);
	subobj.DNSNAME      = sprintf("%s.%s", 
				      strlower(subobj.HOSTNAME), 
				      subobj.DNSDOMAIN);
	subobj.BASEDN       = "DC=" + join(",DC=", split(".", subobj.REALM));
	rdn_list = split(".", subobj.REALM);
	subobj.RDN_DC       = rdn_list[0];
	return subobj;
}

var keep = new Array(
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
	"sam database",
	"spoolss database",
	"wins database",
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
	"nbt port",
	"dgram port",
	"cldap port",
	"krb5 port",
	"web port",
	"tls enabled",
	"tls keyfile",
	"tls certfile",
	"tls cafile",
	"tls crlfile",
	"swat directory",
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
	"rpc big endian",
	"max connections",
	"paranoid server security",
	"socket options",
	"strict sync",
	"case insensitive filesystem",
	"max print jobs",
	"printable",
	"print ok",
	"printer name",
	"printer",
	"map system",
	"map hidden",
	"map archive",
	"domain logons",
	"preferred master",
	"prefered master",
	"local master",
	"domain master",
	"browseable",
	"browsable",
	"wins server",
	"wins support",
	"csc policy",
	"strict locking",
	"config file",
	"preload",
	"auto services",
	"lock dir",
	"lock directory",
	"pid directory",
	"js include",
	"setup directory",
	"socket address",
	"-valid",
	"copy",
	"include",
	"available",
	"volume",
	"fstype",
	"panic action",
	"msdfs root",
	"host msdfs",
	"winbind separator");

function upgrade_smbconf(samba3)
{
	//FIXME
}
