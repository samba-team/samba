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

function upgrade_registry(regdb,prefix,ldb)
{
	assert(regdb != undefined);
	var prefix_up = strupper(prefix);
	var ldif = new Array();

	for (var i in regdb.keys) {
		var rk = regdb.keys[i];
		var pts = split("/", rk.name);

		/* Only handle selected hive */
		if (strupper(pts[0]) != prefix_up) {
			continue;
		}

		var keydn = regkey_to_dn(rk.name);

		var pts = split("/", rk.name);

		/* Convert key name to dn */
		ldif[rk.name] = sprintf("
dn: %s
name: %s

", keydn, pts[0]);
		
		for (var j in rk.values) {
			var rv = rk.values[j];

			ldif[rk.name + " (" + rv.name + ")"] = sprintf("
dn: %s,value=%s
value: %s
type: %d
data:: %s", keydn, rv.name, rv.name, rv.type, ldb.encode(rv.data));
		}
	}

	return ldif;
}

function upgrade_sam_policy(samba3,dn)
{
	var ldif = sprintf("
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

", dn, samba3.policy.min_password_length, 
	samba3.policy.password_history, samba3.policy.minimum_password_age,
	samba3.policy.maximum_password_age, samba3.policy.lockout_duration,
	samba3.policy.reset_count_minutes, samba3.policy.user_must_logon_to_change_password,
	samba3.policy.bad_lockout_minutes, samba3.policy.disconnect_time
);
	
	return ldif;
}

function upgrade_sam_account(ldb,acc,domaindn,domainsid)
{
	if (acc.nt_username == undefined) {
		acc.nt_username = acc.username;
	}	

	if (acc.nt_username == "") {
		acc.nt_username = acc.username;
	}	

	if (acc.fullname == undefined) {
		var pw = nss.getpwnam(acc.fullname);
		acc.fullname = pw.pw_gecos;
	}

	var pts = split(',', acc.fullname);
	acc.fullname = pts[0];

	if (acc.fullname == undefined) {
		acc.fullname = acc.username;
	}
	
	assert(acc.fullname != undefined);
	assert(acc.nt_username != undefined);

	var ldif = sprintf(
"dn: cn=%s,%s
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

", ldb.dn_escape(acc.fullname), domaindn, acc.logon_time, acc.logoff_time, acc.username, acc.nt_username, acc.nt_username, 

acc.acct_desc, acc.group_rid, acc.bad_password_count, acc.logon_count,
acc.domain, acc.dir_drive, acc.munged_dial, acc.homedir, acc.logon_script, 
acc.profile_path, acc.workstations, acc.kickoff_time, acc.bad_password_time, 
acc.pass_last_set_time, acc.pass_can_change_time, acc.pass_must_change_time, domainsid, acc.user_rid,
	ldb.encode(acc.lm_pw), ldb.encode(acc.nt_pw)); 

	return ldif;
}

function upgrade_sam_group(grp,domaindn)
{
	var nss = nss_init();

	var gr;
	if (grp.sid_name_use == 5) { // Well-known group
		return undefined;
	}

	if (grp.nt_name == "Domain Guests" ||
	    grp.nt_name == "Domain Users" ||
	    grp.nt_name == "Domain Admins") {
		return undefined;
	}
	
	if (grp.gid == -1) {
		gr = nss.getgrnam(grp.nt_name);
	} else {
		gr = nss.getgrgid(grp.gid);
	}

	if (gr == undefined) {
		grp.unixname = "UNKNOWN";
	} else {
		grp.unixname = gr.gr_name;
	}

	assert(grp.unixname != undefined);
	
	var ldif = sprintf(
"dn: cn=%s,%s
objectClass: top
objectClass: group
description: %s
cn: %s
objectSid: %s
unixName: %s
samba3SidNameUse: %d
", grp.nt_name, domaindn, 
grp.comment, grp.nt_name, grp.sid, grp.unixname, grp.sid_name_use);

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
	var version_id = 0;

	for (i in samba3.winsentries) {
		var rType;
		var rState;
		var nType;
		var numIPs = 0;
		var e = samba3.winsentries[i];
		var now = sys.nttime();
		var ttl = sys.unix2nttime(e.ttl);

		version_id++;

		for (var i in e.ips) {
			numIPs++;
		}

		if (e.type == 0x1C) {
			rType = 0x2;
		} else if (sys.bitAND(e.type, 0x80)) {
			if (numIPs > 1) {
				rType = 0x2;
			} else {
				rType = 0x1;
			}
		} else {
			if (numIPs > 1) {
				rType = 0x3;
			} else {
				rType = 0x0;
			}
		}

		if (ttl > now) {
			rState = 0x0;/* active */
		} else {
			rState = 0x1;/* released */		
		}

		nType = (sys.bitAND(e.nb_flags,0x60)>>5);

		ldif = ldif + sprintf("
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
", e.name, e.type, e.type, e.name, 
   rType, rState, nType, 
   sys.ldaptime(ttl), version_id);

		for (var i in e.ips) {
			ldif = ldif + sprintf("address: %s\n", e.ips[i]);
		}
	}

	ldif = ldif + sprintf("
dn: CN=VERSION
objectClass: winsMaxVersion
maxVersion: %llu
", version_id);

	return ldif;
}

function upgrade_provision(samba3)
{
	var subobj = new Object();
	var nss = nss_init();
	var lp = loadparm_init();
	var rdn_list;

	var domainname = samba3.configuration.get("workgroup");
	
	if (domainname == undefined) {
		domainname = samba3.secrets.domains[0].name;
		println("No domain specified in smb.conf file, assuming '" + domainname + "'");
	}
	
	var domsec = samba3.find_domainsecrets(domainname);
	var hostsec = samba3.find_domainsecrets(hostname());
	var realm = samba3.configuration.get("realm");

	if (realm == undefined) {
		realm = domainname;
		println("No realm specified in smb.conf file, assuming '" + realm + "'");
	}
	random_init(local);

	subobj.REALM        = realm;
	subobj.DOMAIN       = domainname;
	subobj.HOSTNAME     = hostname();

	assert(subobj.REALM);
	assert(subobj.DOMAIN);
	assert(subobj.HOSTNAME);

	subobj.HOSTIP       = hostip();
	if (domsec != undefined) {
		subobj.DOMAINGUID   = domsec.guid;
		subobj.DOMAINSID    = domsec.sid;
	} else {
		println("Can't find domain secrets for '" + domainname + "'; using random SID and GUID");
		subobj.DOMAINGUID = randguid();
		subobj.DOMAINSID = randsid();
	}
	
	if (hostsec) {
		subobj.HOSTGUID     = hostsec.guid;
	} else {
		subobj.HOSTGUID = randguid();
	}
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
	subobj.ROOT         = findnss(nss.getpwnam, "root");
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
	return subobj;
}

smbconf_keep = new Array(
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
	"config file",
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
	"winbind separator");

/*
   Remove configuration variables not present in Samba4
	oldconf: Old configuration structure
	mark: Whether removed configuration variables should be 
		kept in the new configuration as "samba3:<name>"
 */
function upgrade_smbconf(oldconf,mark)
{
	var data = oldconf.data();
	var newconf = param_init();

	for (var s in data) {
		for (var p in data[s]) {
			var keep = false;
			for (var k in smbconf_keep) { 
				if (smbconf_keep[k] == p) {
					keep = true;
					break;
				}
			}

			if (keep) {
				newconf.set(s, p, oldconf.get(s, p));
			} else if (mark) {
				newconf.set(s, "samba3:"+p, oldconf.get(s,p));
			}
		}
	}

	if (oldconf.get("domain logons") == "True") {
		newconf.set("server role", "domain controller");
	} else {
		if (oldconf.get("security") == "user") {
			newconf.set("server role", "standalone");
		} else {
			newconf.set("server role", "member server");
		}
	}

	return newconf;
}

function upgrade(subobj, samba3, message, paths, session_info, credentials)
{
	var ret = 0;
	var lp = loadparm_init();
	var samdb = ldb_init();
	samdb.session_info = session_info;
	samdb.credentials = credentials;
	var ok = samdb.connect(paths.samdb);
	if (!ok) {
		info.message("samdb connect failed: " + samdb.errstring() + "\n");
		assert(ok);
	}

	message("Writing configuration\n");
	var newconf = upgrade_smbconf(samba3.configuration,true);
	newconf.save(paths.smbconf);

	message("Importing account policies\n");
	var ldif = upgrade_sam_policy(samba3,subobj.BASEDN);
	ok = samdb.modify(ldif);
	if (!ok) {
		message("samdb load failed: " + samdb.errstring() + "\n");
		assert(ok);
	}
	var regdb = ldb_init();
	ok = regdb.connect(paths.hklm);
	if (!ok) {
		message("registry connect: " + regdb.errstring() + "\n");
		assert(ok);
	}

	ok = regdb.modify(sprintf("
dn: value=RefusePasswordChange,key=Parameters,key=Netlogon,key=Services,key=CurrentControlSet,key=System,HIVE=NONE
replace: type
type: 4
replace: data
data: %d
", samba3.policy.refuse_machine_password_change));
	if (!ok) {
		message("registry load failed: " + regdb.errstring() + "\n");
		assert(ok);
	}

	message("Importing users\n");
	for (var i in samba3.samaccounts) {
		var msg = "... " + samba3.samaccounts[i].username;
		var ldif = upgrade_sam_account(samdb,samba3.samaccounts[i],subobj.BASEDN,subobj.DOMAINSID);
		ok = samdb.add(ldif);
		if (!ok && samdb.errstring() != "Record exists") { 
			msg = msg + "... error: " + samdb.errstring();
			ret = ret + 1; 
		}
		message(msg + "\n");
	}

	message("Importing groups\n");
	for (var i in samba3.groupmappings) {
		var msg = "... " + samba3.groupmappings[i].nt_name;
		var ldif = upgrade_sam_group(samba3.groupmappings[i],subobj.BASEDN);
		if (ldif != undefined) {
			ok = samdb.add(ldif);
			if (!ok && samdb.errstring() != "Record exists") { 
				msg = msg + "... error: " + samdb.errstring();
				ret = ret + 1; 
			}
		}
		message(msg + "\n");
	}

	message("Importing registry data\n");
	var hives = new Array("hkcr","hkcu","hklm","hkpd","hku","hkpt"); 
	for (var i in hives) {
		var hn = hives[i];
		message("... " + hn + "\n");
		regdb = ldb_init();
		ok = regdb.connect(paths[hn]);
		assert(ok);
		var ldif = upgrade_registry(samba3.registry, hn, regdb);
		for (var j in ldif) {
			var msg = "... ... " + j;
			ok = regdb.add(ldif[j]);
			if (!ok && regdb.errstring() != "Record exists") { 
				msg = msg + "... error: " + regdb.errstring();
				ret = ret + 1; 
			}
			message(msg + "\n");
		}
	}


	message("Importing WINS data\n");
	var winsdb = ldb_init();
	ok = winsdb.connect(paths.winsdb);
	assert(ok);
	ldb_erase(winsdb);

	var ldif = upgrade_wins(samba3);
	ok = winsdb.add(ldif);
	assert(ok);

	// figure out ldapurl, if applicable
	var ldapurl = undefined;
	var pdb = samba3.configuration.get_list("passdb backend");
	if (pdb != undefined) {
		for (var b in pdb) {
			if (strlen(pdb[b]) >= 7) {
				if (substr(pdb[b], 0, 7) == "ldapsam") {
					ldapurl = substr(pdb[b], 8);
				}
			}
		}
	}

	// URL was not specified in passdb backend but ldap /is/ used
	if (ldapurl == "") {
		ldapurl = "ldap://" + samba3.configuration.get("ldap server");
	}

	// Enable samba3sam module if original passdb backend was ldap
	if (ldapurl != undefined) {
		message("Enabling Samba3 LDAP mappings for SAM database\n");

		ok = samdb.modify("
dn: @MODULES
changetype: modify
replace: @LIST
@LIST: samldb,operational,objectguid,rdn_name,samba3sam
");
		if (!ok) {
			message("Error enabling samba3sam module: " + samdb.errstring() + "\n");
			ret = ret + 1;
		}

		ok = samdb.add(sprintf("
dn: @MAP=samba3sam
@MAP_URL: %s", ldapurl));
		assert(ok);

	}

	return ret;
}

function upgrade_verify(subobj, samba3,paths,message)
{
	message("Verifying account policies\n");
	var samldb = ldb_init();
	var ne = 0;

	var ok = samldb.connect(paths.samdb);
	assert(ok);

	for (var i in samba3.samaccounts) {
		var msg = samldb.search("(&(sAMAccountName=" + samba3.samaccounts[i].nt_username + ")(objectclass=user))");
		assert(msg.length >= 1);
	}
	
	// FIXME
}
