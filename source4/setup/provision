#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
	provision a Samba4 server
	Copyright Andrew Tridgell 2005
	Released under the GNU GPL v2 or later
*/

options = GetOptions(ARGV,
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"POPT_COMMON_VERSION",
		"POPT_COMMON_CREDENTIALS",
		'realm=s',
		'domain=s',
		'domain-guid=s',
		'domain-sid=s',
		'policy-guid=s',
		'host-name=s',
		'host-ip=s',
		'host-guid=s',
		'invocationid=s',
		'adminpass=s',
		'krbtgtpass=s',
		'machinepass=s',
		'dnspass=s',
		'root=s',
		'nobody=s',
		'nogroup=s',
		'wheel=s',
		'users=s',
		'quiet',
		'blank',
		'server-role=s',
		'partitions-only',
		'ldap-base',
		'ldap-backend=s',
                'ldap-backend-type=s',
                'aci=s');

if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

libinclude("base.js");
libinclude("provision.js");

/*
  print a message if quiet is not set
*/
function message()
{
	if (options["quiet"] == undefined) {
		print(vsprintf(arguments));
	}
}

/*
 show some help
*/
function ShowHelp()
{
	print("
Samba4 provisioning

provision [options]
 --realm	REALM		set realm
 --domain	DOMAIN		set domain
 --domain-guid	GUID		set domainguid (otherwise random)
 --domain-sid	SID		set domainsid (otherwise random)
 --host-name	HOSTNAME	set hostname
 --host-ip	IPADDRESS	set ipaddress
 --host-guid	GUID		set hostguid (otherwise random)
 --policy-guid  GUID            set group policy guid (otherwise random)
 --invocationid	GUID		set invocationid (otherwise random)
 --adminpass	PASSWORD	choose admin password (otherwise random)
 --krbtgtpass	PASSWORD	choose krbtgt password (otherwise random)
 --machinepass	PASSWORD	choose machine password (otherwise random)
 --root         USERNAME	choose 'root' unix username
 --nobody	USERNAME	choose 'nobody' user
 --nogroup	GROUPNAME	choose 'nogroup' group
 --wheel	GROUPNAME	choose 'wheel' privileged group
 --users	GROUPNAME	choose 'users' group
 --quiet			Be quiet
 --blank			do not add users or groups, just the structure
 --server-role  ROLE            Set server role to provision for (default standalone)
 --partitions-only              Configure Samba's partitions, but do not modify them (ie, join a BDC)
 --ldap-base			output only an LDIF file, suitable for creating an LDAP baseDN
 --ldap-backend LDAPSERVER      LDAP server to use for this provision
 --ldap-backend-type  TYPE      OpenLDAP or Fedora DS
 --aci          ACI             An arbitary LDIF fragment, particularly useful to loading a backend ACI value into a target LDAP server
You must provide at least a realm and domain

");
	exit(1);
}

if (options['host-name'] == undefined) {
	options['host-name'] = hostname();
}

/*
   main program
*/
if (options["realm"] == undefined ||
    options["domain"] == undefined ||
    options["host-name"] == undefined) {
	ShowHelp();
}

/* cope with an initially blank smb.conf */
var lp = loadparm_init();
lp.set("realm", options.realm);
lp.set("workgroup", options.domain);
lp.set("server role", options["server-role"]);
lp.reload();

var subobj = provision_guess();
for (r in options) {
	var key = strupper(join("", split("-", r)));
	subobj[key] = options[r];
}

var blank = (options["blank"] != undefined);
var ldapbackend = (options["ldap-backend"] != undefined);
var ldapbackendtype = options["ldap-backend-type"];
var partitions_only = (options["partitions-only"] != undefined);
var paths = provision_default_paths(subobj);
if (options["aci"] != undefined) {
	message("set ACI: %s\n", subobj["ACI"]);
}

message("set DOMAIN SID: %s\n", subobj["DOMAINSID"]);

provision_fix_subobj(subobj, paths);

if (ldapbackend) {
	if (options["ldap-backend"] == "ldapi") {
		subobj.LDAPBACKEND = subobj.LDAPI_URI;
	}
	if (ldapbackendtype == undefined) {
	       
	} else if (ldapbackendtype == "openldap") {
		subobj.LDAPMODULE = "normalise,entryuuid";
		subobj.TDB_MODULES_LIST = "";
	} else if (ldapbackendtype == "fedora-ds") {
		subobj.LDAPMODULE = "nsuniqueid";
	}
	subobj.BACKEND_MOD = subobj.LDAPMODULE + ",paged_searches";
	subobj.DOMAINDN_LDB = subobj.LDAPBACKEND;
	subobj.CONFIGDN_LDB = subobj.LDAPBACKEND;
	subobj.SCHEMADN_LDB = subobj.LDAPBACKEND;
	message("LDAP module: %s on backend: %s\n", subobj.LDAPMODULE, subobj.LDAPBACKEND);
}

if (!provision_validate(subobj, message)) {
	return -1;
}

var system_session = system_session();
var creds = options.get_credentials();
message("Provisioning for %s in realm %s\n", subobj.DOMAIN, subobj.REALM);
message("Using administrator password: %s\n", subobj.ADMINPASS);
if (partitions_only) {
	provision_become_dc(subobj, message, false, paths, system_session);
} else {
	provision(subobj, message, blank, paths, system_session, creds, ldapbackend);
	provision_dns(subobj, message, paths, system_session, creds);
	message("To reproduce this provision, run with:\n");
/* 	There has to be a better way than this... */
	message("--realm='%s' --domain='%s' \\\n", subobj.REALM_CONF, subobj.DOMAIN_CONF);
	if (subobj.DOMAINGUID != undefined) {
		 message("--domain-guid='%s' \\\n", subobj.DOMAINGUID);
	}
	if (subobj.HOSTGUID != undefined) {
		 message("--host-guid='%s' \\\n", subobj.HOSTGUID);
	}
	message("--policy-guid='%s' --host-name='%s' --host-ip='%s' \\\n", subobj.POLICYGUID, subobj.HOSTNAME, subobj.HOSTIP);
	if (subobj.INVOCATIONID != undefined) {
		message("--invocationid='%s' \\\n", subobj.INVOCATIONID);
	}
	message("--adminpass='%s' --krbtgtpass='%s' \\\n", subobj.ADMINPASS, subobj.KRBTGTPASS);
	message("--machinepass='%s' --dnspass='%s' \\\n", subobj.MACHINEPASS, subobj.DNSPASS);
	message("--root='%s' --nobody='%s' --nogroup='%s' \\\n", subobj.ROOT, subobj.NOBODY, subobj.NOGROUP);
	message("--wheel='%s' --users='%s' --server-role='%s' \\\n", subobj.WHEEL, subobj.USERS, subobj.SERVERROLE);
	if (ldapbackend) {
		message("--ldap-backend='%s' \\\n", subobj.LDAPBACKEND);
	}
	if (ldapbackendtype != undefined) {
		message("--ldap-backend-type='%s' \\\n", + ldapbackendtype);
	}
	message("--aci='" + subobj.ACI + "' \\\n")
}


message("All OK\n");
return 0;
