/*
	backend code for provisioning a Samba4 server
	Copyright Andrew Tridgell 2005
	Released under the GNU GPL v2 or later
*/

/* used to generate sequence numbers for records */
provision_next_usn = 1;

sys = sys_init();

/*
  find a user or group from a list of possibilities
*/
function findnss()
{
	var i;
	assert(arguments.length >= 2);
	var nssfn = arguments[0];
	for (i=1;i<arguments.length;i++) {
		if (nssfn(arguments[i]) != undefined) {
			return arguments[i];
		}
	}
	printf("Unable to find user/group for %s\n", arguments[1]);
	assert(i<arguments.length);
}

/*
   add a foreign security principle
 */
function add_foreign(str, sid, desc, unixname)
{
	var add = "
dn: CN=${SID},CN=ForeignSecurityPrincipals,${BASEDN}
objectClass: top
objectClass: foreignSecurityPrincipal
cn: ${SID}
description: ${DESC}
instanceType: 4
whenCreated: ${LDAPTIME}
whenChanged: ${LDAPTIME}
uSNCreated: 1
uSNChanged: 1
showInAdvancedViewOnly: TRUE
name: ${SID}
objectGUID: ${NEWGUID}
objectSid: ${SID}
objectCategory: CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,${BASEDN}
unixName: ${UNIXNAME}
";
	var sub = new Object();
	sub.SID = sid;
	sub.DESC = desc;
	sub.UNIXNAME = unixname;
	return str + substitute_var(add, sub);
}

/*
  return current time as a nt time string
*/
function nttime()
{
	return "" + sys.nttime();
}

/*
  return current time as a ldap time string
*/
function ldaptime()
{
	return sys.ldaptime(sys.nttime());
}

/*
  return a date string suitable for a dns zone serial number
*/
function datestring()
{
	var t = sys.gmtime(sys.nttime());
	return sprintf("%04u%02u%02u%02u",
		       t.tm_year+1900, t.tm_mon+1, t.tm_mday, t.tm_hour);
}

/*
  return first host IP
*/
function hostip()
{
	var list = sys.interfaces();
	return list[0];
}

/*
  return current time as a ldap time string
*/
function nextusn()
{
	provision_next_usn = provision_next_usn+1;
	return provision_next_usn;
}

/*
  return first part of hostname
*/
function hostname()
{
	var s = split(".", sys.hostname());
	return s[0];
}


/*
  setup a ldb in the private dir
 */
function setup_ldb(ldif, dbname, subobj)
{
	var extra = "";
	var ldb = ldb_init();

	if (arguments.length == 4) {
		extra = arguments[3];
	}

	var db = lpGet("private dir") + "/" + dbname;
	var src = lpGet("setup directory") + "/" + ldif;

	sys.unlink(db);

	var data = sys.file_load(src);
	data = data + extra;
	data = substitute_var(data, subobj);

	ok = ldb.add(db, data);
	assert(ok);
}

/*
  setup a file in the private dir
 */
function setup_file(template, fname, subobj)
{
	var f = lpGet("private dir") + "/" + fname;
	var src = lpGet("setup directory") + "/" + template;

	sys.unlink(f);

	var data = sys.file_load(src);
	data = substitute_var(data, subobj);

	ok = sys.file_save(f, data);
	assert(ok);
}

/*
  provision samba4 - caution, this wipes all existing data!
*/
function provision(subobj, message)
{
	var data = "";

	/*
	  some options need to be upper/lower case
	*/
	subobj.REALM       = strlower(subobj.REALM);
	subobj.HOSTNAME    = strlower(subobj.HOSTNAME);
	subobj.DOMAIN      = strupper(subobj.DOMAIN);
	subobj.NETBIOSNAME = strupper(subobj.HOSTNAME);

	data = add_foreign(data, "S-1-5-7",  "Anonymous",           "${NOBODY}");
	data = add_foreign(data, "S-1-1-0",  "World",               "${NOGROUP}");
	data = add_foreign(data, "S-1-5-2",  "Network",             "${NOGROUP}");
	data = add_foreign(data, "S-1-5-18", "System",              "${ROOT}");
	data = add_foreign(data, "S-1-5-11", "Authenticated Users", "${USERS}");

	provision_next_usn = 1;

	message("Setting up hklm.ldb\n");
	setup_ldb("hklm.ldif", "hklm.ldb", subobj);
	message("Setting up sam.ldb\n");
	setup_ldb("provision.ldif", "sam.ldb", subobj, data);
	message("Setting up rootdse.ldb\n");
	setup_ldb("rootdse.ldif", "rootdse.ldb", subobj);
	message("Setting up secrets.ldb\n");
	setup_ldb("secrets.ldif", "secrets.ldb", subobj);
	message("Setting up DNS zone file\n");
	setup_file("provision.zone", subobj.DNSDOMAIN + ".zone", subobj);
}

/*
  guess reasonably default options for provisioning
*/
function provision_guess()
{
	var subobj = new Object();
	subobj.REALM        = lpGet("realm");
	subobj.DOMAIN       = lpGet("workgroup");
	subobj.HOSTNAME     = hostname();
	subobj.HOSTIP       = hostip();
	subobj.DOMAINGUID   = randguid();
	subobj.DOMAINSID    = randsid();
	subobj.HOSTGUID     = randguid();
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
	subobj.ROOT         = findnss(getpwnam, "root");
	subobj.NOBODY       = findnss(getpwnam, "nobody");
	subobj.NOGROUP      = findnss(getgrnam, "nogroup", "nobody");
	subobj.WHEEL        = findnss(getgrnam, "wheel", "root");
	subobj.USERS        = findnss(getgrnam, "users", "guest", "other");
	subobj.DNSDOMAIN    = strlower(subobj.REALM);
	subobj.DNSNAME      = sprintf("%s.%s", 
				      strlower(subobj.HOSTNAME), 
				      subobj.DNSDOMAIN);
	subobj.BASEDN       = "DC=" + join(",DC=", split(".", subobj.REALM));
	return subobj;
}

return 0;
