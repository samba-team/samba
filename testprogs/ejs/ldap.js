#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
	test certin LDAP behaviours
*/

var ldb = ldb_init();

var options = GetOptions(ARGV, 
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"POPT_COMMON_CREDENTIALS");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

libinclude("base.js");

if (options.ARGV.length != 1) {
   println("Usage: ldap.js <HOST>");
   return -1;
}

var host = options.ARGV[0];

function basic_tests(ldb, base_dn)
{
	println("Running basic tests");

	ldb.del("cn=ldaptestuser,cn=users," + base_dn);

	var ok = ldb.add("
dn: cn=ldaptestuser,cn=users," + base_dn + "
objectClass: user
objectClass: person
cn: LDAPtestUSER
");
	assert(ok);

	println("Testing ldb.search");
	var res = ldb.search("(&(cn=ldaptestuser)(objectClass=user))");

	assert(res[0].dn == "cn=ldaptestuser,cn=users," + base_dn);
	assert(res[0].cn == "ldaptestuser");
	assert(res[0].name == "ldaptestuser");
	assert(res[0].objectGUID != undefined);
	assert(res[0].whenCreated != undefined);

	ok = ldb.del(res[0].dn);
	assert(ok);
}

function find_basedn(ldb)
{
    var attrs = new Array("defaultNamingContext");
    var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
    assert(res.length == 1);
    return res[0].defaultNamingContext;
}

/* use command line creds if available */
ldb.credentials = options.get_credentials();

var ok = ldb.connect("ldap://" + host);
var base_dn = find_basedn(ldb);

printf("baseDN: %s\n", base_dn);

basic_tests(ldb, base_dn)

return 0;
