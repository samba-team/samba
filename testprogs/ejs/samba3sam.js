#!/usr/bin/env smbscript
/*
  (C) Jelmer Vernooij <jelmer@samba.org> 2005
  (C) Martin Kuehl <mkhl@samba.org> 2006
  Published under the GNU GPL
  Sponsored by Google Summer of Code
 */

var sys;
var ldb = ldb_init();
var smb3 = ldb_init();
var smb4 = ldb_init();
var options = GetOptions(ARGV, "POPT_AUTOHELP", "POPT_COMMON_SAMBA");
if (options == undefined) {
        println("Failed to parse options");
        return -1;
}

libinclude("base.js");

if (options.ARGV.length != 2) {
        println("Usage: samba3sam.js <TESTDIR> <DATADIR>");
        return -1;
}

prefix = options.ARGV[0];
datadir = options.ARGV[1];

function setup_modules(sys, ldb, from, to) {
	var ldif = sys.file_load(datadir + "/" + "provision_samba3sam.ldif");
	ldif = substitute_var(ldif, from);
	assert(ldif != undefined);
	var ok = ldb.add(ldif);
	assert(ok);

	var ok = ldb.add("
dn: @MAP=samba3sam
@FROM: " + from.BASEDN + "
@TO: " + to.BASEDN + "

dn: @MODULES
@LIST: rootdse,paged_results,server_sort,extended_dn,asq,samldb,objectclass,password_hash,operational,objectguid,rdn_name,samba3sam,partition

dn: @PARTITION
partition: " + from.BASEDN + ":" + from.URL + "
partition: " + to.BASEDN + ":" + to.URL + "
replicateEntries: @SUBCLASSES
replicateEntries: @ATTRIBUTES
replicateEntries: @INDEXLIST
");
	assert(ok);
}

function setup_data(sys, ldb, remote) {
	var ldif = sys.file_load(datadir + "/" + "samba3.ldif");
	ldif = substitute_var(ldif, remote);
	assert(ldif != undefined);
	var ok = ldb.add(ldif);
	assert(ok);
}

function search_tests(ldb) {
	println("Looking up by non-mapped attribute");
	var msg = ldb.search("(cn=Administrator)");
	assert(msg.length == 1);
	assert(msg[0].cn == "Administrator");

	println("Looking up by mapped attribute");
	var msg = ldb.search("(name=Backup Operators)");
	assert(msg.length == 1);
	assert(msg[0].name == "Backup Operators");

	println("Looking up by old name of renamed attribute");
	var msg = ldb.search("(displayName=Backup Operators)");
	assert(msg.length == 0);

	println("Looking up mapped entry containing SID");
	var msg = ldb.search("(cn=Replicator)");
	assert(msg.length == 1);
	println(msg[0].dn);
	assert(msg[0].dn == "cn=Replicator,ou=Groups,sambaDomainName=TESTS,dc=vernstok,dc=nl");
	assert(msg[0].objectSid == "S-1-5-21-4231626423-2410014848-2360679739-552");

	println("Checking mapping of objectClass");
	var oc = msg[0].objectClass;
	assert(oc != undefined);
	for (var i in oc) {
		assert(oc[i] == "posixGroup" || oc[i] == "group");
	}

	println("Looking up by objectClass");
	var msg = ldb.search("(|(objectClass=user)(cn=Administrator))");
	assert(msg != undefined);
	assert(msg.length == 2);
	for (var i = 0; i < msg.length; i++) {
		assert((msg[i].dn == "unixName=Administrator,ou=Users,sambaDomainName=TESTS,dc=vernstok,dc=nl") ||
		       (msg[i].dn == "unixName=nobody,ou=Users,sambaDomainName=TESTS,dc=vernstok,dc=nl"));
	}
}

function modify_tests(ldb, remote) {
	println("Adding a record that will be fallbacked");
	ok = ldb.add("
dn: cn=Foo,dc=idealx,dc=org
foo: bar
blah: Blie
cn: Foo
showInAdvancedViewOnly: TRUE
");
	assert(ok);

	println("Checking for existence of record (local)");
	/* TODO: This record must be searched in the local database, which is currently only supported for base searches
	 * msg = ldb.search("(cn=Foo)", new Array('foo','blah','cn','showInAdvancedViewOnly'));
	 * TODO: Actually, this version should work as well but doesn't...
	 * msg = ldb.search("(cn=Foo)", "dc=idealx,dc=org", ldb.LDB_SCOPE_SUBTREE new Array('foo','blah','cn','showInAdvancedViewOnly'));
	 */
	msg = ldb.search("", "cn=Foo,dc=idealx,dc=org", ldb.LDB_SCOPE_BASE new Array('foo','blah','cn','showInAdvancedViewOnly'));
	assert(msg.length == 1);
	assert(msg[0].showInAdvancedViewOnly == "TRUE");
	assert(msg[0].foo == "bar");
	assert(msg[0].blah == "Blie");

	println("Adding record that will be mapped");
	ok = ldb.add("
dn: cn=Niemand,sambaDomainName=TESTS,dc=vernstok,dc=nl
objectClass: user
unixName: bin
unicodePwd: geheim
cn: Niemand
");
	assert(ok);

	println("Checking for existence of record (remote)");
	msg = ldb.search("(unixName=bin)", new Array('unixName','cn','dn', 'unicodePwd'));
	assert(msg.length == 1);
	assert(msg[0].cn == "Niemand"); 
	assert(msg[0].unicodePwd == "geheim");

	println("Checking for existence of record (local && remote)");
	msg = ldb.search("(&(unixName=bin)(unicodePwd=geheim))", new Array('unixName','cn','dn', 'unicodePwd'));
	assert(msg.length == 1);                // TODO: should check with more records
	assert(msg[0].cn == "Niemand");
	assert(msg[0].unixName == "bin");
	assert(msg[0].unicodePwd == "geheim");

	println("Checking for existence of record (local || remote)");
	msg = ldb.search("(|(unixName=bin)(unicodePwd=geheim))", new Array('unixName','cn','dn', 'unicodePwd'));
	assert(msg.length == 1);                // TODO: should check with more records
	assert(msg[0].cn == "Niemand");
	assert(msg[0].unixName == "bin" || msg[0].unicodePwd == "geheim");

	println("Checking for data in destination database");
	msg = remote.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].sambaSID == "S-1-5-21-4231626423-2410014848-2360679739-2001");
	assert(msg[0].displayName == "Niemand");

	println("Adding attribute...");
	ok = ldb.modify("
dn: cn=Niemand,sambaDomainName=TESTS,dc=vernstok,dc=nl
changetype: modify
add: description
description: Blah
");
	assert(ok);

	println("Checking whether changes are still there...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].cn == "Niemand");
	assert(msg[0].description == "Blah");

	println("Modifying attribute...");
	ok = ldb.modify("
dn: cn=Niemand,sambaDomainName=TESTS,dc=vernstok,dc=nl
changetype: modify
replace: description
description: Blie
");
	assert(ok);

	println("Checking whether changes are still there...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].description == "Blie");

	println("Deleting attribute...");
	ok = ldb.modify("
dn: cn=Niemand,sambaDomainName=TESTS,dc=vernstok,dc=nl
changetype: modify
delete: description
");
	assert(ok);

	println("Checking whether changes are no longer there...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].description == undefined);

	println("Renaming record...");
	ok = ldb.rename("cn=Niemand,sambaDomainName=TESTS,dc=vernstok,dc=nl", "cn=Niemand,dc=vernstok,dc=nl");

	println("Checking whether DN has changed...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length == 1);
	assert(msg[0].dn == "cn=Niemand,dc=vernstok,dc=nl");

	println("Deleting record...");
	ok = ldb.del("cn=Niemand,dc=vernstok,dc=nl");
	assert(ok);

	println("Checking whether record is gone...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length == 0);
}

sys = sys_init();
var ldbfile = prefix + "/" + "test.ldb";
var ldburl = "tdb://" + ldbfile;

var samba4 = new Object("samba4 partition info");
var samba4.FILE = prefix + "/" + "samba4.ldb";
var samba4.URL = "tdb://" + samba4.FILE;
var samba4.BASEDN = "dc=vernstok,dc=nl";

var samba3 = new Object("samba3 partition info");
var samba3.FILE = prefix + "/" + "samba3.ldb";
var samba3.URL = "tdb://" + samba3.FILE;
var samba3.BASEDN = "cn=Samba3Sam," + samba4.BASEDN;

sys.unlink(ldbfile);
sys.unlink(samba3.FILE);
sys.unlink(samba4.FILE);

var ok = ldb.connect(ldburl);
assert(ok);
var ok = smb3.connect(samba3.URL);
assert(ok);
var ok = smb4.connect(samba4.URL);
assert(ok);

setup_data(sys, smb3, samba3);

setup_modules(sys, ldb, samba4, samba3);

ldb = ldb_init();
var ok = ldb.connect(ldburl);
assert(ok);

search_tests(ldb, smb3);

modify_tests(ldb, smb3);

sys.unlink(ldbfile);
sys.unlink(samba3.FILE);
sys.unlink(samba4.FILE);

return 0;
