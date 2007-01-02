#!/usr/bin/env smbscript
/*
  (C) Jelmer Vernooij <jelmer@samba.org> 2005
  (C) Martin Kuehl <mkhl@samba.org> 2006
  Published under the GNU GPL
  Sponsored by Google Summer of Code
 */

var sys;
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

var prefix = options.ARGV[0];
var datadir = options.ARGV[1];

function setup_data(obj, ldif)
{
	assert(ldif != undefined);
	ldif = substitute_var(ldif, obj);
	assert(ldif != undefined);
	var ok = obj.db.add(ldif);
	assert(ok);
}

function setup_modules(ldb, s3, s4, ldif)
{
	assert(ldif != undefined);
	ldif = substitute_var(ldif, s4);
	assert(ldif != undefined);
	var ok = ldb.add(ldif);
	assert(ok);

	var ldif = "
dn: @MAP=samba3sam
@FROM: " + s4.BASEDN + "
@TO: sambaDomainName=TESTS," + s3.BASEDN + "

dn: @MODULES
@LIST: rootdse,paged_results,server_sort,extended_dn,asq,samldb,objectclass,password_hash,operational,objectguid,rdn_name,samba3sam,partition

dn: @PARTITION
partition: " + s4.BASEDN + ":" + s4.url + "
partition: " + s3.BASEDN + ":" + s3.url + "
replicateEntries: @SUBCLASSES
replicateEntries: @ATTRIBUTES
replicateEntries: @INDEXLIST
";
	var ok = ldb.add(ldif);
	assert(ok);
}

function test_s3sam_search(ldb)
{
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
	assert(msg[0].dn == "cn=Replicator,ou=Groups,dc=vernstok,dc=nl");
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
		assert((msg[i].dn == "unixName=Administrator,ou=Users,dc=vernstok,dc=nl") ||
		       (msg[i].dn == "unixName=nobody,ou=Users,dc=vernstok,dc=nl"));
	}
}

function test_s3sam_modify(ldb, s3)
{
	var msg, ok;
	println("Adding a record that will be fallbacked");
	ok = ldb.add("
dn: cn=Foo
foo: bar
blah: Blie
cn: Foo
showInAdvancedViewOnly: TRUE
");
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	println("Checking for existence of record (local)");
	/* TODO: This record must be searched in the local database, which is currently only supported for base searches
	 * msg = ldb.search("(cn=Foo)", new Array('foo','blah','cn','showInAdvancedViewOnly'));
	 * TODO: Actually, this version should work as well but doesn't...
	 * 
	 */
	var attrs =  new Array('foo','blah','cn','showInAdvancedViewOnly');
	msg = ldb.search("(cn=Foo)", "cn=Foo", ldb.LDB_SCOPE_BASE, attrs);
	assert(msg.length == 1);
	assert(msg[0].showInAdvancedViewOnly == "TRUE");
	assert(msg[0].foo == "bar");
	assert(msg[0].blah == "Blie");

	println("Adding record that will be mapped");
	ok = ldb.add("
dn: cn=Niemand,cn=Users,dc=vernstok,dc=nl
objectClass: user
unixName: bin
unicodePwd: geheim
cn: Niemand
");
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}
	assert(ok);

	println("Checking for existence of record (remote)");
	msg = ldb.search("(unixName=bin)", new Array('unixName','cn','dn', 'unicodePwd'));
	assert(msg.length == 1);
	assert(msg[0].cn == "Niemand"); 
	assert(msg[0].unicodePwd == "geheim");

	println("Checking for existence of record (local && remote)");
	msg = ldb.search("(&(unixName=bin)(unicodePwd=geheim))", new Array('unixName','cn','dn', 'unicodePwd'));
	assert(msg.length == 1);		// TODO: should check with more records
	assert(msg[0].cn == "Niemand");
	assert(msg[0].unixName == "bin");
	assert(msg[0].unicodePwd == "geheim");

	println("Checking for existence of record (local || remote)");
	msg = ldb.search("(|(unixName=bin)(unicodePwd=geheim))", new Array('unixName','cn','dn', 'unicodePwd'));
	println("got " + msg.length + " replies");
	assert(msg.length == 1);		// TODO: should check with more records
	assert(msg[0].cn == "Niemand");
	assert(msg[0].unixName == "bin" || msg[0].unicodePwd == "geheim");

	println("Checking for data in destination database");
	msg = s3.db.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].sambaSID == "S-1-5-21-4231626423-2410014848-2360679739-2001");
	assert(msg[0].displayName == "Niemand");

	println("Adding attribute...");
	ok = ldb.modify("
dn: cn=Niemand,cn=Users,dc=vernstok,dc=nl
changetype: modify
add: description
description: Blah
");
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}
	assert(ok);

	println("Checking whether changes are still there...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].cn == "Niemand");
	assert(msg[0].description == "Blah");

	println("Modifying attribute...");
	ok = ldb.modify("
dn: cn=Niemand,cn=Users,dc=vernstok,dc=nl
changetype: modify
replace: description
description: Blie
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	assert(ok);

	println("Checking whether changes are still there...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].description == "Blie");

	println("Deleting attribute...");
	ok = ldb.modify("
dn: cn=Niemand,cn=Users,dc=vernstok,dc=nl
changetype: modify
delete: description
");
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}
	assert(ok);

	println("Checking whether changes are no longer there...");
	msg = ldb.search("(cn=Niemand)");
	assert(msg.length >= 1);
	assert(msg[0].description == undefined);

	println("Renaming record...");
	ok = ldb.rename("cn=Niemand,cn=Users,dc=vernstok,dc=nl", "cn=Niemand2,cn=Users,dc=vernstok,dc=nl");
	assert(ok);

	println("Checking whether DN has changed...");
	msg = ldb.search("(cn=Niemand2)");
	assert(msg.length == 1);
	assert(msg[0].dn == "cn=Niemand2,cn=Users,dc=vernstok,dc=nl");

	println("Deleting record...");
	ok = ldb.del("cn=Niemand2,cn=Users,dc=vernstok,dc=nl");
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	println("Checking whether record is gone...");
	msg = ldb.search("(cn=Niemand2)");
	assert(msg.length == 0);
}

function test_map_search(ldb, s3, s4)
{
	println("Running search tests on mapped data");
	var res;
	var dn;
	var attrs;

	/* Add a set of split records */
	var ldif = "
dn: " + s4.dn("cn=X") + "
objectClass: user
cn: X
codePage: x
revision: x
objectCategory: x
nextRid: y
lastLogon: x
description: x
objectSid: S-1-5-21-4231626423-2410014848-2360679739-552
primaryGroupID: 1-5-21-4231626423-2410014848-2360679739-512

dn: " + s4.dn("cn=Y") + "
objectClass: top
cn: Y
codePage: x
revision: x
objectCategory: y
nextRid: y
lastLogon: y
description: x

dn: " + s4.dn("cn=Z") + "
objectClass: top
cn: Z
codePage: x
revision: y
objectCategory: z
nextRid: y
lastLogon: z
description: y
";
	ldif = substitute_var(ldif, s4);
	assert(ldif != undefined);
	var ok = ldb.add(ldif);
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	/* Add a set of remote records */
	var ldif = "
dn: " + s3.dn("cn=A") + "
objectClass: posixAccount
cn: A
sambaNextRid: x
sambaBadPasswordCount: x
sambaLogonTime: x
description: x
sambaSID: S-1-5-21-4231626423-2410014848-2360679739-552
sambaPrimaryGroupSID: S-1-5-21-4231626423-2410014848-2360679739-512

dn: " + s3.dn("cn=B") + "
objectClass: top
cn:B
sambaNextRid: x
sambaBadPasswordCount: x
sambaLogonTime: y
description: x

dn: " + s3.dn("cn=C") + "
objectClass: top
cn: C
sambaNextRid: x
sambaBadPasswordCount: y
sambaLogonTime: z
description: y
";
	ldif = substitute_var(ldif, s3);
	assert(ldif != undefined);
	var ok = s3.db.add(ldif);
	assert(ok);

	println("Testing search by DN");

	/* Search remote record by local DN */
	dn = s4.dn("cn=A");
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "x");

	/* Search remote record by remote DN */
	dn = s3.dn("cn=A");
	attrs = new Array("objectCategory", "lastLogon", "sambaLogonTime");
	res = s3.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == undefined);
	assert(res[0].sambaLogonTime == "x");

	/* Search split record by local DN */
	dn = s4.dn("cn=X");
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].objectCategory == "x");
	assert(res[0].lastLogon == "x");

	/* Search split record by remote DN */
	dn = s3.dn("cn=X");
	attrs = new Array("objectCategory", "lastLogon", "sambaLogonTime");
	res = s3.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == undefined);
	assert(res[0].sambaLogonTime == "x");

	println("Testing search by attribute");

	/* Search by ignored attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(revision=x)", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");

	/* Search by kept attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(description=y)", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=Z"));
	assert(res[0].objectCategory == "z");
	assert(res[0].lastLogon == "z");
	assert(res[1].dn == s4.dn("cn=C"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "z");

	/* Search by renamed attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(badPwdCount=x)", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");

	/* Search by converted attribute */
	attrs = new Array("objectCategory", "lastLogon", "objectSid");
	/* TODO:
	   Using the SID directly in the parse tree leads to conversion
	   errors, letting the search fail with no results.
	res = ldb.search("(objectSid=S-1-5-21-4231626423-2410014848-2360679739-552)", NULL, ldb. SCOPE_DEFAULT, attrs);
	*/
	res = ldb.search("(objectSid=*)", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=X"));
	assert(res[0].objectCategory == "x");
	assert(res[0].lastLogon == "x");
	assert(res[0].objectSid == "S-1-5-21-4231626423-2410014848-2360679739-552");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	assert(res[1].objectSid == "S-1-5-21-4231626423-2410014848-2360679739-552");

	/* Search by generated attribute */
	/* In most cases, this even works when the mapping is missing
	 * a `convert_operator' by enumerating the remote db. */
	attrs = new Array("objectCategory", "lastLogon", "primaryGroupID");
	res = ldb.search("(primaryGroupID=512)", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == s4.dn("cn=A"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "x");
	assert(res[0].primaryGroupID == "512");

	/* TODO: There should actually be two results, A and X.  The
	 * primaryGroupID of X seems to get corrupted somewhere, and the
	 * objectSid isn't available during the generation of remote (!) data,
	 * which can be observed with the following search.  Also note that Xs
	 * objectSid seems to be fine in the previous search for objectSid... */
	/*
	res = ldb.search("(primaryGroupID=*)", NULL, ldb. SCOPE_DEFAULT, attrs);
	println(res.length + " results found");
	for (i=0;i<res.length;i++) {
		for (obj in res[i]) {
			println(obj + ": " + res[i][obj]);
		}
		println("---");
	}
	*/

	/* Search by remote name of renamed attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(sambaBadPasswordCount=*)", "", ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 0);

	/* Search by objectClass */
	attrs = new Array("objectCategory", "lastLogon", "objectClass");
	res = ldb.search("(objectClass=user)", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=X"));
	assert(res[0].objectCategory == "x");
	assert(res[0].lastLogon == "x");
	assert(res[0].objectClass != undefined);
	assert(res[0].objectClass[3] == "user");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	assert(res[1].objectClass != undefined);
	assert(res[1].objectClass[0] == "user");

	/* Prove that the objectClass is actually used for the search */
	res = ldb.search("(|(objectClass=user)(badPwdCount=x))", NULL, ldb. SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 3);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[0].objectClass != undefined);
	for (i=0;i<res[0].objectClass.length;i++) {
		assert(res[0].objectClass[i] != "user");
	}
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");
	assert(res[1].objectClass != undefined);
	assert(res[1].objectClass[3] == "user");
	assert(res[2].dn == s4.dn("cn=A"));
	assert(res[2].objectCategory == undefined);
	assert(res[2].lastLogon == "x");
	assert(res[2].objectClass != undefined);
	assert(res[2].objectClass[0] == "user");

	println("Testing search by parse tree");

	/* Search by conjunction of local attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(&(codePage=x)(revision=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");

	/* Search by conjunction of remote attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(&(lastLogon=x)(description=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=X"));
	assert(res[0].objectCategory == "x");
	assert(res[0].lastLogon == "x");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	
	/* Search by conjunction of local and remote attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(&(codePage=x)(description=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");

	/* Search by conjunction of local and remote attribute w/o match */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(&(codePage=x)(nextRid=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 0);
	res = ldb.search("(&(revision=x)(lastLogon=z))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 0);

	/* Search by disjunction of local attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(|(revision=x)(objectCategory=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");

	/* Search by disjunction of remote attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(|(badPwdCount=x)(lastLogon=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 3);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");
	assert(res[2].dn == s4.dn("cn=A"));
	assert(res[2].objectCategory == undefined);
	assert(res[2].lastLogon == "x");

	/* Search by disjunction of local and remote attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(|(revision=x)(lastLogon=y))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 3);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=B"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "y");
	assert(res[2].dn == s4.dn("cn=X"));
	assert(res[2].objectCategory == "x");
	assert(res[2].lastLogon == "x");

	/* Search by disjunction of local and remote attribute w/o match */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(|(codePage=y)(nextRid=z))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 0);

	/* Search by negated local attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(revision=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 4);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	assert(res[2].dn == s4.dn("cn=Z"));
	assert(res[2].objectCategory == "z");
	assert(res[2].lastLogon == "z");
	assert(res[3].dn == s4.dn("cn=C"));
	assert(res[3].objectCategory == undefined);
	assert(res[3].lastLogon == "z");

	/* Search by negated remote attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(description=x))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 2);
	assert(res[0].dn == s4.dn("cn=Z"));
	assert(res[0].objectCategory == "z");
	assert(res[0].lastLogon == "z");
	assert(res[1].dn == s4.dn("cn=C"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "z");

	/* Search by negated conjunction of local attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(&(codePage=x)(revision=x)))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 4);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	assert(res[2].dn == s4.dn("cn=Z"));
	assert(res[2].objectCategory == "z");
	assert(res[2].lastLogon == "z");
	assert(res[3].dn == s4.dn("cn=C"));
	assert(res[3].objectCategory == undefined);
	assert(res[3].lastLogon == "z");

	/* Search by negated conjunction of remote attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(&(lastLogon=x)(description=x)))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 4);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=B"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "y");
	assert(res[2].dn == s4.dn("cn=Z"));
	assert(res[2].objectCategory == "z");
	assert(res[2].lastLogon == "z");
	assert(res[3].dn == s4.dn("cn=C"));
	assert(res[3].objectCategory == undefined);
	assert(res[3].lastLogon == "z");

	/* Search by negated conjunction of local and remote attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(&(codePage=x)(description=x)))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 4);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	assert(res[2].dn == s4.dn("cn=Z"));
	assert(res[2].objectCategory == "z");
	assert(res[2].lastLogon == "z");
	assert(res[3].dn == s4.dn("cn=C"));
	assert(res[3].objectCategory == undefined);
	assert(res[3].lastLogon == "z");

	/* Search by negated disjunction of local attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(|(revision=x)(objectCategory=x)))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=A"));
	assert(res[1].objectCategory == undefined);
	assert(res[1].lastLogon == "x");
	assert(res[2].dn == s4.dn("cn=Z"));
	assert(res[2].objectCategory == "z");
	assert(res[2].lastLogon == "z");
	assert(res[3].dn == s4.dn("cn=C"));
	assert(res[3].objectCategory == undefined);
	assert(res[3].lastLogon == "z");

	/* Search by negated disjunction of remote attributes */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(|(badPwdCount=x)(lastLogon=x)))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 3);
	assert(res[0].dn == s4.dn("cn=Y"));
	assert(res[0].objectCategory == "y");
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=Z"));
	assert(res[1].objectCategory == "z");
	assert(res[1].lastLogon == "z");
	assert(res[2].dn == s4.dn("cn=C"));
	assert(res[2].objectCategory == undefined);
	assert(res[2].lastLogon == "z");

	/* Search by negated disjunction of local and remote attribute */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(!(|(revision=x)(lastLogon=y)))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 3);
	assert(res[0].dn == s4.dn("cn=A"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "x");
	assert(res[1].dn == s4.dn("cn=Z"));
	assert(res[1].objectCategory == "z");
	assert(res[1].lastLogon == "z");
	assert(res[2].dn == s4.dn("cn=C"));
	assert(res[2].objectCategory == undefined);
	assert(res[2].lastLogon == "z");

	/* Search by complex parse tree */
	attrs = new Array("objectCategory", "lastLogon");
	res = ldb.search("(|(&(revision=x)(objectCategory=x))(!(&(description=x)(nextRid=y)))(badPwdCount=y))", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 5);
	assert(res[0].dn == s4.dn("cn=B"));
	assert(res[0].objectCategory == undefined);
	assert(res[0].lastLogon == "y");
	assert(res[1].dn == s4.dn("cn=X"));
	assert(res[1].objectCategory == "x");
	assert(res[1].lastLogon == "x");
	assert(res[2].dn == s4.dn("cn=A"));
	assert(res[2].objectCategory == undefined);
	assert(res[2].lastLogon == "x");
	assert(res[3].dn == s4.dn("cn=Z"));
	assert(res[3].objectCategory == "z");
	assert(res[3].lastLogon == "z");
	assert(res[4].dn == s4.dn("cn=C"));
	assert(res[4].objectCategory == undefined);
	assert(res[4].lastLogon == "z");

	/* Clean up */
	var dns = new Array();
	dns[0] = s4.dn("cn=A");
	dns[1] = s4.dn("cn=B");
	dns[2] = s4.dn("cn=C");
	dns[3] = s4.dn("cn=X");
	dns[4] = s4.dn("cn=Y");
	dns[5] = s4.dn("cn=Z");
	for (i=0;i<dns.length;i++) {
		var ok = ldb.del(dns[i]);
		assert(ok);
	}
}

function test_map_modify(ldb, s3, s4)
{
	println("Running modification tests on mapped data");

	var ldif;
	var attrs;
	var dn, dn2;
	var res;
	var ok;

	println("Testing modification of local records");

	/* Add local record */
	dn = "cn=test,dc=idealx,dc=org";
	ldif = "
dn: " + dn + "
cn: test
foo: bar
revision: 1
description: test
";
	ok = ldb.add(ldif);
	assert(ok);
	/* Check it's there */
	attrs = new Array("foo", "revision", "description");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].foo == "bar");
	assert(res[0].revision == "1");
	assert(res[0].description == "test");
	/* Check it's not in the local db */
	res = s4.db.search("(cn=test)", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 0);
	/* Check it's not in the remote db */
	res = s3.db.search("(cn=test)", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res != undefined);
	assert(res.length == 0);

	/* Modify local record */
	ldif = "
dn: " + dn + "
replace: foo
foo: baz
replace: description
description: foo
";
	ok = ldb.modify(ldif);
	assert(ok);
	/* Check in local db */
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].foo == "baz");
	assert(res[0].revision == "1");
	assert(res[0].description == "foo");

	/* Rename local record */
	dn2 = "cn=toast,dc=idealx,dc=org";
	ok = ldb.rename(dn, dn2);
	assert(ok);
	/* Check in local db */
	res = ldb.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].foo == "baz");
	assert(res[0].revision == "1");
	assert(res[0].description == "foo");

	/* Delete local record */
	ok = ldb.del(dn2);
	assert(ok);
	/* Check it's gone */
	res = ldb.search("", dn2, ldb.SCOPE_BASE);
	assert(res != undefined);
	assert(res.length == 0);

	println("Testing modification of remote records");

	/* Add remote record */
	dn = s4.dn("cn=test");
	dn2 = s3.dn("cn=test");
	ldif = "
dn: " + dn2 + "
cn: test
description: foo
sambaBadPasswordCount: 3
sambaNextRid: 1001
";
	ok = s3.db.add(ldif);
	assert(ok);
	/* Check it's there */
	attrs = new Array("description", "sambaBadPasswordCount", "sambaNextRid");
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "foo");
	assert(res[0].sambaBadPasswordCount == "3");
	assert(res[0].sambaNextRid == "1001");
	/* Check in mapped db */
	attrs = new Array("description", "badPwdCount", "nextRid");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "foo");
	assert(res[0].badPwdCount == "3");
	assert(res[0].nextRid == "1001");
	/* Check in local db */
	res = s4.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 0);

	/* Modify remote data of remote record */
	ldif = "
dn: " + dn + "
replace: description
description: test
replace: badPwdCount
badPwdCount: 4
";
	ok = ldb.modify(ldif);
	/* Check in mapped db */
	attrs = new Array("description", "badPwdCount", "nextRid");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "test");
	assert(res[0].badPwdCount == "4");
	assert(res[0].nextRid == "1001");
	/* Check in remote db */
	attrs = new Array("description", "sambaBadPasswordCount", "sambaNextRid");
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "test");
	assert(res[0].sambaBadPasswordCount == "4");
	assert(res[0].sambaNextRid == "1001");

	/* Rename remote record */
	dn2 = s4.dn("cn=toast");
	ok = ldb.rename(dn, dn2);
	assert(ok);
	/* Check in mapped db */
	dn = dn2;
	attrs = new Array("description", "badPwdCount", "nextRid");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "test");
	assert(res[0].badPwdCount == "4");
	assert(res[0].nextRid == "1001");
	/* Check in remote db */
	dn2 = s3.dn("cn=toast");
	attrs = new Array("description", "sambaBadPasswordCount", "sambaNextRid");
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "test");
	assert(res[0].sambaBadPasswordCount == "4");
	assert(res[0].sambaNextRid == "1001");

	/* Delete remote record */
	ok = ldb.del(dn);
	assert(ok);
	/* Check in mapped db */
	res = ldb.search("", dn, ldb.SCOPE_BASE);
	assert(res != undefined);
	assert(res.length == 0);
	/* Check in remote db */
	res = s3.db.search("", dn2, ldb.SCOPE_BASE);
	assert(res != undefined);
	assert(res.length == 0);

	/* Add remote record (same as before) */
	dn = s4.dn("cn=test");
	dn2 = s3.dn("cn=test");
	ldif = "
dn: " + dn2 + "
cn: test
description: foo
sambaBadPasswordCount: 3
sambaNextRid: 1001
";
	ok = s3.db.add(ldif);
	assert(ok);

	/* Modify local data of remote record */
	ldif = "
dn: " + dn + "
add: revision
revision: 1
replace: description
description: test
";
	ok = ldb.modify(ldif);
	/* Check in mapped db */
	attrs = new Array("revision", "description");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "test");
	assert(res[0].revision == "1");
	/* Check in remote db */
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "test");
	assert(res[0].revision == undefined);
	/* Check in local db */
	res = s4.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == undefined);
	assert(res[0].revision == "1");

	/* Delete (newly) split record */
	ok = ldb.del(dn);
	assert(ok);

	println("Testing modification of split records");

	/* Add split record */
	dn = s4.dn("cn=test");
	dn2 = s3.dn("cn=test");
	ldif = "
dn: " + dn + "
cn: test
description: foo
badPwdCount: 3
nextRid: 1001
revision: 1
";
	ok = ldb.add(ldif);
	assert(ok);
	/* Check it's there */
	attrs = new Array("description", "badPwdCount", "nextRid", "revision");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "foo");
	assert(res[0].badPwdCount == "3");
	assert(res[0].nextRid == "1001");
	assert(res[0].revision == "1");
	/* Check in local db */
	res = s4.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == undefined);
	assert(res[0].badPwdCount == undefined);
	assert(res[0].nextRid == undefined);
	assert(res[0].revision == "1");
	/* Check in remote db */
	attrs = new Array("description", "sambaBadPasswordCount", "sambaNextRid", "revision");
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "foo");
	assert(res[0].sambaBadPasswordCount == "3");
	assert(res[0].sambaNextRid == "1001");
	assert(res[0].revision == undefined);

	/* Modify of split record */
	ldif = "
dn: " + dn + "
replace: description
description: test
replace: badPwdCount
badPwdCount: 4
replace: revision
revision: 2
";
	ok = ldb.modify(ldif);
	assert(ok);
	/* Check in mapped db */
	attrs = new Array("description", "badPwdCount", "nextRid", "revision");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "test");
	assert(res[0].badPwdCount == "4");
	assert(res[0].nextRid == "1001");
	assert(res[0].revision == "2");
	/* Check in local db */
	res = s4.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == undefined);
	assert(res[0].badPwdCount == undefined);
	assert(res[0].nextRid == undefined);
	assert(res[0].revision == "2");
	/* Check in remote db */
	attrs = new Array("description", "sambaBadPasswordCount", "sambaNextRid", "revision");
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "test");
	assert(res[0].sambaBadPasswordCount == "4");
	assert(res[0].sambaNextRid == "1001");
	assert(res[0].revision == undefined);

	/* Rename split record */
	dn2 = s4.dn("cn=toast");
	ok = ldb.rename(dn, dn2);
	assert(ok);
	/* Check in mapped db */
	dn = dn2;
	attrs = new Array("description", "badPwdCount", "nextRid", "revision");
	res = ldb.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == "test");
	assert(res[0].badPwdCount == "4");
	assert(res[0].nextRid == "1001");
	assert(res[0].revision == "2");
	/* Check in local db */
	res = s4.db.search("", dn, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn);
	assert(res[0].description == undefined);
	assert(res[0].badPwdCount == undefined);
	assert(res[0].nextRid == undefined);
	assert(res[0].revision == "2");
	/* Check in remote db */
	dn2 = s3.dn("cn=toast");
	attrs = new Array("description", "sambaBadPasswordCount", "sambaNextRid", "revision");
	res = s3.db.search("", dn2, ldb.SCOPE_BASE, attrs);
	assert(res != undefined);
	assert(res.length == 1);
	assert(res[0].dn == dn2);
	assert(res[0].description == "test");
	assert(res[0].sambaBadPasswordCount == "4");
	assert(res[0].sambaNextRid == "1001");
	assert(res[0].revision == undefined);

	/* Delete split record */
	ok = ldb.del(dn);
	assert(ok);
	/* Check in mapped db */
	res = ldb.search("", dn, ldb.SCOPE_BASE);
	assert(res != undefined);
	assert(res.length == 0);
	/* Check in local db */
	res = s4.db.search("", dn, ldb.SCOPE_BASE);
	assert(res != undefined);
	assert(res.length == 0);
	/* Check in remote db */
	res = s3.db.search("", dn2, ldb.SCOPE_BASE);
	assert(res != undefined);
	assert(res.length == 0);
}

function make_dn(rdn)
{
	return rdn + ",sambaDomainName=TESTS," + this.BASEDN;
}

function make_s4dn(rdn)
{
	return rdn + "," + this.BASEDN;
}

var ldb = ldb_init();

sys = sys_init();
var ldbfile = prefix + "/" + "test.ldb";
var ldburl = "tdb://" + ldbfile;

var samba4 = new Object("samba4 partition info");
samba4.file = prefix + "/" + "samba4.ldb";
samba4.url = "tdb://" + samba4.file;
samba4.BASEDN = "dc=vernstok,dc=nl";
samba4.db = ldb_init();
samba4.dn = make_s4dn;

var samba3 = new Object("samba3 partition info");
samba3.file = prefix + "/" + "samba3.ldb";
samba3.url = "tdb://" + samba3.file;
samba3.BASEDN = "cn=Samba3Sam";
samba3.db = ldb_init();
samba3.dn = make_dn;

sys.unlink(ldbfile);
sys.unlink(samba3.file);
sys.unlink(samba4.file);

var ok = ldb.connect(ldburl);
assert(ok);
var ok = samba3.db.connect(samba3.url);
assert(ok);
var ok = samba4.db.connect(samba4.url);
assert(ok);

setup_data(samba3, sys.file_load(datadir + "/" + "samba3.ldif"));
setup_modules(ldb, samba3, samba4, sys.file_load(datadir + "/" + "provision_samba3sam.ldif"));

ldb = ldb_init();
var ok = ldb.connect(ldburl);
assert(ok);

test_s3sam_search(ldb);
test_s3sam_modify(ldb, samba3);

sys.unlink(ldbfile);
sys.unlink(samba3.file);
sys.unlink(samba4.file);

ldb = ldb_init();
var ok = ldb.connect(ldburl);
assert(ok);
samba3.db = ldb_init();
var ok = samba3.db.connect(samba3.url);
assert(ok);
samba4.db = ldb_init();
var ok = samba4.db.connect(samba4.url);
assert(ok);

setup_modules(ldb, samba3, samba4, sys.file_load(datadir + "provision_samba3sam.ldif"));

ldb = ldb_init();
var ok = ldb.connect(ldburl);
assert(ok);

test_map_search(ldb, samba3, samba4);
test_map_modify(ldb, samba3, samba4);

sys.unlink(ldbfile);
sys.unlink(samba3.file);
sys.unlink(samba4.file);

return 0;
