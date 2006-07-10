#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
	demonstrate access to ldb databases from ejs
*/


var ldb = ldb_init();
var sys;
var options = GetOptions(ARGV, 
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

libinclude("base.js");

if (options.ARGV.length != 1) {
   println("Usage: ldap.js <HOST>");
   return -1;
}

prefix = options.ARGV[0];

function basic_tests(ldb)
{
	println("Running basic tests");
	ok = ldb.add("
dn: cn=x,cn=test
objectClass: foo
x: 3
");
	assert(ok);

	println("Testing ldb.search");
	var res = ldb.search("(objectClass=*)");
	assert(res[0].objectClass[0] == "foo");
	assert(res[0].dn == "cn=x,cn=test");
	assert(res[0].x == 3);

	ok = ldb.add("
dn: cn=x2,cn=test
objectClass: foo
x: 4
");
	assert(ok);
	var attrs = new Array("x");
	res = ldb.search("x=4", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res[0].x == 4);
	assert(res[0].objectClass == undefined);
	assert(res[0].dn == "cn=x2,cn=test");

	ok = ldb.del("cn=x,cn=test");
	assert(ok);

	ok = ldb.rename("cn=x2,cn=test", "cn=x3,cn=test");
	assert(ok);
	res = ldb.search("x=4", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res[0].dn == "cn=x3,cn=test");

	ok = ldb.modify("
dn: cn=x3,cn=test
changetype: modify
add: x
x: 7
");

	res = ldb.search("x=7");
	assert(res.length == 1);
	assert(res[0].x.length == 2);

	/* Check a few things before we add modules */
	assert(res[0].objectGUID == undefined);
	assert(res[0].createTimestamp == undefined);
	assert(res[0].whenCreated == undefined);

}
	
function setup_modules(ldb)
{
	ok = ldb.add("
dn: @MODULES
@LIST: rootdse,operational,objectguid,rdn_name,partition

dn: cn=ROOTDSE
defaultNamingContext: cn=Test

dn: @PARTITION
partition: cn=SideTest:" + prefix +  "testside.ldb
partition: cn=Sub,cn=Test:" + prefix +  "testsub.ldb
partition: cn=Test:" + prefix +  "testpartition.ldb
partition: cn=Sub,cn=Sub,cn=Test:" + prefix +  "testsubsub.ldb
");
}

/* Test the basic operation of the timestamps,objectguid and name_rdn
   modules */

function modules_test(ldb) 
{
        println("Running modules tests");
	ok = ldb.add("
dn: cn=x8,cn=test
objectClass: foo
x: 8
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	ok = ldb.add("
dn: cn=x9,cn=test
objectClass: foo
x: 9
cn: X9
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	var res = ldb.search("x=8", "cn=test", ldb.SCOPE_DEFAULT);
	assert(res[0].objectGUID != undefined);
	assert(res[0].createTimestamp == undefined);
	assert(res[0].whenCreated != undefined);
	assert(res[0].name == "x8");
	assert(res[0].cn == "x8");

	var attrs = new Array("*", "createTimestamp");
	var res2 = ldb.search("x=9", "cn=test", ldb.SCOPE_DEFAULT, attrs);
	assert(res2[0].objectGUID != undefined);
	assert(res2[0].createTimestamp != undefined);
	assert(res2[0].whenCreated != undefined);
	assert(res2[0].name == "x9");
	assert(res2[0].cn == "x9");

	assert(res[0].objectGUID != res2[0].objectGUID);

	var attrs = new Array("*");
	var res3 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res3[0].cn == undefined);
	assert(res3[0].distinguishedName == undefined);
	assert(res3[0].name == undefined);
	assert(res3[0].currentTime != undefined);
	assert(res3[0].highestCommittedUSN != undefined);
	println(res3[0].namingContexts[0]);
	println(res3[0].namingContexts[1]);
	println(res3[0].namingContexts[2]);
	println(res3[0].namingContexts[3]);

	assert(res3[0].namingContexts[0] == "cn=Test");
	assert(res3[0].namingContexts[1] == "cn=SideTest");
	assert(res3[0].namingContexts[2] == "cn=Sub,cn=Test");
	assert(res3[0].namingContexts[3] == "cn=Sub,cn=Sub,cn=Test");
	var usn = res3[0].highestCommittedUSN;
	
}

sys = sys_init();
var dbfile = "test.ldb";

sys.unlink(prefix + dbfile);
sys.unlink(prefix + "testpartition.ldb");
sys.unlink(prefix + "testsub.ldb");
sys.unlink(prefix + "testsubsub.ldb");
sys.unlink(prefix + "testside.ldb");

var ok = ldb.connect("tdb://" + prefix + dbfile);
assert(ok);

basic_tests(ldb);

setup_modules(ldb);
ldb = ldb_init();
var ok = ldb.connect("tdb://" + prefix + dbfile);
assert(ok);

modules_test(ldb);

sys.unlink(prefix + dbfile);
sys.unlink(prefix + "testpartition.ldb");
sys.unlink(prefix + "testsub.ldb");
sys.unlink(prefix + "testsubsub.ldb");
sys.unlink(prefix + "testside.ldb");
return 0;
