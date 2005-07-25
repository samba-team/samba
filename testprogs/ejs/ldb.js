#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
	demonstrate access to ldb databases from ejs
*/


var ldb = ldb_init();
var sys;
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
@LIST: timestamps,objectguid,rdn_name
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
	assert(ok);

	ok = ldb.add("
dn: cn=x9,cn=test
objectClass: foo
x: 9
cn: X9
");
	assert(ok);

	var res = ldb.search("x=8", NULL, ldb.SCOPE_DEFAULT);
	assert(res[0].objectGUID != undefined);
	assert(res[0].createTimestamp != undefined);
	assert(res[0].whenCreated != undefined);
	assert(res[0].name == "x8");
	assert(res[0].cn == "x8");

	var res2 = ldb.search("x=9", NULL, ldb.SCOPE_DEFAULT);
	assert(res2[0].objectGUID != undefined);
	assert(res2[0].createTimestamp != undefined);
	assert(res2[0].whenCreated != undefined);
	assert(res2[0].name == "x9");
	assert(res2[0].cn == "x9");

	assert(res[0].objectGUID != res2[0].objectGUID);

}

sys = sys_init();
var dbfile = "test.ldb";
sys.unlink(dbfile);
var ok = ldb.connect("tdb://" + dbfile);
assert(ok);

basic_tests(ldb);

setup_modules(ldb);
ldb = ldb_init();
var ok = ldb.connect("tdb://" + dbfile);
assert(ok);

modules_test(ldb);

sys.unlink(dbfile);
return 0;
