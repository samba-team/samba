#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
	demonstrate access to ldb databases from ejs
*/


var ldb = ldb_init();

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
	
}

sys_init(ldb);
var dbfile = "test.ldb";
ldb.unlink(dbfile);
var ok = ldb.connect("tdb://" + dbfile);
assert(ok);

basic_tests(ldb);

ldb.unlink(dbfile);
return 0;
