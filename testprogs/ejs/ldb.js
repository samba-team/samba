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
partition: cn=Sub,cn=PartTest:" + prefix +  "testsub.ldb
partition: cn=PartTest:" + prefix +  "testpartition.ldb
partition: cn=Sub,cn=Sub,cn=PartTest:" + prefix +  "testsubsub.ldb
");
}

/* Test the basic operation of the timestamps,objectguid and name_rdn
   modules */

function modules_test(ldb) 
{
        println("Running modules tests");

        ok = ldb.add("
dn: @ATTRIBUTES
caseattr: CASE_INSENSITIVE
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	ok = ldb.add("
dn: cn=x8,cn=PartTest
objectClass: foo
x: 8
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	ok = ldb.add("
dn: cn=x9,cn=PartTest
objectClass: foo
x: 9
cn: X9
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	var res = ldb.search("x=8", "cn=PartTest", ldb.SCOPE_DEFAULT);
	assert(res[0].objectGUID != undefined);
	assert(res[0].createTimestamp == undefined);
	assert(res[0].whenCreated != undefined);
	assert(res[0].name == "x8");
	assert(res[0].cn == "x8");

	var attrs = new Array("*", "createTimestamp");
	var res2 = ldb.search("x=9", "cn=PartTest", ldb.SCOPE_DEFAULT, attrs);
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

	assert(res3[0].namingContexts[0] == "cn=Sub,cn=Sub,cn=PartTest");
	assert(res3[0].namingContexts[1] == "cn=Sub,cn=PartTest");
	assert(res3[0].namingContexts[2] == "cn=PartTest");
	assert(res3[0].namingContexts[3] == "cn=SideTest");
	var usn = res3[0].highestCommittedUSN;

	/* Start a transaction.  We are going to abort it later, to
	 * show we clean up all partitions */

	ok = ldb.transaction_start()
	if (!ok) {
		println("Failed to start a transaction: " + ldb.errstring());
		assert(ok);
	}

	
	ok = ldb.add("
dn: cn=x10,cn=parttest
objectClass: foo
x: 10
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	var attrs = new Array("highestCommittedUSN");
	var res4 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	var usn2 = res4[0].highestCommittedUSN;
	assert(usn < res4[0].highestCommittedUSN);

	ok = ldb.add("
dn: cn=x11,cn=sub,cn=parttest
objectClass: foo
x: 11
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	var attrs = new Array("highestCommittedUSN");
	var res5 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(usn2 < res5[0].highestCommittedUSN);
	
	var attrs = new Array("*", "createTimestamp");
	var res6 = ldb.search("x=11", "cn=parttest", ldb.SCOPE_SUB, attrs);
	assert(res6.length == 0);

	var attrs = new Array("*", "createTimestamp");
	var res7 = ldb.search("x=10", "cn=sub,cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res7.length == 0);

	var res8 = ldb.search("x=11", "cn=sub,cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res8[0].objectGUID != undefined);
	assert(res8[0].createTimestamp != undefined);
	assert(res8[0].whenCreated != undefined);
	assert(res8[0].name == "x11");
	assert(res8[0].cn == "x11");

	ok = ldb.add("
dn: caseattr=XY,cn=PartTest
objectClass: foo
x: Y
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	ok = ldb.add("
dn: caseattr=XZ,cn=PartTest
objectClass: foo
x: Z
caseattr: XZ
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	ok = ldb.add("
dn: caseattr2=XZ,cn=PartTest
objectClass: foo
x: Z
caseattr2: XZ
");
	if (!ok) {
		println("Failed to add: " + ldb.errstring());
		assert(ok);
	}

	var resX = ldb.search("caseattr=xz", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(resX.length == 1); 
	assert(resX[0].objectGUID != undefined);
	assert(resX[0].createTimestamp != undefined);
	assert(resX[0].whenCreated != undefined);
	assert(resX[0].name == "XZ");

	var rescount = ldb.search("(|(caseattr=*)(cn=*))", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(rescount.length == 5); 

	/* Check this attribute is *not* case sensitive */
	var resXcount = ldb.search("caseattr=x*", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(resXcount.length == 2); 
	
	/* Check that this attribute *is* case sensitive */
	var resXcount2 = ldb.search("caseattr2=xz", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(resXcount2.length == 0); 
	

	/* Now abort the transaction to show that even with
	 * partitions, it is aborted everywhere */
	ok = ldb.transaction_cancel();
	if (!ok) {
		println("Failed to cancel a transaction: " + ldb.errstring());
		assert(ok);
	}

	/* now check it all went away */

	var attrs = new Array("highestCommittedUSN");
	var res9 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(usn == res9[0].highestCommittedUSN);
	
	var attrs = new Array("*");
	var res10 = ldb.search("x=11", "cn=sub,cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res10.length == 0);

	var attrs = new Array("*");
	var res11 = ldb.search("x=10", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res11.length == 0);

	var attrs = new Array("*");
	var res12 = ldb.search("caseattr=*", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res12.length == 0);

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
