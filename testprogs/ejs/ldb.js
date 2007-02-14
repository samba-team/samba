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
   println("Usage: ldb.js <prefix>");
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
	assert(ok.error == 0);

	println("Testing ldb.search");
	var res = ldb.search("(objectClass=*)");
	assert(res.msgs[0].objectClass[0] == "foo");
	assert(res.msgs[0].dn == "cn=x,cn=test");
	assert(res.msgs[0].x == 3);

	ok = ldb.add("
dn: cn=x2,cn=test
objectClass: foo
x: 4
");
	assert(ok.error == 0);
	var attrs = new Array("x");
	res = ldb.search("x=4", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res.msgs[0].x == 4);
	assert(res.msgs[0].objectClass == undefined);
	assert(res.msgs[0].dn == "cn=x2,cn=test");

	ok = ldb.del("cn=x,cn=test");
	assert(ok.error == 0);

	ok = ldb.rename("cn=x2,cn=test", "cn=x3,cn=test");
	assert(ok.error == 0);
	res = ldb.search("x=4", NULL, ldb.SCOPE_DEFAULT, attrs);
	assert(res.msgs[0].dn == "cn=x3,cn=test");

	ok = ldb.modify("
dn: cn=x3,cn=test
changetype: modify
add: x
x: 7
");

	res = ldb.search("x=7");
	assert(res.msgs.length == 1);
	assert(res.msgs[0].x.length == 2);

	/* Check a few things before we add modules */
	assert(res.msgs[0].objectGUID == undefined);
	assert(res.msgs[0].createTimestamp == undefined);
	assert(res.msgs[0].whenCreated == undefined);

}
	
function setup_modules(ldb)
{
	ok = ldb.add("
dn: @MODULES
@LIST: rootdse,operational,rdn_name,partition

dn: cn=ROOTDSE
defaultNamingContext: cn=Test

dn: @PARTITION
partition: cn=SideTest:" + prefix + "/" + "testside.ldb
partition: cn=Sub,cn=PartTest:" + prefix + "/" + "testsub.ldb
partition: cn=PartTest:" + prefix + "/" + "testpartition.ldb
partition: cn=Sub,cn=Sub,cn=PartTest:" + prefix + "/" + "testsubsub.ldb
replicateEntries: @SUBCLASSES
replicateEntries: @ATTRIBUTES
replicateEntries: @INDEXLIST
modules: cn=PartTest:objectguid
");
}

/* Test the basic operation of the timestamps,objectguid and name_rdn
   modules */

function modules_test(ldb, parttestldb) 
{
        println("Running modules tests");

        ok = ldb.add("
dn: @ATTRIBUTES
cn: CASE_INSENSITIVE
caseattr: CASE_INSENSITIVE
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	/* Confirm that the attributes were replicated */
	var res_attrs =  parttestldb.search("cn=*", "@ATTRIBUTES",  parttestldb.SCOPE_BASE);
	assert(res_attrs.msgs[0].cn == "CASE_INSENSITIVE");

	ok = ldb.add("
dn: cn=x8,cn=PartTest
objectClass: foo
x: 8
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.add("
dn: cn=x9,cn=PartTest
objectClass: foo
x: 9
cn: X9
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.add("
dn: cn=X9,cn=PartTest
objectClass: foo
x: 9
cn: X9
");
	if (ok.error == 0) {
		println("Should have failed to add cn=X9,cn=PartTest");
		assert(ok.error != 0);
	}

	var res = ldb.search("x=8", "cn=PartTest", ldb.SCOPE_DEFAULT);
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].uSNCreated != undefined);
	assert(res.msgs[0].uSNChanged != undefined);
	assert(res.msgs[0].createTimestamp == undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].name == "x8");
	assert(res.msgs[0].cn == "x8");

	/* Confirm that this ended up in the correct LDB */
	var res_otherldb =  parttestldb.search("x=8", "cn=PartTest",  parttestldb.SCOPE_DEFAULT);
	assert(res_otherldb.msgs[0].objectGUID != undefined);
	assert(res_otherldb.msgs[0].createTimestamp == undefined);
	assert(res_otherldb.msgs[0].whenCreated != undefined);
	assert(res_otherldb.msgs[0].name == "x8");
	assert(res_otherldb.msgs[0].cn == "x8");

	var attrs = new Array("*", "createTimestamp");
	var res2 = ldb.search("x=9", "cn=PartTest", ldb.SCOPE_DEFAULT, attrs);
	assert(res2.msgs[0].objectGUID != undefined);
	assert(res2.msgs[0].createTimestamp != undefined);
	assert(res2.msgs[0].whenCreated != undefined);
	assert(res2.msgs[0].name == "x9");
	assert(res2.msgs[0].cn == "x9");

	assert(res.msgs[0].objectGUID != res2.msgs[0].objectGUID);

	var attrs = new Array("*");
	var res3 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res3.msgs[0].cn == undefined);
	assert(res3.msgs[0].distinguishedName == undefined);
	assert(res3.msgs[0].name == undefined);
	assert(res3.msgs[0].currentTime != undefined);
	assert(res3.msgs[0].highestCommittedUSN != undefined);

	assert(res3.msgs[0].namingContexts[0] == "cn=Sub,cn=Sub,cn=PartTest");
	assert(res3.msgs[0].namingContexts[1] == "cn=Sub,cn=PartTest");
	assert(res3.msgs[0].namingContexts[2] == "cn=PartTest");
	assert(res3.msgs[0].namingContexts[3] == "cn=SideTest");
	var usn = res3.msgs[0].highestCommittedUSN;

	/* Start a transaction.  We are going to abort it later, to
	 * show we clean up all partitions */

	ok = ldb.transaction_start()
	if (!ok) {
		println("Failed to start a transaction: " + ok.errstr);
		assert(ok.error == 0);
	}

	
	ok = ldb.add("
dn: cn=x10,cn=parttest
objectClass: foo
x: 10
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	var attrs = new Array("highestCommittedUSN");
	var res4 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	var usn2 = res4.msgs[0].highestCommittedUSN;
	assert(usn < res4.msgs[0].highestCommittedUSN);

	ok = ldb.add("
dn: cn=x11,cn=sub,cn=parttest
objectClass: foo
x: 11
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	var attrs = new Array("highestCommittedUSN");
	var res5 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(usn2 < res5.msgs[0].highestCommittedUSN);
	
	var attrs = new Array("*", "createTimestamp");
	var res6 = ldb.search("x=11", "cn=parttest", ldb.SCOPE_SUB, attrs);
	assert(res6.msgs.length == 0);

	var attrs = new Array("*", "createTimestamp");
	var res7 = ldb.search("x=10", "cn=sub,cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res7.msgs.length == 0);

	var res8 = ldb.search("x=11", "cn=sub,cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	
	assert(res8.msgs[0].objectGUID == undefined); /* The objectGUID module is not loaded here */
	assert(res8.msgs[0].uSNCreated == undefined); /* The objectGUID module is not loaded here */
	assert(res8.msgs[0].name == "x11");
	assert(res8.msgs[0].cn == "x11");

	ok = ldb.add("
dn: caseattr=XY,cn=PartTest
objectClass: foo
x: Y
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.add("
dn: caseattr=XZ,cn=PartTest
objectClass: foo
x: Z
caseattr: XZ
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.add("
dn: caseattr=xz,cn=PartTest
objectClass: foo
x: Z
caseattr: xz
");
	if (ok.error == 0) {
		println("Should have failed to add caseattr=xz,cn=PartTest");
		assert(ok.error != 0);
	}

	ok = ldb.add("
dn: caseattr2=XZ,cn=PartTest
objectClass: foo
x: Z
caseattr2: XZ
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.add("
dn: caseattr2=Xz,cn=PartTest
objectClass: foo
x: Z
caseattr2: Xz
");
	if (ok.error != 0) {
		println("Failed to add: " + ok.errstr);
		assert(ok.error == 0);
	}

	var resX = ldb.search("caseattr=xz", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(resX.msgs.length == 1); 
	assert(resX.msgs[0].objectGUID != undefined);
	assert(resX.msgs[0].createTimestamp != undefined);
	assert(resX.msgs[0].whenCreated != undefined);
	assert(resX.msgs[0].name == "XZ");

	var rescount = ldb.search("(|(caseattr=*)(cn=*))", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(rescount.msgs.length == 5); 

	/* Check this attribute is *not* case sensitive */
	var resXcount = ldb.search("caseattr=x*", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(resXcount.msgs.length == 2); 
	
	/* Check that this attribute *is* case sensitive */
	var resXcount2 = ldb.search("caseattr2=xz", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(resXcount2.msgs.length == 0); 
	

	/* Now abort the transaction to show that even with
	 * partitions, it is aborted everywhere */
	ok = ldb.transaction_cancel();
	if (!ok) {
		println("Failed to cancel a transaction: " + ok.errstr);
		assert(ok);
	}

	/* now check it all went away */

	var attrs = new Array("highestCommittedUSN");
	var res9 = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(usn == res9.msgs[0].highestCommittedUSN);
	
	var attrs = new Array("*");
	var res10 = ldb.search("x=11", "cn=sub,cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res10.msgs.length == 0);

	var attrs = new Array("*");
	var res11 = ldb.search("x=10", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res11.msgs.length == 0);

	var attrs = new Array("*");
	var res12 = ldb.search("caseattr=*", "cn=parttest", ldb.SCOPE_DEFAULT, attrs);
	assert(res12.msgs.length == 0);

}

sys = sys_init();
var dbfile = "test.ldb";

sys.unlink(prefix + "/" + dbfile);
sys.unlink(prefix + "/" + "testpartition.ldb");
sys.unlink(prefix + "/" + "testsub.ldb");
sys.unlink(prefix + "/" + "testsubsub.ldb");
sys.unlink(prefix + "/" + "testside.ldb");

var ok = ldb.connect("tdb://" + prefix + "/" + dbfile);
assert(ok);

basic_tests(ldb);

setup_modules(ldb);
ldb = ldb_init();
var ok = ldb.connect("tdb://" + prefix + "/" + dbfile);
assert(ok);

parttestldb = ldb_init();
var ok = parttestldb.connect("tdb://" + prefix + "/" + "testpartition.ldb");
assert(ok);

modules_test(ldb, parttestldb);

sys.unlink(prefix + "/" + dbfile);
sys.unlink(prefix + "/" + "testpartition.ldb");
sys.unlink(prefix + "/" + "testsub.ldb");
sys.unlink(prefix + "/" + "testsubsub.ldb");
sys.unlink(prefix + "/" + "testside.ldb");
return 0;
