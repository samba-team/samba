#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
	test certin LDAP behaviours
*/

var ldb = ldb_init();
var gc_ldb = ldb_init();

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

function basic_tests(ldb, gc_ldb, base_dn, configuration_dn, schema_dn)
{
	println("Running basic tests");

	ldb.del("cn=ldaptestcomputer,cn=computers," + base_dn);
	ldb.del("cn=ldaptestcomputer3,cn=computers," + base_dn);
	ldb.del("cn=ldaptest2computer,cn=computers," + base_dn);
	ldb.del("cn=ldaptestuser,cn=users," + base_dn);
	ldb.del("cn=ldaptestuser2,cn=users," + base_dn);
	ldb.del("cn=ldaptestuser3,cn=users," + base_dn);
	ldb.del("cn=ldaptestuser4,cn=users," + base_dn);
	ldb.del("cn=ldaptestuser5,cn=users," + base_dn);
	ldb.del("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn);
	ldb.del("cn=ldaptestuser7,cn=users," + base_dn);
	ldb.del("CN=ldaptestcontainer2," + base_dn);
	ldb.del("cn=ldaptestgroup,cn=users," + base_dn);
	ldb.del("cn=ldaptestgroup2,cn=users," + base_dn);

	println("Testing group add with invalid member");
	var ok = ldb.add("
dn: cn=ldaptestgroup,cn=uSers," + base_dn + "
objectclass: group
member: cn=ldaptestuser,cn=useRs," + base_dn + "
");

	if (ok.error != 32) { /* LDAP_NO_SUCH_OBJECT */
		println(ok.errstr);
		assert(ok.error == 32);
	}

	println("Testing user add");
	var ok = ldb.add("
dn: cn=ldaptestuser,cn=uSers," + base_dn + "
objectclass: user
objectclass: person
cN: LDAPtestUSER
givenname: ldap
sn: testy
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestuser,cn=users," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
		ok = ldb.add("
dn: cn=ldaptestuser,cn=uSers," + base_dn + "
objectclass: user
objectclass: person
cN: LDAPtestUSER
givenname: ldap
sn: testy
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	var ok = ldb.add("
dn: cn=ldaptestgroup,cn=uSers," + base_dn + "
objectclass: group
member: cn=ldaptestuser,cn=useRs," + base_dn + "
");
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	var ok = ldb.add("
dn: cn=ldaptestcomputer,cn=computers," + base_dn + "
objectclass: computer
cN: LDAPtestCOMPUTER
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestcomputer,cn=computers," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
		ok = ldb.add("
dn: cn=ldaptestcomputer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtestCOMPUTER
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	var ok = ldb.add("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtest2COMPUTER
userAccountControl: 4096
displayname: ldap testy
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptest2computer,cn=computers," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
		//	assert(ok.error == 0);
		}
		ok = ldb.add("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtest2COMPUTER
userAccountControl: 4096
displayname: ldap testy
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	var ok = ldb.add("
dn: cn=ldaptestcomputer3,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtest2COMPUTER
");
	if (ok.error != 34) {
		println("Did not reject invalid RDN compared with DN: " + ok.errstr);
		assert(ok.error == 34);
	}

	var ok = ldb.add("
dn: cn=ldaptestcomputer3,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtestCOMPUTER3
sAMAccountType: 805306368
");

	if (ok.error != 53) {
		println("Did not reject invalid 'sAMAccountType: 805306368': " + ok.errstr);
		assert(ok.error == 53);
	}

	var ok = ldb.add("
dn: cn=ldaptestcomputer3,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtestCOMPUTER3
userAccountControl: 0
");

	if (ok.error != 53) {
		println("Did not reject invalid 'userAccountControl: 0': " + ok.errstr);
		assert(ok.error == 53);
	}

	var ok = ldb.add("
dn: cn=ldaptestuser7,cn=users," + base_dn + "
objectClass: user
cn: LDAPtestuser7
userAccountControl: 0
");

	if (ok.error != 53) {
		println("Did not reject invalid 'userAccountControl: 0': " + ok.errstr);
		assert(ok.error == 53);
	}

	var ok = ldb.add("
dn: cn=ldaptestuser7,cn=users," + base_dn + "
objectClass: user
cn: LDAPtestuser7
userAccountControl: 2
");

	if (ok.error != 0) {
		println("Did not accept 'userAccountControl: 2': " + ok.errstr);
		assert(ok.error == 0);
	}

	    ldb.del("cn=ldaptestuser7,cn=users," + base_dn);

	var ok = ldb.add("
dn: cn=ldaptestcomputer3,cn=computers," + base_dn + "
objectclass: computer
cN: LDAPtestCOMPUTER3
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestcomputer3,cn=computers," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
		ok = ldb.add("
dn: cn=ldaptestcomputer3,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtestCOMPUTER3
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	println("Testing ldb.search for (&(cn=ldaptestcomputer3)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestcomputer3)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestcomputer3)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestcomputer3,CN=Computers," + base_dn));
	assert(res.msgs[0].cn == "ldaptestcomputer3");
	assert(res.msgs[0].name == "ldaptestcomputer3");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "person");
	assert(res.msgs[0].objectClass[2] == "organizationalPerson");
	assert(res.msgs[0].objectClass[3] == "user");
	assert(res.msgs[0].objectClass[4] == "computer");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].objectCategory == ("CN=Computer,CN=Schema,CN=Configuration," + base_dn));
	assert(res.msgs[0].primaryGroupID == 513);
	assert(res.msgs[0].sAMAccountType == 805306368);
	assert(res.msgs[0].userAccountControl == 546);

	    ldb.del(res.msgs[0].dn);

	    println("Testing attribute or value exists behaviour");
	    ok = ldb.modify("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: cifs/ldaptest2computer
");

//LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS
		if (ok.error != 20) {
			println("Expected error LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS, got :" + ok.errstr);
			assert(ok.error == 20);
		}

	    ok = ldb.modify("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: cifs/ldaptest2computer
");

	    if (ok.error != 0) {
		    println("Failed to replace servicePrincpalName:" + ok.errstr);
		    assert(ok.error == 20);
	    }

	    ok = ldb.modify("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
");

//LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS
	    if (ok.error != 20) {
		    println("Expected error LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS, got :" + ok.errstr);
			assert(ok.error == 20);
	    }
	    
	    println("Testing ranged results");
	    ok = ldb.modify("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
changetype: modify
replace: servicePrincipalName
");
	    if (ok.error != 0) {
		    println("Failed to replace servicePrincpalName:" + ok.errstr);
		    assert(ok.error == 0);
	    }
	    
	    ok = ldb.modify("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/ldaptest2computer0
servicePrincipalName: host/ldaptest2computer1
servicePrincipalName: host/ldaptest2computer2
servicePrincipalName: host/ldaptest2computer3
servicePrincipalName: host/ldaptest2computer4
servicePrincipalName: host/ldaptest2computer5
servicePrincipalName: host/ldaptest2computer6
servicePrincipalName: host/ldaptest2computer7
servicePrincipalName: host/ldaptest2computer8
servicePrincipalName: host/ldaptest2computer9
servicePrincipalName: host/ldaptest2computer10
servicePrincipalName: host/ldaptest2computer11
servicePrincipalName: host/ldaptest2computer12
servicePrincipalName: host/ldaptest2computer13
servicePrincipalName: host/ldaptest2computer14
servicePrincipalName: host/ldaptest2computer15
servicePrincipalName: host/ldaptest2computer16
servicePrincipalName: host/ldaptest2computer17
servicePrincipalName: host/ldaptest2computer18
servicePrincipalName: host/ldaptest2computer19
servicePrincipalName: host/ldaptest2computer20
servicePrincipalName: host/ldaptest2computer21
servicePrincipalName: host/ldaptest2computer22
servicePrincipalName: host/ldaptest2computer23
servicePrincipalName: host/ldaptest2computer24
servicePrincipalName: host/ldaptest2computer25
servicePrincipalName: host/ldaptest2computer26
servicePrincipalName: host/ldaptest2computer27
servicePrincipalName: host/ldaptest2computer28
servicePrincipalName: host/ldaptest2computer29
");

	    if (ok.error != 0) {
		    println("Failed to replace servicePrincpalName:" + ok.errstr);
		    assert(ok.error == 0);
	    }
	    
	    
	    var attrs = new Array("servicePrincipalName;range=0-*");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) for servicePrincipalName;range=0-*");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
//	    println(res.msgs[0]["servicePrincipalName;range=0-*"].length);
	    assert(res.msgs[0]["servicePrincipalName;range=0-*"].length == 30);

	    var attrs = new Array("servicePrincipalName;range=0-19");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) for servicePrincipalName;range=0-19");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
//	    println(res.msgs[0]["servicePrincipalName;range=0-19"].length);
	    assert(res.msgs[0]["servicePrincipalName;range=0-19"].length == 20);

	    var attrs = new Array("servicePrincipalName;range=0-30");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName;range=0-19");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
	    assert(res.msgs[0]["servicePrincipalName;range=0-*"].length == 30);

	    var attrs = new Array("servicePrincipalName;range=0-40");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName;range=0-40");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
	    assert(res.msgs[0]["servicePrincipalName;range=0-*"].length == 30);

	    var attrs = new Array("servicePrincipalName;range=30-40");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName;range=30-40");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
	    assert(res.msgs[0]["servicePrincipalName;range=30-*"].length == 0);

	    var attrs = new Array("servicePrincipalName;range=10-40");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName;range=10-40");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
	    assert(res.msgs[0]["servicePrincipalName;range=10-*"].length == 20);
//	    var pos_11 = res.msgs[0]["servicePrincipalName;range=10-*"][18];

	    var attrs = new Array("servicePrincipalName;range=11-40");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName;range=10-*");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
	    assert(res.msgs[0]["servicePrincipalName;range=11-*"].length == 19);
//	    println(res.msgs[0]["servicePrincipalName;range=11-*"][18]);
//	    println(pos_11);
//	    assert((res.msgs[0]["servicePrincipalName;range=11-*"][18]) == pos_11);

	    var attrs = new Array("servicePrincipalName;range=11-15");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName;range=11-15");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
	    assert(res.msgs[0]["servicePrincipalName;range=11-15"].length == 5);
//	    assert(res.msgs[0]["servicePrincipalName;range=11-15"][4] == pos_11);

	    var attrs = new Array("servicePrincipalName");
	    var res = ldb.search("(cn=ldaptest2computer))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	    if (res.error != 0 || res.msgs.length != 1) {
		    println("Could not find (cn=ldaptest2computer) at servicePrincipalName");
		    assert(res.error == 0);
		    assert(res.msgs.length == 1);
	    }
//	    println(res.msgs[0]["servicePrincipalName"][18]);
//	    println(pos_11);
	    assert(res.msgs[0]["servicePrincipalName"].length == 30);
//	    assert(res.msgs[0]["servicePrincipalName"][18] == pos_11);

	    ok = ldb.add("
dn: cn=ldaptestuser2,cn=useRs," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER2
givenname: testy
sn: ldap user2
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestuser2,cn=users," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	        ok = ldb.add("
dn: cn=ldaptestuser2,cn=useRs," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER2
givenname: testy
sn: ldap user2
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}


	println("Testing Ambigious Name Resolution");
// Testing ldb.search for (&(anr=ldap testy)(objectClass=user))
	var res = ldb.search("(&(anr=ldap testy)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 3) {
		println("Could not find (&(anr=ldap testy)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 3);
	}

// Testing ldb.search for (&(anr=testy ldap)(objectClass=user))
	var res = ldb.search("(&(anr=testy ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 2) {
		println("Found only " + res.msgs.length + " for (&(anr=testy ldap)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 2);
	}

	var res = ldb.search("(&(anr=testy ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 2) {
		println("Found only " + res.msgs.length + " for (&(anr=\"testy ldap\")(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 2);
	}

// Testing ldb.search for (&(anr=ldap)(objectClass=user))
	var res = ldb.search("(&(anr=ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 4) {
		println("Found only " + res.msgs.length + " for (&(anr=ldap)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 4);
	} 

// Testing ldb.search for (&(anr==ldap)(objectClass=user))
	var res = ldb.search("(&(anr==ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Found only " + res.msgs.length + " for (&(anr=ldap)(objectClass=user))");
		println("Could not find (&(anr==ldap)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser");
	assert(res.msgs[0].name == "ldaptestuser");

// Testing ldb.search for (&(anr=testy)(objectClass=user))
	var res = ldb.search("(&(anr=testy)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 2) {
		println("Found only " + res.msgs.length + " for (&(anr=testy)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 2);
	}

// Testing ldb.search for (&(anr=ldap testy)(objectClass=user))
	var res = ldb.search("(&(anr=testy ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 2) {
		println("Found only " + res.msgs.length + " for (&(anr=ldap testy)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 2);
	}

// Testing ldb.search for (&(anr==ldap testy)(objectClass=user))
	var res = ldb.search("(&(anr==testy ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Found only " + res.msgs.length + " for (&(anr==ldap testy)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser");
	assert(res.msgs[0].name == "ldaptestuser");

// Testing ldb.search for (&(anr==testy ldap)(objectClass=user))
	var res = ldb.search("(&(anr==testy ldap)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(anr==testy ldap)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser");
	assert(res.msgs[0].name == "ldaptestuser");

	// Testing ldb.search for (&(anr=testy ldap user)(objectClass=user))
	var res = ldb.search("(&(anr=testy ldap user)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(anr=testy ldap user)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser2,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser2");
	assert(res.msgs[0].name == "ldaptestuser2");

	// Testing ldb.search for (&(anr==testy ldap user2)(objectClass=user))
	var res = ldb.search("(&(anr==testy ldap user2)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(anr==testy ldap user2)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser2,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser2");
	assert(res.msgs[0].name == "ldaptestuser2");

	// Testing ldb.search for (&(anr==ldap user2)(objectClass=user))
	var res = ldb.search("(&(anr==ldap user2)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(anr==ldap user2)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser2,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser2");
	assert(res.msgs[0].name == "ldaptestuser2");

	// Testing ldb.search for (&(anr==not ldap user2)(objectClass=user))
	var res = ldb.search("(&(anr==not ldap user2)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 0) {
		println("Must not find (&(anr==not ldap user2)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 0);
	}

	// Testing ldb.search for (&(anr=not ldap user2)(objectClass=user))
	var res = ldb.search("(&(anr=not ldap user2)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 0) {
		println("Must not find (&(anr=not ldap user2)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 0);
	}

	println("Testing Group Modifies");
	ok = ldb.modify("
dn: cn=ldaptestgroup,cn=users," + base_dn + "
changetype: modify
add: member
member: cn=ldaptestuser2,cn=users," + base_dn + "
member: cn=ldaptestcomputer,cn=computers," + base_dn + "
");

	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.del("cn=ldaptestuser3,cn=users," + base_dn);

	println("Testing adding non-existent user to a group");
	ok = ldb.modify("
dn: cn=ldaptestgroup,cn=users," + base_dn + "
changetype: modify
add: member
member: cn=ldaptestuser3,cn=users," + base_dn + "
");
	if (ok.error != 32) { /* LDAP_NO_SUCH_OBJECT */
		println(ok.errstr);
		assert(ok.error == 32);
	}

	println("Testing Renames");

	ok = ldb.rename("cn=ldaptestuser2,cn=users," + base_dn, "cn=ldaptestuser3,cn=users," + base_dn);
	if (ok.error != 0) {
		println("Could not rename cn=ldaptestuser2,cn=users," + base_dn + " into cn=ldaptestuser3,cn=users," + base_dn + ": " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser3,cn=users," + base_dn);
	if (ok.error != 0) {
		println("Could not rename cn=ldaptestuser3,cn=users," + base_dn + " onto itself: " + ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestUSER3,cn=users," + base_dn);
	if (ok.error != 0) {
		println("Could not rename cn=ldaptestuser3,cn=users," + base_dn + " into cn=ldaptestUSER3,cn=users," + base_dn + ": " + ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing ldb.search for (&(cn=ldaptestuser3)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestuser3)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser3)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestUSER3,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestUSER3");
	assert(res.msgs[0].name == "ldaptestUSER3");

	println("Testing ldb.search for (&(&(cn=ldaptestuser3)(userAccountControl=*))(objectClass=user))");
	var res = ldb.search("(&(&(cn=ldaptestuser3)(userAccountControl=*))(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser3)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestUSER3,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestUSER3");
	assert(res.msgs[0].name == "ldaptestUSER3");

	println("Testing ldb.search for (&(&(cn=ldaptestuser3)(userAccountControl=546))(objectClass=user))");
	var res = ldb.search("(&(&(cn=ldaptestuser3)(userAccountControl=546))(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(&(cn=ldaptestuser3)(userAccountControl=546))(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestUSER3,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestUSER3");
	assert(res.msgs[0].name == "ldaptestUSER3");

	println("Testing ldb.search for (&(&(cn=ldaptestuser3)(userAccountControl=547))(objectClass=user))");
	var res = ldb.search("(&(&(cn=ldaptestuser3)(userAccountControl=547))(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 0) {
		println("Should not find (&(&(cn=ldaptestuser3)(userAccountControl=547))(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 0);
	}

// This is a Samba special, and does not exist in real AD
//	println("Testing ldb.search for (dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")");
//	var res = ldb.search("(dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")");
//	if (res.error != 0 || res.msgs.length != 1) {
//		println("Could not find (dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")");
//		assert(res.error == 0);
//		assert(res.msgs.length == 1);
//	}
//	assert(res.msgs[0].dn == ("CN=ldaptestUSER3,CN=Users," + base_dn));
//	assert(res.msgs[0].cn == "ldaptestUSER3");
//	assert(res.msgs[0].name == "ldaptestUSER3");

	println("Testing ldb.search for (distinguishedName=CN=ldaptestUSER3,CN=Users," + base_dn + ")");
	var res = ldb.search("(distinguishedName=CN=ldaptestUSER3,CN=Users," + base_dn + ")");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}
	assert(res.msgs[0].dn == ("CN=ldaptestUSER3,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestUSER3");
	assert(res.msgs[0].name == "ldaptestUSER3");

	// ensure we cannot add it again
	ok = ldb.add("
dn: cn=ldaptestuser3,cn=userS," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER3
");
//LDB_ERR_ENTRY_ALREADY_EXISTS
	if (ok.error != 68) {
		println("expected error LDB_ERR_ENTRY_ALREADY_EXISTS, got: " + ok.errstr);
		assert(ok.error == 68);
	}

	// rename back
	ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser2,cn=users," + base_dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	// ensure we cannnot rename it twice
	ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser2,cn=users," + base_dn);
//LDB_ERR_NO_SUCH_OBJECT
	assert(ok.error == 32);

	// ensure can now use that name
	ok = ldb.add("
dn: cn=ldaptestuser3,cn=users," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER3
");
	
	// ensure we now cannnot rename
	ok = ldb.rename("cn=ldaptestuser2,cn=users," + base_dn, "cn=ldaptestuser3,cn=users," + base_dn);
//LDB_ERR_ENTRY_ALREADY_EXISTS
	if (ok.error != 68) {
		println("expected error LDB_ERR_ENTRY_ALREADY_EXISTS, got: " + ok.errstr);
		assert(ok.error == 68);
	}
	assert(ok.error == 68);
	ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser3,cn=configuration," + base_dn);
	if (ok.error != 71 && ok.error != 64) {
		println("expected error LDB_ERR_ENTRY_ALREADY_EXISTS or LDAP_NAMING_VIOLATION, got: " + ok.errstr);
		assert(ok.error == 71 || ok.error == 64);
	}
	assert(ok.error == 71 || ok.error == 64);

	ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser5,cn=users," + base_dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.del("cn=ldaptestuser5,cn=users," + base_dn);

	ok = ldb.del("cn=ldaptestgroup2,cn=users," + base_dn);

	ok = ldb.rename("cn=ldaptestgroup,cn=users," + base_dn, "cn=ldaptestgroup2,cn=users," + base_dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing subtree Renames");

	ok = ldb.add("
dn: cn=ldaptestcontainer," + base_dn + "
objectClass: container
");
	
	ok = ldb.add("
dn: CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER4
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestuser4,cn=ldaptestcontainer," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
		ok = ldb.add("
dn: CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER4
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
add: member
member: cn=ldaptestuser4,cn=ldaptestcontainer," + base_dn + "
");
	if (ok.error != 0) {
		println("Failure adding ldaptestuser4 to a group");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	println("Testing ldb.rename of cn=ldaptestcontainer," + base_dn + " to cn=ldaptestcontainer2," + base_dn);
	ok = ldb.rename("CN=ldaptestcontainer," + base_dn, "CN=ldaptestcontainer2," + base_dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing ldb.search for (&(cn=ldaptestuser4)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestuser4)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser4)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	println("Testing subtree ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in (just renamed from) cn=ldaptestcontainer," + base_dn);
	var res = ldb.search("(&(cn=ldaptestuser4)(objectClass=user))", "cn=ldaptestcontainer," + base_dn, ldb.SCOPE_SUBTREE);
	if (res.error != 32) {
		println(res.errstr);
		assert(res.error == 32);
	}

	println("Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in (just renamed from) cn=ldaptestcontainer," + base_dn);
	var res = ldb.search("(&(cn=ldaptestuser4)(objectClass=user))", "cn=ldaptestcontainer," + base_dn, ldb.SCOPE_ONELEVEL);
	if (res.error != 32) {
		println(res.errstr);
		assert(res.error == 32);
	}

	println("Testing ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in renamed container");
	var res = ldb.search("(&(cn=ldaptestuser4)(objectClass=user))", "cn=ldaptestcontainer2," + base_dn, ldb.SCOPE_SUBTREE);
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser4)(objectClass=user)) under cn=ldaptestcontainer2," + base_dn);
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn));
	assert(strupper(res.msgs[0].memberOf[0]) == (strupper("CN=ldaptestgroup2,CN=Users," + base_dn)));

	println("Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group)) in cn=users");
	var res_group = ldb.search("(&(cn=ldaptestgroup2)(objectClass=group))", "cn=users," + base_dn, ldb.SCOPE_SUBTREE);
	if (res_group.error != 0 || res_group.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestgroup2)(objectClass=group)) under cn=users," + base_dn);
		assert(res_group.error == 0);
		assert(res_group.msgs.length == 1);
	}

	println("Testing ldb.search for (member=CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn + ") to check subtree renames and linked attributes");
	var res = ldb.search("(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn + ")", base_dn, ldb.SCOPE_SUBTREE);
	if (res.error != 0 || res.msgs.length != 1) {
		for (i=0; i < res_group.msgs[0].member.length; i++) {
		    println("res_group.member[" +  i + "]: " + res_group.msgs[0].member[i]);
		}

		println("Could not find (member=CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn + "), perhaps linked attributes are not conistant with subtree renames?");
		println("Testing ldb.search for (member=CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn + ") to check if it just hasn't been updated");
		var res2 = ldb.search("(member=CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn + ")", base_dn, ldb.SCOPE_SUBTREE);
		if (res2.error != 0 || res2.msgs.length != 1) {
			println("Could not find (member=CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn + "), very odd, it wasn't here at all..");
		}

		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	println("Testing ldb.rename (into itself) of cn=ldaptestcontainer2," + base_dn + " to cn=ldaptestcontainer,cn=ldaptestcontainer2," + base_dn);
	ok = ldb.rename("cn=ldaptestcontainer2," + base_dn, "cn=ldaptestcontainer,cn=ldaptestcontainer2," + base_dn);
	if (ok.error != 53) { /* LDAP_UNWILLING_TO_PERFORM */
		println(ok.errstr);
		assert(ok.error == 53);
	}

	println("Testing ldb.rename (into non-existent container) of cn=ldaptestcontainer2," + base_dn + " to cn=ldaptestcontainer,cn=ldaptestcontainer3," + base_dn);
	ok = ldb.rename("cn=ldaptestcontainer2," + base_dn, "cn=ldaptestcontainer,cn=ldaptestcontainer3," + base_dn);
	if (ok.error != 53 && ok.error != 80) { /* LDAP_UNWILLING_TO_PERFORM or LDAP_OTHER*/
		println(ok.errstr);
		assert(ok.error == 53 || ok.error == 80);
	}

	println("Testing delete (should fail, not a leaf node) of renamed cn=ldaptestcontainer2," + base_dn);
	ok = ldb.del("cn=ldaptestcontainer2," + base_dn);
	if (ok.error != 66) { /* LDB_ERR_NOT_ALLOWED_ON_NON_LEAF */
		println(ok.errstr);
		assert(ok.error == 66);
	}

	println("Testing base ldb.search for CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn);
	var res = ldb.search("(objectclass=*)", ("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn), ldb.SCOPE_BASE);
	if (res.error == 0 && res.count == 1) {
		assert(res.error == 0 && res.count == 1);
	}
	var res = ldb.search("(cn=ldaptestuser40)", ("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn), ldb.SCOPE_BASE);
	if (res.error == 0 && res.count == 0) {
		assert(res.error == 0 && res.count == 0);
	}

	println("Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in cn=ldaptestcontainer2," + base_dn);
	var res = ldb.search("(&(cn=ldaptestuser4)(objectClass=user))", "cn=ldaptestcontainer2," + base_dn, ldb.SCOPE_ONELEVEL);
	if (res.error == 0 && res.count == 0) {
		assert(res.error == 0 && res.count == 0);
	}

	println("Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in cn=ldaptestcontainer2," + base_dn);
	var res = ldb.search("(&(cn=ldaptestuser4)(objectClass=user))", "cn=ldaptestcontainer2," + base_dn, ldb.SCOPE_SUBTREE);
	if (res.error == 0 && res.count == 0) {
		assert(res.error == 0 && res.count == 0);
	}

	println("Testing delete of subtree renamed "+("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn));
	ok = ldb.del(("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn));
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}
	println("Testing delete of renamed cn=ldaptestcontainer2," + base_dn);
	ok = ldb.del("cn=ldaptestcontainer2," + base_dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	ok = ldb.add("
dn: cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	ok = ldb.add("
dn: cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	ok = ldb.add("
dn: cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
	if (ok.error != 0) {
		ok = ldb.del("cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn);
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	ok = ldb.add("
dn: cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
		if (ok.error != 0) {
			println(ok.errstr);
			assert(ok.error == 0);
		}
	}

	println("Testing ldb.search for (&(cn=ldaptestuser)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestuser)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser");
	assert(res.msgs[0].name == "ldaptestuser");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "person");
	assert(res.msgs[0].objectClass[2] == "organizationalPerson");
	assert(res.msgs[0].objectClass[3] == "user");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].objectCategory == ("CN=Person,CN=Schema,CN=Configuration," + base_dn));
	assert(res.msgs[0].sAMAccountType == 805306368);
	assert(res.msgs[0].userAccountControl == 546);
	assert(strupper(res.msgs[0].memberOf[0]) == strupper("CN=ldaptestgroup2,CN=Users," + base_dn));
	assert(res.msgs[0].memberOf.length == 1);
 
	println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))");
	var res2 = ldb.search("(&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))");
	if (res2.error != 0 || res2.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))");
		assert(res2.error == 0);
		assert(res2.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res2.msgs[0].dn);

	println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon))");
	var res3 = ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))");
	if (res3.error != 0) {
		println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)): " + res3.errstr);
		assert(res3.error == 0);
	} else if (res3.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)): matched " + res3.msgs.length);
		assert(res3.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res3.msgs[0].dn);

	if (gc_ldb != undefined) {
		println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog");
		var res3gc = gc_ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))");
		if (res3gc.error != 0) {
			println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog: " + res3gc.errstr);
			assert(res3gc.error == 0);
		} else if (res3gc.msgs.length != 1) {
			println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog: matched " + res3gc.msgs.length);
			assert(res3gc.msgs.length == 1);
		}
	
		assert(res.msgs[0].dn == res3gc.msgs[0].dn);
	}

	println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in with 'phantom root' control");
	var attrs = new Array("cn");
	var controls = new Array("search_options:1:2");
	var res3control = gc_ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))", base_dn, ldb.SCOPE_SUBTREE, attrs, controls);
	if (res3control.error != 0 || res3control.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog");
		assert(res3control.error == 0);
		assert(res3control.msgs.length == 1);
	}
	
	assert(res.msgs[0].dn == res3control.msgs[0].dn);

	ok = ldb.del(res.msgs[0].dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestcomputer)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestcomputer)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestcomputer,CN=Computers," + base_dn));
	assert(res.msgs[0].cn == "ldaptestcomputer");
	assert(res.msgs[0].name == "ldaptestcomputer");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "person");
	assert(res.msgs[0].objectClass[2] == "organizationalPerson");
	assert(res.msgs[0].objectClass[3] == "user");
	assert(res.msgs[0].objectClass[4] == "computer");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].objectCategory == "cn=Computer,cn=Schema,cn=Configuration," + base_dn);
	assert(res.msgs[0].sAMAccountType == 805306368);
	assert(res.msgs[0].userAccountControl == 546);

	println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
	var res2 = ldb.search("(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
	if (res2.error != 0 || res2.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
		assert(res2.error == 0);
		assert(res2.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res2.msgs[0].dn);

	if (gc_ldb != undefined) {
		println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + ")) in Global Catlog");
		var res2gc = gc_ldb.search("(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
		if (res2gc.error != 0 || res2gc.msgs.length != 1) {
			println("Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + ")) in Global Catlog");
			assert(res2gc.error == 0);
			assert(res2gc.msgs.length == 1);
		}

		assert(res.msgs[0].dn == res2gc.msgs[0].dn);
	}

	println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER))");
	var res3 = ldb.search("(&(cn=ldaptestcomputer)(objectCategory=compuTER))");
	if (res3.error != 0 || res3.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER))");
		assert(res3.error == 0);
		assert(res3.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res3.msgs[0].dn);

	if (gc_ldb != undefined) {
		println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog");
		var res3gc = gc_ldb.search("(&(cn=ldaptestcomputer)(objectCategory=compuTER))");
		if (res3gc.error != 0 || res3gc.msgs.length != 1) {
			println("Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog");
			assert(res3gc.error == 0);
			assert(res3gc.msgs.length == 1);
		}

		assert(res.msgs[0].dn == res3gc.msgs[0].dn);
	}

	println("Testing ldb.search for (&(cn=ldaptestcomp*r)(objectCategory=compuTER))");
	var res4 = ldb.search("(&(cn=ldaptestcomp*r)(objectCategory=compuTER))");
	if (res4.error != 0 || res4.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestcomp*r)(objectCategory=compuTER))");
		assert(res4.error == 0);
		assert(res4.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res4.msgs[0].dn);

	println("Testing ldb.search for (&(cn=ldaptestcomput*)(objectCategory=compuTER))");
	var res5 = ldb.search("(&(cn=ldaptestcomput*)(objectCategory=compuTER))");
	if (res5.error != 0 || res5.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestcomput*)(objectCategory=compuTER))");
		assert(res5.error == 0);
		assert(res5.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res5.msgs[0].dn);

	println("Testing ldb.search for (&(cn=*daptestcomputer)(objectCategory=compuTER))");
	var res6 = ldb.search("(&(cn=*daptestcomputer)(objectCategory=compuTER))");
	if (res6.error != 0 || res6.msgs.length != 1) {
		println("Could not find (&(cn=*daptestcomputer)(objectCategory=compuTER))");
		assert(res6.error == 0);
		assert(res6.msgs.length == 1);
	}

	assert(res.msgs[0].dn == res6.msgs[0].dn);

	ok = ldb.del(res.msgs[0].dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing ldb.search for (&(cn=ldaptest2computer)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptest2computer)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptest2computer)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptest2computer,CN=Computers," + base_dn));
	assert(res.msgs[0].cn == "ldaptest2computer");
	assert(res.msgs[0].name == "ldaptest2computer");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "person");
	assert(res.msgs[0].objectClass[2] == "organizationalPerson");
	assert(res.msgs[0].objectClass[3] == "user");
	assert(res.msgs[0].objectClass[4] == "computer");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].objectCategory == "cn=Computer,cn=Schema,cn=Configuration," + base_dn);
	assert(res.msgs[0].sAMAccountType == 805306369);
	assert(res.msgs[0].userAccountControl == 4096);


   	ok = ldb.del(res.msgs[0].dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

        var attrs = new Array("cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "memberOf");
	println("Testing ldb.search for (&(cn=ldaptestUSer2)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestUSer2)(objectClass=user))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestUSer2)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestuser2,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestuser2");
	assert(res.msgs[0].name == "ldaptestuser2");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "person");
	assert(res.msgs[0].objectClass[2] == "organizationalPerson");
	assert(res.msgs[0].objectClass[3] == "user");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].nTSecurityDescriptor != undefined);
	assert(res.msgs[0].memberOf[0] == ("CN=ldaptestgroup2,CN=Users," + base_dn));

        var attrs = new Array("cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "member");
	println("Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group))");
	var res = ldb.search("(&(cn=ldaptestgroup2)(objectClass=group))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestgroup2)(objectClass=group))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestgroup2,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestgroup2");
	assert(res.msgs[0].name == "ldaptestgroup2");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "group");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);
	assert(res.msgs[0].nTSecurityDescriptor != undefined);
	assert(res.msgs[0].member[0] == ("CN=ldaptestuser2,CN=Users," + base_dn));
	assert(res.msgs[0].member.length == 1);

	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
replace: member
member: CN=ldaptestuser2,CN=Users," + base_dn + "
member: CN=ldaptestutf8user èùéìòà,CN=Users," + base_dn + "
");
	if (ok.error != 0) {
		println("Failure testing replace of linked attributes");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	println("Testing Linked attribute behaviours");
	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
delete: member
");
	if (ok.error != 0) {
		println("Failure testing delete of linked attributes");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
add: member
member: CN=ldaptestuser2,CN=Users," + base_dn + "
member: CN=ldaptestutf8user èùéìòà,CN=Users," + base_dn + "
");
	if (ok.error != 0) {
		println("Failure testing add of linked attributes");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
replace: member
");
	if (ok.error != 0) {
		println("Failure testing replace of linked attributes");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
add: member
member: CN=ldaptestuser2,CN=Users," + base_dn + "
member: CN=ldaptestutf8user èùéìòà,CN=Users," + base_dn + "
");
	if (ok.error != 0) {
		println("Failure testing add of linked attributes");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	ok = ldb.modify("
dn: cn=ldaptestgroup2,cn=users," + base_dn + "
changetype: modify
delete: member
member: CN=ldaptestutf8user èùéìòà,CN=Users," + base_dn + "
");
	if (ok.error != 0) {
		println("Failure testing replace of linked attributes");
		println(ok.errstr);
		assert(ok.error == 0);
	}
	
	var res = ldb.search("(&(cn=ldaptestgroup2)(objectClass=group))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestgroup2)(objectClass=group))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestgroup2,CN=Users," + base_dn));
	assert(res.msgs[0].member[0] == ("CN=ldaptestuser2,CN=Users," + base_dn));
	assert(res.msgs[0].member.length == 1);

	ok = ldb.del(("CN=ldaptestuser2,CN=Users," + base_dn));
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

        var attrs = new Array("cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "member");
	println("Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group)) to check linked delete");
	var res = ldb.search("(&(cn=ldaptestgroup2)(objectClass=group))", base_dn, ldb.SCOPE_SUBTREE, attrs);
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestgroup2)(objectClass=group)) to check linked delete");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestgroup2,CN=Users," + base_dn));
	assert(res.msgs[0].member == undefined);

	println("Testing ldb.search for (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");

	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	assert(res.msgs[0].dn == ("CN=ldaptestutf8user èùéìòà,CN=Users," + base_dn));
	assert(res.msgs[0].cn == "ldaptestutf8user èùéìòà");
	assert(res.msgs[0].name == "ldaptestutf8user èùéìòà");
	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "person");
	assert(res.msgs[0].objectClass[2] == "organizationalPerson");
	assert(res.msgs[0].objectClass[3] == "user");
	assert(res.msgs[0].objectGUID != undefined);
	assert(res.msgs[0].whenCreated != undefined);

	ok = ldb.del(res.msgs[0].dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing ldb.search for (&(cn=ldaptestutf8user2*)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestutf8user2*)(objectClass=user))");
	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (&(cn=ldaptestutf8user2*)(objectClass=user))");
		assert(res.error == 0);
		assert(res.msgs.length == 1);
	}

	ok = ldb.del(res.msgs[0].dn);
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	ok = ldb.del(("CN=ldaptestgroup2,CN=Users," + base_dn))
	if (ok.error != 0) {
		println(ok.errstr);
		assert(ok.error == 0);
	}

	println("Testing ldb.search for (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");

	if (res.error != 0 || res.msgs.length != 1) {
		println("Could not find (expect space collapse, win2k3 fails) (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))");
	} else {
		assert(res.msgs[0].dn == ("cn=ldaptestutf8user2 èùéìòà,cn=users," + base_dn));
		assert(res.msgs[0].cn == "ldaptestutf8user2 èùéìòà");
	}

	println("Testing that we can't get at the configuration DN from the main search base");
	var attrs = new Array("cn");
	var res = ldb.search("objectClass=crossRef", base_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	if (res.msgs.length != 0) {
		println("Got configuration DN " + res.msgs[0].dn + " which should not be able to be seen from main search base");
	}
	assert(res.msgs.length == 0);

	println("Testing that we can get at the configuration DN from the main search base on the LDAP port with the 'phantom root' search_options control");
	var attrs = new Array("cn");
	var controls = new Array("search_options:1:2");
	var res = ldb.search("objectClass=crossRef", base_dn, ldb.SCOPE_SUBTREE, attrs, controls);
	assert(res.error == 0);
	assert(res.msgs.length > 0);

	if (gc_ldb != undefined) {
		println("Testing that we can get at the configuration DN from the main search base on the GC port with the search_options control == 0");
		var attrs = new Array("cn");
		var controls = new Array("search_options:1:0");
		var res = gc_ldb.search("objectClass=crossRef", base_dn, gc_ldb.SCOPE_SUBTREE, attrs, controls);
		assert(res.error == 0);
		assert(res.msgs.length > 0);

		println("Testing that we do find configuration elements in the global catlog");
		var attrs = new Array("cn");
		var res = gc_ldb.search("objectClass=crossRef", base_dn, ldb.SCOPE_SUBTREE, attrs);
		assert(res.error == 0);
		assert (res.msgs.length > 0);
	
		println("Testing that we do find configuration elements and user elements at the same time");
		var attrs = new Array("cn");
		var res = gc_ldb.search("(|(objectClass=crossRef)(objectClass=person))", base_dn, ldb.SCOPE_SUBTREE, attrs);
		assert(res.error == 0);
		assert (res.msgs.length > 0);

		println("Testing that we do find configuration elements in the global catlog, with the configuration basedn");
		var attrs = new Array("cn");
		var res = gc_ldb.search("objectClass=crossRef", configuration_dn, ldb.SCOPE_SUBTREE, attrs);
		assert(res.error == 0);
		assert (res.msgs.length > 0);
	}

	println("Testing that we can get at the configuration DN on the main LDAP port");
	var attrs = new Array("cn");
	var res = ldb.search("objectClass=crossRef", configuration_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	assert (res.msgs.length > 0);

	println("Testing objectCategory canonacolisation");
	var attrs = new Array("cn");
	var res = ldb.search("objectCategory=ntDsDSA", configuration_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	if (res.msgs.length == 0) {
		println("Didn't find any records with objectCategory=ntDsDSA");
	}
	assert(res.msgs.length != 0);
	
	var attrs = new Array("cn");
	var res = ldb.search("objectCategory=CN=ntDs-DSA," + schema_dn, configuration_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	if (res.msgs.length == 0) {
		println("Didn't find any records with objectCategory=CN=ntDs-DSA," + schema_dn);
	}
	assert(res.msgs.length != 0);
	
	println("Testing objectClass attribute order on "+ base_dn);
	var attrs = new Array("objectClass");
	var res = ldb.search("objectClass=domain", base_dn, ldb.SCOPE_BASE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length == 1);

	assert(res.msgs[0].objectClass[0] == "top");
	assert(res.msgs[0].objectClass[1] == "domain");
	assert(res.msgs[0].objectClass[2] == "domainDNS");

//  check enumeration

 	var attrs = new Array("cn");
	println("Testing ldb.search for objectCategory=person");
	var res = ldb.search("objectCategory=person", base_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length > 0);

 	var attrs = new Array("cn");
	var controls = new Array("domain_scope:1");
	println("Testing ldb.search for objectCategory=person with domain scope control");
	var res = ldb.search("objectCategory=person", base_dn, ldb.SCOPE_SUBTREE, attrs, controls);
	assert(res.error == 0);
	assert(res.msgs.length > 0);
 
	var attrs = new Array("cn");
	println("Testing ldb.search for objectCategory=user");
	var res = ldb.search("objectCategory=user", base_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length > 0);

 	var attrs = new Array("cn");
	var controls = new Array("domain_scope:1");
	println("Testing ldb.search for objectCategory=user with domain scope control");
	var res = ldb.search("objectCategory=user", base_dn, ldb.SCOPE_SUBTREE, attrs, controls);
	assert(res.error == 0);
	assert(res.msgs.length > 0);
	
 	var attrs = new Array("cn");
	println("Testing ldb.search for objectCategory=group");
	var res = ldb.search("objectCategory=group", base_dn, ldb.SCOPE_SUBTREE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length > 0);

 	var attrs = new Array("cn");
	var controls = new Array("domain_scope:1");
	println("Testing ldb.search for objectCategory=group with domain scope control");
	var res = ldb.search("objectCategory=group", base_dn, ldb.SCOPE_SUBTREE, attrs, controls);
	assert(res.error == 0);
	assert(res.msgs.length > 0);
	
}

function basedn_tests(ldb, gc_ldb)
{
	println("Testing for all rootDSE attributes");
	var attrs = new Array();
	var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length == 1);

	println("Testing for highestCommittedUSN");
	var attrs = new Array("highestCommittedUSN");
	var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length == 1);
	assert(res.msgs[0].highestCommittedUSN != undefined);
	assert(res.msgs[0].highestCommittedUSN != 0);

	println("Testing for netlogon via LDAP");
	var attrs = new Array("netlogon");
	var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length == 0);

	println("Testing for netlogon and highestCommittedUSN via LDAP");
	var attrs = new Array("netlogon", "highestCommittedUSN");
	var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res.error == 0);
	assert(res.msgs.length == 0);
}

function find_basedn(ldb)
{
    var attrs = new Array("defaultNamingContext");
    var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
    assert(res.error == 0);
    assert(res.msgs.length == 1);
    return res.msgs[0].defaultNamingContext;
}

function find_configurationdn(ldb)
{
    var attrs = new Array("configurationNamingContext");
    var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
    assert(res.error == 0);
    assert(res.msgs.length == 1);
    return res.msgs[0].configurationNamingContext;
}

function find_schemadn(ldb)
{
    var attrs = new Array("schemaNamingContext");
    var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
    assert(res.error == 0);
    assert(res.msgs.length == 1);
    return res.msgs[0].schemaNamingContext;
}

/* use command line creds if available */
ldb.credentials = options.get_credentials();
gc_ldb.credentials = options.get_credentials();

var ok = ldb.connect("ldap://" + host);
var base_dn = find_basedn(ldb);

var configuration_dn = find_configurationdn(ldb);
var schema_dn = find_schemadn(ldb);

println("baseDN: %s\n", base_dn);

var ok = gc_ldb.connect("ldap://" + host + ":3268");
if (!ok) {
	gc_ldb = undefined;
}

basic_tests(ldb, gc_ldb, base_dn, configuration_dn, schema_dn)

basedn_tests(ldb, gc_ldb)

return 0;
