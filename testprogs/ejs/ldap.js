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

function basic_tests(ldb, gc_ldb, base_dn, configuration_dn)
{
	println("Running basic tests");

	ldb.del("cn=ldaptestuser,cn=users," + base_dn);

	var ok = ldb.add("
dn: cn=ldaptestuser,cn=users," + base_dn + "
objectClass: user
objectClass: person
cn: LDAPtestUSER
");
	if (!ok) {
		ok = ldb.del("cn=ldaptestuser,cn=users," + base_dn);
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
		ok = ldb.add("
dn: cn=ldaptestuser,cn=users," + base_dn + "
objectClass: user
objectClass: person
cn: LDAPtestUSER
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	}

	var ok = ldb.add("
dn: cn=ldaptestcomputer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtestCOMPUTER
");
	if (!ok) {
		ok = ldb.del("cn=ldaptestcomputer,cn=computers," + base_dn);
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
		ok = ldb.add("
dn: cn=ldaptestcomputer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtestCOMPUTER
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	}

	var ok = ldb.add("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtest2COMPUTER
userAccountControl: 4096
");
	if (!ok) {
		ok = ldb.del("cn=ldaptest2computer,cn=computers," + base_dn);
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
		ok = ldb.add("
dn: cn=ldaptest2computer,cn=computers," + base_dn + "
objectClass: computer
cn: LDAPtest2COMPUTER
userAccountControl: 4096
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	}

	ok = ldb.add("
dn: cn=ldaptestuser2,cn=users," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER2
");
	if (!ok) {
		ok = ldb.del("cn=ldaptestuser2,cn=users," + base_dn);
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	        ok = ldb.add("
dn: cn=ldaptestuser2,cn=users," + base_dn + "
objectClass: person
objectClass: user
cn: LDAPtestUSER2
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	}

	ok = ldb.add("
dn: cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
	if (!ok) {
		ok = ldb.del("cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn);
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	ok = ldb.add("
dn: cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	}

	ok = ldb.add("
dn: cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
	if (!ok) {
		ok = ldb.del("cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn);
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	ok = ldb.add("
dn: cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn + "
objectClass: user
");
		if (!ok) {
			println(ldb.errstring());
			assert(ok);
		}
	}

	println("Testing ldb.search for (&(cn=ldaptestuser)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestuser)(objectClass=user))");
	if (res.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectClass=user))");
		assert(res.length == 1);
	}

	assert(res[0].dn == "cn=ldaptestuser,cn=users," + base_dn);
	assert(res[0].cn == "ldaptestuser");
	assert(res[0].name == "ldaptestuser");
	assert(res[0].objectClass[0] == "top");
	assert(res[0].objectClass[1] == "person");
	assert(res[0].objectClass[2] == "organizationalPerson");
	assert(res[0].objectClass[3] == "user");
	assert(res[0].objectGUID != undefined);
	assert(res[0].whenCreated != undefined);
	assert(res[0].objectCategory == "cn=Person,cn=Schema,cn=Configuration," + base_dn);
	assert(res[0].sAMAccountType == 805306368);
//	assert(res[0].userAccountControl == 546);

	println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))");
	var res2 = ldb.search("(&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))");
	if (res2.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))");
		assert(res2.length == 1);
	}

	assert(res[0].dn == res2[0].dn);

	println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon))");
	var res3 = ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))");
	if (res3.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon))");
		assert(res3.length == 1);
	}

	assert(res[0].dn == res3[0].dn);

	if (gc_ldb != undefined) {
		println("Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog");
		var res3gc = gc_ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))");
		if (res3gc.length != 1) {
			println("Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog");
			assert(res3gc.length == 1);
		}
	
		assert(res[0].dn == res3gc[0].dn);
	}

	ok = ldb.del(res[0].dn);
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestcomputer)(objectClass=user))");
	if (res.length != 1) {
		println("Could not find (&(cn=ldaptestuser)(objectClass=user))");
		assert(res.length == 1);
	}

	assert(res[0].dn == "cn=ldaptestcomputer,cn=computers," + base_dn);
	assert(res[0].cn == "ldaptestcomputer");
	assert(res[0].name == "ldaptestcomputer");
	assert(res[0].objectClass[0] == "top");
	assert(res[0].objectClass[1] == "person");
	assert(res[0].objectClass[2] == "organizationalPerson");
	assert(res[0].objectClass[3] == "user");
	assert(res[0].objectClass[4] == "computer");
	assert(res[0].objectGUID != undefined);
	assert(res[0].whenCreated != undefined);
	assert(res[0].objectCategory == "cn=Computer,cn=Schema,cn=Configuration," + base_dn);
//	assert(res[0].sAMAccountType == 805306368);
//	assert(res[0].userAccountControl == 546);

	println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
	var res2 = ldb.search("(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
	if (res2.length != 1) {
		println("Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
		assert(res2.length == 1);
	}

	assert(res[0].dn == res2[0].dn);

	if (gc_ldb != undefined) {
		println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + ")) in Global Catlog");
		var res2gc = gc_ldb.search("(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))");
		if (res2gc.length != 1) {
			println("Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + ")) in Global Catlog");
			assert(res2gc.length == 1);
		}

		assert(res[0].dn == res2gc[0].dn);
	}

	println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER))");
	var res3 = ldb.search("(&(cn=ldaptestcomputer)(objectCategory=compuTER))");
	if (res3.length != 1) {
		println("Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER))");
		assert(res3.length == 1);
	}

	assert(res[0].dn == res3[0].dn);

	if (gc_ldb != undefined) {
		println("Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog");
		var res3gc = gc_ldb.search("(&(cn=ldaptestcomputer)(objectCategory=compuTER))");
		if (res3gc.length != 1) {
			println("Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog");
			assert(res3gc.length == 1);
		}

		assert(res[0].dn == res3gc[0].dn);
	}

	println("Testing ldb.search for (&(cn=ldaptestcomp*r)(objectCategory=compuTER))");
	var res4 = ldb.search("(&(cn=ldaptestcomp*r)(objectCategory=compuTER))");
	if (res4.length != 1) {
		println("Could not find (&(cn=ldaptestcomp*r)(objectCategory=compuTER))");
		assert(res4.length == 1);
	}

	assert(res[0].dn == res4[0].dn);

	println("Testing ldb.search for (&(cn=ldaptestcomput*)(objectCategory=compuTER))");
	var res5 = ldb.search("(&(cn=ldaptestcomput*)(objectCategory=compuTER))");
	if (res5.length != 1) {
		println("Could not find (&(cn=ldaptestcomput*)(objectCategory=compuTER))");
		assert(res5.length == 1);
	}

	assert(res[0].dn == res5[0].dn);

	println("Testing ldb.search for (&(cn=*daptestcomputer)(objectCategory=compuTER))");
	var res6 = ldb.search("(&(cn=*daptestcomputer)(objectCategory=compuTER))");
	if (res6.length != 1) {
		println("Could not find (&(cn=*daptestcomputer)(objectCategory=compuTER))");
		assert(res6.length == 1);
	}

	assert(res[0].dn == res6[0].dn);

	ok = ldb.del(res[0].dn);
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	println("Testing ldb.search for (&(cn=ldaptest2computer)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptest2computer)(objectClass=user))");
	if (res.length != 1) {
		println("Could not find (&(cn=ldaptest2computer)(objectClass=user))");
		assert(res.length == 1);
	}

	assert(res[0].dn == "cn=ldaptest2computer,cn=computers," + base_dn);
	assert(res[0].cn == "ldaptest2computer");
	assert(res[0].name == "ldaptest2computer");
	assert(res[0].objectClass[0] == "top");
	assert(res[0].objectClass[1] == "person");
	assert(res[0].objectClass[2] == "organizationalPerson");
	assert(res[0].objectClass[3] == "user");
	assert(res[0].objectClass[4] == "computer");
	assert(res[0].objectGUID != undefined);
	assert(res[0].whenCreated != undefined);
	assert(res[0].objectCategory == "cn=Computer,cn=Schema,cn=Configuration," + base_dn);
	assert(res[0].sAMAccountType == 805306369);
//	assert(res[0].userAccountControl == 4098);


	println("Testing ldb.search for (&(cn=ldaptestUSer2)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestUSer2)(objectClass=user))");
	if (res.length != 1) {
		println("Could not find (&(cn=ldaptestUSer2)(objectClass=user))");
		assert(res.length == 1);
	}

	assert(res[0].dn == "cn=ldaptestuser2,cn=users," + base_dn);
	assert(res[0].cn == "ldaptestuser2");
	assert(res[0].name == "ldaptestuser2");
	assert(res[0].objectClass[0] == "top");
	assert(res[0].objectClass[1] == "person");
	assert(res[0].objectClass[2] == "organizationalPerson");
	assert(res[0].objectClass[3] == "user");
	assert(res[0].objectGUID != undefined);
	assert(res[0].whenCreated != undefined);

	ok = ldb.del(res[0].dn);
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	println("Testing ldb.search for (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");

	if (res.length != 1) {
		println("Could not find (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");
		assert(res.length == 1);
	}

	assert(res[0].dn == "cn=ldaptestutf8user èùéìòà,cn=users," + base_dn);
	assert(res[0].cn == "ldaptestutf8user èùéìòà");
	assert(res[0].name == "ldaptestutf8user èùéìòà");
	assert(res[0].objectClass[0] == "top");
	assert(res[0].objectClass[1] == "person");
	assert(res[0].objectClass[2] == "organizationalPerson");
	assert(res[0].objectClass[3] == "user");
	assert(res[0].objectGUID != undefined);
	assert(res[0].whenCreated != undefined);

	ok = ldb.del(res[0].dn);
	if (!ok) {
		println(ldb.errstring());
		assert(ok);
	}

	println("Testing ldb.search for (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))");
	var res = ldb.search("(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))");

	if (res.length != 1) {
		println("Could not find (expect space collapse, win2k3 fails) (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))");
	} else {
		assert(res[0].dn == "cn=ldaptestutf8user2 èùéìòà,cn=users," + base_dn);
		assert(res[0].cn == "ldaptestutf8user2 èùéìòà");
	}

	println("Testing for highestCommittedUSN");
	var attrs = new Array("highestCommittedUSN");
	var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
	assert(res.length == 1);
	assert(res[0].highestCommittedUSN != undefined);
	assert(res[0].highestCommittedUSN != 0);

	println("Testing that we can't get at the configuration DN from the main search base");
	var attrs = new Array("cn");
	var res = ldb.search("objectClass=crossRef", base_dn, ldb.SCOPE_SUBTREE, attrs);
	assert (res.length == 0);

	if (gc_ldb != undefined) {
		println("Testing that we do find configuration elements in the global catlog");
		var attrs = new Array("cn");
		var res = gc_ldb.search("objectClass=crossRef", base_dn, ldb.SCOPE_SUBTREE, attrs);
		assert (res.length > 0);
	
		println("Testing that we do find configuration elements and user elements at the same time");
		var attrs = new Array("cn");
		var res = gc_ldb.search("(|(objectClass=crossRef)(objectClass=person))", base_dn, ldb.SCOPE_SUBTREE, attrs);
		assert (res.length > 0);

		println("Testing that we do find configuration elements in the global catlog, with the configuration basedn");
		var attrs = new Array("cn");
		var res = gc_ldb.search("objectClass=crossRef", configuration_dn, ldb.SCOPE_SUBTREE, attrs);
		assert (res.length > 0);
	}

	println("Testing that we can get at the configuration DN on the main LDAP port");
	var attrs = new Array("cn");
	var res = ldb.search("objectClass=crossRef", configuration_dn, ldb.SCOPE_SUBTREE, attrs);
	assert (res.length > 0);

}

function find_basedn(ldb)
{
    var attrs = new Array("defaultNamingContext");
    var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
    assert(res.length == 1);
    return res[0].defaultNamingContext;
}

function find_configurationdn(ldb)
{
    var attrs = new Array("configurationNamingContext");
    var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
    assert(res.length == 1);
    return res[0].configurationNamingContext;
}

/* use command line creds if available */
ldb.credentials = options.get_credentials();
gc_ldb.credentials = options.get_credentials();

var ok = ldb.connect("ldap://" + host);
var base_dn = find_basedn(ldb);
var configuration_dn = find_configurationdn(ldb);

printf("baseDN: %s\n", base_dn);

var ok = gc_ldb.connect("ldap://" + host + ":3268");
if (!ok) {
	gc_ldb = undefined;
}

basic_tests(ldb, gc_ldb, base_dn, configuration_dn)

return 0;
