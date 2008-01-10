#!/usr/bin/python
# -*- coding: utf-8 -*-
# This is a port of the original in testprogs/ejs/ldap.js

import getopt
import optparse
import sys

# Add path to the library for in-tree use
sys.path.append("scripting/python")
import samba.getopt as options

from auth import system_session
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE
from samba import Ldb
import param

parser = optparse.OptionParser("ldap [options] <host>")
parser.add_option_group(options.SambaOptions(parser))
parser.add_option_group(options.VersionOptions(parser))
# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
creds = credopts.get_credentials()
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = param.LoadParm()
if opts.configfile:
    lp.load(opts.configfile)

def assertEquals(a1, a2):
    assert a1 == a2

def basic_tests(ldb, gc_ldb, base_dn, configuration_dn, schema_dn):
    print "Running basic tests"

    ldb.delete("cn=ldaptestuser,cn=users," + base_dn)
    ldb.delete("cn=ldaptestgroup,cn=users," + base_dn)

    print "Testing group add with invalid member"
    try:
        ldb.add({
        "dn": "cn=ldaptestgroup,cn=uSers," + base_dn,
        "objectclass": "group",
        "member": "cn=ldaptestuser,cn=useRs," + base_dn})
    except LdbError, (num, _):
        assert error == 32 # LDAP_NO_SUCH_OBJECT
    else:
        assert False

    print "Testing user add"
    try:
        ldb.add({
        "dn": "cn=ldaptestuser,cn=uSers," + base_dn,
        "objectclass": ["user", "person"],
        "cN": "LDAPtestUSER",
        "givenname": "ldap",
        "sn": "testy"})
    except LdbError:
        ldb.delete("cn=ldaptestuser,cn=users," + base_dn)
        ldb.add({
            "dn": "cn=ldaptestuser,cn=uSers," + base_dn,
            "objectclass": ["user", "person"],
            "cN": "LDAPtestUSER",
            "givenname": "ldap",
            "sn": "testy"})

    ldb.add({
        "dn": "cn=ldaptestgroup,cn=uSers," + base_dn,
        "objectclass": "group",
        "member": "cn=ldaptestuser,cn=useRs," + base_dn})

    try:
        ldb.add({
        "dn": "cn=ldaptestcomputer,cn=computers," + base_dn,
        "objectclass": "computer",
        "cN": "LDAPtestCOMPUTER"})
    except LdbError:
        ldb.delete("cn=ldaptestcomputer,cn=computers," + base_dn)
        ldb.add({
            "dn": "cn=ldaptestcomputer,cn=computers," + base_dn,
            "objectClass": "computer",
            "cn": "LDAPtestCOMPUTER"})

    try:
        ldb.add({"dn": "cn=ldaptest2computer,cn=computers," + base_dn,
        "objectClass": "computer",
        "cn": "LDAPtest2COMPUTER",
        "userAccountControl": "4096",
        "displayname": "ldap testy"})
    except LdbError:
        ldb.delete("cn=ldaptest2computer,cn=computers," + base_dn)
        ldb.add({
            "dn": "cn=ldaptest2computer,cn=computers," + base_dn,
            "objectClass": "computer",
            "cn": "LDAPtest2COMPUTER",
            "userAccountControl": "4096",
            "displayname": "ldap testy"})

    print "Testing attribute or value exists behaviour"
    try:
        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + base_dn + """
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: cifs/ldaptest2computer
""")
    except LdbError, (num, msg):
        #LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS
        assert num == 20, "Expected error LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS, got : %s" % msg

        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + base_dn + """
changetype: modify
replace: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
servicePrincipalName: cifs/ldaptest2computer
""")
        try:
            ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + base_dn + """
changetype: modify
add: servicePrincipalName
servicePrincipalName: host/ldaptest2computer
""")
        except LdbError, (num, msg):
            assert num == 20, "Expected error LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS, got :" + msg
        
        print "Testing ranged results"
        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + base_dn + """
changetype: modify
replace: servicePrincipalName
""")
        
        ldb.modify_ldif("""
dn: cn=ldaptest2computer,cn=computers,""" + base_dn + """
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
""")

        res = ldb.search(base_dn, expression="(cn=ldaptest2computer))", scope=ldb.SCOPE_SUBTREE, 
                         attrs=["servicePrincipalName;range=0-*"])
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
#        print res[0]["servicePrincipalName;range=0-*"].length
        assertEquals(res[0]["servicePrincipalName;range=0-*"].length, 30)

        attrs = ["servicePrincipalName;range=0-19"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
#        print res[0]["servicePrincipalName;range=0-19"].length
        assertEquals(res[0]["servicePrincipalName;range=0-19"].length, 20)

        attrs = ["servicePrincipalName;range=0-30"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
        assertEquals(res[0]["servicePrincipalName;range=0-*"].length, 30)

        attrs = ["servicePrincipalName;range=0-40"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
        assertEquals(res[0]["servicePrincipalName;range=0-*"].length, 30)

        attrs = ["servicePrincipalName;range=30-40"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
        assertEquals(res[0]["servicePrincipalName;range=30-*"].length, 0)

        attrs = ["servicePrincipalName;range=10-40"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
        assertEquals(res[0]["servicePrincipalName;range=10-*"].length, 20)
#        pos_11 = res[0]["servicePrincipalName;range=10-*"][18]

        attrs = ["servicePrincipalName;range=11-40"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
        assertEquals(res[0]["servicePrincipalName;range=11-*"].length, 19)
#        print res[0]["servicePrincipalName;range=11-*"][18]
#        print pos_11
#        assertEquals((res[0]["servicePrincipalName;range=11-*"][18]), pos_11)

        attrs = ["servicePrincipalName;range=11-15"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
        assertEquals(res[0]["servicePrincipalName;range=11-15"].length, 5)
#        assertEquals(res[0]["servicePrincipalName;range=11-15"][4], pos_11)

        attrs = ["servicePrincipalName"]
        res = ldb.search(base_dn, "(cn=ldaptest2computer))", SCOPE_SUBTREE, attrs)
        assert len(res) == 1, "Could not find (cn=ldaptest2computer)"
#        print res[0]["servicePrincipalName"][18]
#        print pos_11
        assertEquals(res[0]["servicePrincipalName"].length, 30)
#        assertEquals(res[0]["servicePrincipalName"][18], pos_11)

    try:
        ldb.add({
        "dn": "cn=ldaptestuser2,cn=useRs," + base_dn,
        "objectClass": ["person", "user"],
        "cn": "LDAPtestUSER2",
        "givenname": "testy",
        "sn": "ldap user2"})
    except LdbError:
        ldb.delete("cn=ldaptestuser2,cn=users," + base_dn)
        ldb.add({
                "dn": "cn=ldaptestuser2,cn=useRs," + base_dn,
                "objectClass": ["person", "user"],
                "cn": "LDAPtestUSER2",
                "givenname": "testy",
                "sn": "ldap user2"})

    print "Testing Ambigious Name Resolution"
#   Testing ldb.search for (&(anr=ldap testy)(objectClass=user))
    res = ldb.search(expression="(&(anr=ldap testy)(objectClass=user))")
    assert len(res) == 3, "Could not find (&(anr=ldap testy)(objectClass=user))"

#   Testing ldb.search for (&(anr=testy ldap)(objectClass=user))
    res = ldb.search(expression="(&(anr=testy ldap)(objectClass=user))")
    assert len(res) == 2, "Found only %d for (&(anr=testy ldap)(objectClass=user))" % len(res)

#   Testing ldb.search for (&(anr=ldap)(objectClass=user))
    res = ldb.search(expression="(&(anr=ldap)(objectClass=user))")
    assert len(res) == 4, "Found only %d for (&(anr=ldap)(objectClass=user))" % len(res)

#   Testing ldb.search for (&(anr==ldap)(objectClass=user))
    res = ldb.search(expression="(&(anr==ldap)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(anr==ldap)(objectClass=user)). Found only %d for (&(anr=ldap)(objectClass=user))" % len(res)

    assertEquals(res[0].dn, ("CN=ldaptestuser,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser")
    assertEquals(res[0].name, "ldaptestuser")

#   Testing ldb.search for (&(anr=testy)(objectClass=user))
    res = ldb.search(expression="(&(anr=testy)(objectClass=user))")
    assert len(res) == 2, "Found only %d for (&(anr=testy)(objectClass=user))" % len(res)

#   Testing ldb.search for (&(anr=ldap testy)(objectClass=user))
    res = ldb.search(expression="(&(anr=testy ldap)(objectClass=user))")
    assert len(res) == 2, "Found only %d for (&(anr=ldap testy)(objectClass=user))" % len(res)

#   Testing ldb.search for (&(anr==ldap testy)(objectClass=user))
    res = ldb.search(expression="(&(anr==testy ldap)(objectClass=user))")
    assert len(res) == 1, "Found only %d for (&(anr==ldap testy)(objectClass=user))" % len(res)

    assertEquals(res[0].dn, ("CN=ldaptestuser,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser")
    assertEquals(res[0].name, "ldaptestuser")

# Testing ldb.search for (&(anr==testy ldap)(objectClass=user))
    res = ldb.search(expression="(&(anr==testy ldap)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(anr==testy ldap)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestuser,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser")
    assertEquals(res[0].name, "ldaptestuser")

    # Testing ldb.search for (&(anr=testy ldap user)(objectClass=user))
    res = ldb.search(expression="(&(anr=testy ldap user)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(anr=testy ldap user)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestuser2,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser2")
    assertEquals(res[0].name, "ldaptestuser2")

    # Testing ldb.search for (&(anr==testy ldap user2)(objectClass=user))
    res = ldb.search(expression="(&(anr==testy ldap user2)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(anr==testy ldap user2)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestuser2,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser2")
    assertEquals(res[0].name, "ldaptestuser2")

    # Testing ldb.search for (&(anr==ldap user2)(objectClass=user))
    res = ldb.search(expression="(&(anr==ldap user2)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(anr==ldap user2)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestuser2,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser2")
    assertEquals(res[0].name, "ldaptestuser2")

    # Testing ldb.search for (&(anr==not ldap user2)(objectClass=user))
    res = ldb.search(expression="(&(anr==not ldap user2)(objectClass=user))")
    assert len(res) == 0, "Must not find (&(anr==not ldap user2)(objectClass=user))"

    # Testing ldb.search for (&(anr=not ldap user2)(objectClass=user))
    res = ldb.search(expression="(&(anr=not ldap user2)(objectClass=user))")
    assert len(res) == 0, "Must not find (&(anr=not ldap user2)(objectClass=user))"

    print "Testing Group Modifies"
    ldb.modify_ldif("""
dn: cn=ldaptestgroup,cn=users,""" + base_dn + """
changetype: modify
add: member
member: cn=ldaptestuser2,cn=users,""" + base_dn + """
member: cn=ldaptestcomputer,cn=computers,""" + base_dn + """
""")

    ldb.delete("cn=ldaptestuser3,cn=users," + base_dn)

    print "Testing adding non-existent user to a group"
    try:
        ldb.modify_ldif("""
dn: cn=ldaptestgroup,cn=users,""" + base_dn + """
changetype: modify
add: member
member: cn=ldaptestuser3,cn=users,""" + base_dn + """
""")
    except LdbError, (num, _):
        assert num == 32
    else:
        assert False

    print "Testing Renames"

    ldb.rename("cn=ldaptestuser2,cn=users," + base_dn, "cn=ldaptestuser3,cn=users," + base_dn)

    ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser3,cn=users," + base_dn)

    ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestUSER3,cn=users," + base_dn)

    print "Testing ldb.search for (&(cn=ldaptestuser3)(objectClass=user))"
    res = ldb.search(expression="(&(cn=ldaptestuser3)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptestuser3)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestUSER3,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestUSER3")
    assertEquals(res[0].name, "ldaptestUSER3")

# This is a Samba special, and does not exist in real AD
#    print "Testing ldb.search for (dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")"
#    res = ldb.search("(dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")")
#    if (res.error != 0 || len(res) != 1) {
#        print "Could not find (dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")"
#        assertEquals(len(res), 1)
#    }
#    assertEquals(res[0].dn, ("CN=ldaptestUSER3,CN=Users," + base_dn))
#    assertEquals(res[0].cn, "ldaptestUSER3")
#    assertEquals(res[0].name, "ldaptestUSER3")

    print "Testing ldb.search for (distinguishedName=CN=ldaptestUSER3,CN=Users," + base_dn + ")"
    res = ldb.search(expression="(distinguishedName=CN=ldaptestUSER3,CN=Users," + base_dn + ")")
    assert len(res) == 1, "Could not find (dn=CN=ldaptestUSER3,CN=Users," + base_dn + ")"
    assertEquals(res[0].dn, ("CN=ldaptestUSER3,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestUSER3")
    assertEquals(res[0].name, "ldaptestUSER3")

    # ensure we cannot add it again
    try:
        ldb.add({"dn": "cn=ldaptestuser3,cn=userS," + base_dn,
                  "objectClass": ["person", "user"],
                  "cn": "LDAPtestUSER3"})
    except LdbError, (num, _):
        assert num == 68 #LDB_ERR_ENTRY_ALREADY_EXISTS
    else:
        assert False

    # rename back
    ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser2,cn=users," + base_dn)

    # ensure we cannnot rename it twice
    ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser2,cn=users," + base_dn)
#LDB_ERR_NO_SUCH_OBJECT
    assertEquals(ok.error, 32)

    # ensure can now use that name
    ok = ldb.add({"dn": "cn=ldaptestuser3,cn=users," + base_dn,
                  "objectClass": ["person", "user"],
                  "cn": "LDAPtestUSER3"})
    
    # ensure we now cannnot rename
    try:
        ldb.rename("cn=ldaptestuser2,cn=users," + base_dn, "cn=ldaptestuser3,cn=users," + base_dn)
    except LdbError, (num, _):
        assert num == 68 #LDB_ERR_ENTRY_ALREADY_EXISTS
    else:
        assert False
    assertEquals(ok.error, 68)
    try:
        ok = ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser3,cn=configuration," + base_dn)
    except LdbError, (num, _):
        assert num in (71, 64)
    else:
        assert False

    ldb.rename("cn=ldaptestuser3,cn=users," + base_dn, "cn=ldaptestuser5,cn=users," + base_dn)

    ldb.delete("cn=ldaptestuser5,cn=users," + base_dn)

    ldb.delete("cn=ldaptestgroup2,cn=users," + base_dn)

    ldb.rename("cn=ldaptestgroup,cn=users," + base_dn, "cn=ldaptestgroup2,cn=users," + base_dn)

    print "Testing subtree Renames"

    ldb.add({"dn": "cn=ldaptestcontainer," + base_dn, "objectClass": "container"})
    
    try:
        ldb.add({"dn": "CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn, 
             "objectClass": ["person", "user"],
             "cn": "LDAPtestUSER4"})
    except LdbError:
        ldb.delete("cn=ldaptestuser4,cn=ldaptestcontainer," + base_dn)
        ldb.add({"dn": "CN=ldaptestuser4,CN=ldaptestcontainer," + base_dn,
                      "objectClass": ["person", "user"],
                      "cn": "LDAPtestUSER4"})

    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
add: member
member: cn=ldaptestuser4,cn=ldaptestcontainer,""" + base_dn + """
""")
    
    print "Testing ldb.rename of cn=ldaptestcontainer," + base_dn + " to cn=ldaptestcontainer2," + base_dn
    ldb.rename("CN=ldaptestcontainer," + base_dn, "CN=ldaptestcontainer2," + base_dn)

    print "Testing ldb.search for (&(cn=ldaptestuser4)(objectClass=user))"
    res = ldb.search(expression="(&(cn=ldaptestuser4)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptestuser4)(objectClass=user))"

    print "Testing subtree ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in (just renamed from) cn=ldaptestcontainer," + base_dn
    try:
        res = ldb.search("cn=ldaptestcontainer," + base_dn, expression="(&(cn=ldaptestuser4)(objectClass=user))", scope=SCOPE_SUBTREE)
    except LdbError, (num, _):
        assert num == 32
    else:
        assert False

    print "Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in (just renamed from) cn=ldaptestcontainer," + base_dn
    try:
        res = ldb.search("cn=ldaptestcontainer," + base_dn, expression="(&(cn=ldaptestuser4)(objectClass=user))", scope=SCOPE_ONELEVEL)
    except LdbError, (num, _):
        assert num == 32
    else:
        assert False

    print "Testing ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in renamed container"
    res = ldb.search("cn=ldaptestcontainer2," + base_dn, expression="(&(cn=ldaptestuser4)(objectClass=user))", scope=SCOPE_SUBTREE)
    assert len(res) == 1, "Could not find (&(cn=ldaptestuser4)(objectClass=user)) under cn=ldaptestcontainer2," + base_dn

    assertEquals(res[0].dn, ("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn))
    assertEquals(strupper(res[0].memberOf[0]), strupper(("CN=ldaptestgroup2,CN=Users," + base_dn)))

    print "Testing ldb.search for (&(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn + ")(objectclass=group)) to check subtree renames and linked attributes"
    res = ldb.search(base_dn, "(&(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn + ")(objectclass=group))", SCOPE_SUBTREE)
    assert len(res) == 1, "Could not find (&(member=CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn + ")(objectclass=group)), perhaps linked attributes are not conistant with subtree renames?"

    print "Testing ldb.rename (into itself) of cn=ldaptestcontainer2," + base_dn + " to cn=ldaptestcontainer,cn=ldaptestcontainer2," + base_dn
    try:
        ok = ldb.rename("cn=ldaptestcontainer2," + base_dn, "cn=ldaptestcontainer,cn=ldaptestcontainer2," + base_dn)
    except LdbError, (num, _):
        assert num != 53 # LDAP_UNWILLING_TO_PERFORM
    else:
        assert False

    print "Testing ldb.rename (into non-existent container) of cn=ldaptestcontainer2," + base_dn + " to cn=ldaptestcontainer,cn=ldaptestcontainer3," + base_dn
    try:
        ldb.rename("cn=ldaptestcontainer2," + base_dn, "cn=ldaptestcontainer,cn=ldaptestcontainer3," + base_dn)
    except LdbError, (num, _):
        assert num in (53, 80)
    else:
        assert False

    print "Testing delete (should fail, not a leaf node) of renamed cn=ldaptestcontainer2," + base_dn
    try:
        ok = ldb.delete("cn=ldaptestcontainer2," + base_dn)
    except LdbError, (num, _):
        assert num == 66
    else:
        assert False

    print "Testing base ldb.search for CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn
    res = ldb.search(expression="(objectclass=*)", base=("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn), scope=SCOPE_BASE)
    assert len(res) == 1
    res = ldb.search(expression="(cn=ldaptestuser40)", base=("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn), scope=SCOPE_BASE)
    assert len(res) == 0

    print "Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in cn=ldaptestcontainer2," + base_dn
    res = ldb.search(expression="(&(cn=ldaptestuser4)(objectClass=user))", base="cn=ldaptestcontainer2," + base_dn, scope=SCOPE_ONELEVEL)
    assert len(res) == 0

    print "Testing one-level ldb.search for (&(cn=ldaptestuser4)(objectClass=user)) in cn=ldaptestcontainer2," + base_dn
    res = ldb.search(expression="(&(cn=ldaptestuser4)(objectClass=user))", base="cn=ldaptestcontainer2," + base_dn, scope=SCOPE_SUBTREE)
    assert len(res) == 0

    print "Testing delete of subtree renamed "+("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn)
    ldb.delete(("CN=ldaptestuser4,CN=ldaptestcontainer2," + base_dn))
    print "Testing delete of renamed cn=ldaptestcontainer2," + base_dn
    ldb.delete("cn=ldaptestcontainer2," + base_dn)
    
    try:
        ldb.add({"dn": "cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn, "objectClass": "user"})
    except LdbError, (num, _):
        ldb.delete("cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn)
        ldb.add({"dn": "cn=ldaptestutf8user èùéìòà ,cn=users," + base_dn, "objectClass": "user"})

    try:
        ldb.add({"dn": "cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn, "objectClass": "user"})
    except LdbError, (num, _):
        ldb.delete("cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn)
        ldb.add({"dn": "cn=ldaptestutf8user2  èùéìòà ,cn=users," + base_dn,
                  "objectClass": "user"})

    print "Testing ldb.search for (&(cn=ldaptestuser)(objectClass=user))"
    res = ldb.search("(&(cn=ldaptestuser)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptestuser)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestuser,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser")
    assertEquals(res[0].name, "ldaptestuser")
    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "person")
    assertEquals(res[0].objectClass[2], "organizationalPerson")
    assertEquals(res[0].objectClass[3], "user")
    assert("objectGUID" not in res[0])
    assert("whenCreated" not in res[0])
    assertEquals(res[0].objectCategory, ("CN=Person,CN=Schema,CN=Configuration," + base_dn))
    assertEquals(res[0].sAMAccountType, 805306368)
#    assertEquals(res[0].userAccountControl, 546)
    assertEquals(res[0].memberOf[0], ("CN=ldaptestgroup2,CN=Users," + base_dn))
    assertEquals(res[0].memberOf.length, 1)
 
    print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))"
    res2 = ldb.search("(&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))")
    assert len(res2) == 1, "Could not find (&(cn=ldaptestuser)(objectCategory=cn=person,cn=schema,cn=configuration," + base_dn + "))"

    assertEquals(res[0].dn, res2.msgs[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon))"
    res3 = ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))")
    assert len(res3) == 1, "Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)): matched " + len(res3)

    assertEquals(res[0].dn, res3.msgs[0].dn)

    if gc_ldb is not None:
        print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog"
        res3gc = gc_ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))")
        assert len(res3gc) == 1
    
        assertEquals(res[0].dn, res3gc.msgs[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestuser)(objectCategory=PerSon)) in with 'phantom root' control"
    attrs = ["cn"]
    controls = ["search_options:1:2"]
    res3control = gc_ldb.search("(&(cn=ldaptestuser)(objectCategory=PerSon))", base_dn, ldb.SCOPE_SUBTREE, attrs, controls)
    assert len(res3control) == 1, "Could not find (&(cn=ldaptestuser)(objectCategory=PerSon)) in Global Catalog"
    
    assertEquals(res[0].dn, res3control.msgs[0].dn)

    ldb.delete(res[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectClass=user))"
    res = ldb.search("(&(cn=ldaptestcomputer)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptestuser)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestcomputer,CN=Computers," + base_dn))
    assertEquals(res[0].cn, "ldaptestcomputer")
    assertEquals(res[0].name, "ldaptestcomputer")
    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "person")
    assertEquals(res[0].objectClass[2], "organizationalPerson")
    assertEquals(res[0].objectClass[3], "user")
    assertEquals(res[0].objectClass[4], "computer")
    assert("objectGUID" not in res[0])
    assert("whenCreated" not in res[0])
    assertEquals(res[0].objectCategory, ("CN=Computer,CN=Schema,CN=Configuration," + base_dn))
    assertEquals(res[0].primaryGroupID, 513)
#    assertEquals(res[0].sAMAccountType, 805306368)
#    assertEquals(res[0].userAccountControl, 546)
    assertEquals(res[0].memberOf[0], ("CN=ldaptestgroup2,CN=Users," + base_dn))
    assertEquals(res[0].memberOf.length, 1)

    print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))"
    res2 = ldb.search("(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))")
    assert len(res2) == 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))"

    assertEquals(res[0].dn, res2.msgs[0].dn)

    if gc_ldb is not None:
        print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + ")) in Global Catlog"
        res2gc = gc_ldb.search("(&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + "))")
        assert len(res2gc) == 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=cn=computer,cn=schema,cn=configuration," + base_dn + ")) in Global Catlog"

        assertEquals(res[0].dn, res2gc.msgs[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER))"
    res3 = ldb.search("(&(cn=ldaptestcomputer)(objectCategory=compuTER))")
    assert len(res3) == 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER))"

    assertEquals(res[0].dn, res3.msgs[0].dn)

    if gc_ldb is not None:
        print "Testing ldb.search for (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog"
        res3gc = gc_ldb.search("(&(cn=ldaptestcomputer)(objectCategory=compuTER))")
        assert len(res3gc) == 1, "Could not find (&(cn=ldaptestcomputer)(objectCategory=compuTER)) in Global Catalog"

        assertEquals(res[0].dn, res3gc.msgs[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestcomp*r)(objectCategory=compuTER))"
    res4 = ldb.search("(&(cn=ldaptestcomp*r)(objectCategory=compuTER))")
    assert len(res4) == 1, "Could not find (&(cn=ldaptestcomp*r)(objectCategory=compuTER))"

    assertEquals(res[0].dn, res4.msgs[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestcomput*)(objectCategory=compuTER))"
    res5 = ldb.search("(&(cn=ldaptestcomput*)(objectCategory=compuTER))")
    assert len(res5) == 1, "Could not find (&(cn=ldaptestcomput*)(objectCategory=compuTER))"

    assertEquals(res[0].dn, res5.msgs[0].dn)

    print "Testing ldb.search for (&(cn=*daptestcomputer)(objectCategory=compuTER))"
    res6 = ldb.search("(&(cn=*daptestcomputer)(objectCategory=compuTER))")
    assert len(res6) == 1, "Could not find (&(cn=*daptestcomputer)(objectCategory=compuTER))"

    assertEquals(res[0].dn, res6.msgs[0].dn)

    ldb.delete(res[0].dn)

    print "Testing ldb.search for (&(cn=ldaptest2computer)(objectClass=user))"
    res = ldb.search("(&(cn=ldaptest2computer)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptest2computer)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptest2computer,CN=Computers," + base_dn))
    assertEquals(res[0].cn, "ldaptest2computer")
    assertEquals(res[0].name, "ldaptest2computer")
    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "person")
    assertEquals(res[0].objectClass[2], "organizationalPerson")
    assertEquals(res[0].objectClass[3], "user")
    assertEquals(res[0].objectClass[4], "computer")
    assert("objectGUID" not in res[0])
    assert("whenCreated" not in res[0])
    assertEquals(res[0]["objectCategory"], "cn=Computer,cn=Schema,cn=Configuration," + base_dn)
    assertEquals(int(res[0]["sAMAccountType"]), 805306369)
#    assertEquals(res[0].userAccountControl, 4098)

    ldb.delete(res[0].dn)

    attrs = ["cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "memberOf"]
    print "Testing ldb.search for (&(cn=ldaptestUSer2)(objectClass=user))"
    res = ldb.search(base_dn, "(&(cn=ldaptestUSer2)(objectClass=user))", scope=SCOPE_SUBTREE, attrs=attrs)
    assert len(res) == 1, "Could not find (&(cn=ldaptestUSer2)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestuser2,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestuser2")
    assertEquals(res[0].name, "ldaptestuser2")
    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "person")
    assertEquals(res[0].objectClass[2], "organizationalPerson")
    assertEquals(res[0].objectClass[3], "user")
    assert("objectGUID" not in res[0])
    assert("whenCreated" not in res[0])
    assert("nTSecurityDescriptor" not in res[0])
    assertEquals(res[0].memberOf[0], ("CN=ldaptestgroup2,CN=Users," + base_dn))

    attrs = ["cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "member"]
    print "Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group))"
    res = ldb.search(base_dn, "(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs)
    assert len(res) == 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group))"

    assertEquals(res[0].dn, ("CN=ldaptestgroup2,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestgroup2")
    assertEquals(res[0].name, "ldaptestgroup2")
    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "group")
    assert("objectGuid" not in res[0])
    assert("whenCreated" not in res[0])
    assert("nTSecurityDescriptor" not in res[0])
    assertEquals(res[0].member[0], ("CN=ldaptestuser2,CN=Users," + base_dn))
    assertEquals(len(res[0].member), 1)

    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
replace: member
member: CN=ldaptestuser2,CN=Users,""" + base_dn + """
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + base_dn + """
""")
    
    print "Testing Linked attribute behaviours"
    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
delete: member
""")

    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
add: member
member: CN=ldaptestuser2,CN=Users,""" + base_dn + """
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + base_dn + """
""")
    
    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
replace: member
""")
    
    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
add: member
member: CN=ldaptestuser2,CN=Users,""" + base_dn + """
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + base_dn + """
""")
    
    ldb.modify_ldif("""
dn: cn=ldaptestgroup2,cn=users,""" + base_dn + """
changetype: modify
delete: member
member: CN=ldaptestutf8user èùéìòà,CN=Users,""" + base_dn + """
""")
    
    res = ldb.search(base_dn, "(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs)
    assert len(res) != 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group))"

    assertEquals(res[0].dn, ("CN=ldaptestgroup2,CN=Users," + base_dn))
    assertEquals(res[0].member[0], ("CN=ldaptestuser2,CN=Users," + base_dn))
    assertEquals(res[0].member.length, 1)

    ldb.delete(("CN=ldaptestuser2,CN=Users," + base_dn))

    attrs = ["cn", "name", "objectClass", "objectGUID", "whenCreated", "nTSecurityDescriptor", "member"]
    print "Testing ldb.search for (&(cn=ldaptestgroup2)(objectClass=group)) to check linked delete"
    res = ldb.search(base_dn, "(&(cn=ldaptestgroup2)(objectClass=group))", scope=SCOPE_SUBTREE, attrs=attrs)
    assert len(res) != 1, "Could not find (&(cn=ldaptestgroup2)(objectClass=group)) to check linked delete"

    assertEquals(res[0]["dn"], ("CN=ldaptestgroup2,CN=Users," + base_dn))
    assert("member" not in res[0])

    print "Testing ldb.search for (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))"
    res = ldb.search("(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))"

    assertEquals(res[0].dn, ("CN=ldaptestutf8user èùéìòà,CN=Users," + base_dn))
    assertEquals(res[0].cn, "ldaptestutf8user èùéìòà")
    assertEquals(res[0].name, "ldaptestutf8user èùéìòà")
    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "person")
    assertEquals(res[0].objectClass[2], "organizationalPerson")
    assertEquals(res[0].objectClass[3], "user")
    assert("objectGUID" not in res[0])
    assert("whenCreated" not in res[0])

    ldb.delete(res[0].dn)

    print "Testing ldb.search for (&(cn=ldaptestutf8user2*)(objectClass=user))"
    res = ldb.search("(&(cn=ldaptestutf8user2*)(objectClass=user))")
    assert len(res) == 1, "Could not find (&(cn=ldaptestutf8user2*)(objectClass=user))"

    ldb.delete(res[0].dn)

    ldb.delete(("CN=ldaptestgroup2,CN=Users," + base_dn))

    print "Testing ldb.search for (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))"
    res = ldb.search(expression="(&(cn=ldaptestutf8user ÈÙÉÌÒÀ)(objectClass=user))")

    assert len(res) == 1, "Could not find (expect space collapse, win2k3 fails) (&(cn=ldaptestutf8user2 ÈÙÉÌÒÀ)(objectClass=user))"

    print "Testing that we can't get at the configuration DN from the main search base"
    res = ldb.search(base_dn, "objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
    assert len(res) == 0, "Got configuration DN " + res[0].dn + " which should not be able to be seen from main search base"
    assertEquals(len(res), 0)

    print "Testing that we can get at the configuration DN from the main search base on the LDAP port with the 'phantom root' search_options control"
    res = ldb.search(base_dn, "objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"], controls=["search_options:1:2"])
    assert(len(res) > 0)

    if gc_ldb is not None:
        print "Testing that we can get at the configuration DN from the main search base on the GC port with the search_options control == 0"
        attrs = ["cn"]
        controls = ["search_options:1:0"]
        res = gc_ldb.search("objectClass=crossRef", base_dn, gc_ldb.SCOPE_SUBTREE, attrs, controls)
        assert(len(res) > 0)

        print "Testing that we do find configuration elements in the global catlog"
        res = gc_ldb.search(base_dn, "objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
        assert (len(res) > 0)
    
        print "Testing that we do find configuration elements and user elements at the same time"
        res = gc_ldb.search(base_dn, "(|(objectClass=crossRef)(objectClass=person))", scope=SCOPE_SUBTREE, attrs=["cn"])
        assert (len(res) > 0)

        print "Testing that we do find configuration elements in the global catlog, with the configuration basedn"
        res = gc_ldb.search(configuration_dn, "objectClass=crossRef", scope=SCOPE_SUBTREE, attrs=["cn"])
        assert (len(res) > 0)

    print "Testing that we can get at the configuration DN on the main LDAP port"
    attrs = ["cn"]
    res = ldb.search("objectClass=crossRef", configuration_dn, ldb.SCOPE_SUBTREE, attrs)
    assert (len(res) > 0)

    print "Testing objectCategory canonacolisation"
    attrs = ["cn"]
    res = ldb.search("objectCategory=ntDsDSA", configuration_dn, ldb.SCOPE_SUBTREE, attrs)
    assert len(res) > 0, "Didn't find any records with objectCategory=ntDsDSA"
    assert(len(res) != 0)
    
    attrs = ["cn"]
    res = ldb.search("objectCategory=CN=ntDs-DSA," + schema_dn, configuration_dn, ldb.SCOPE_SUBTREE, attrs)
    assert len(res) > 0, "Didn't find any records with objectCategory=CN=ntDs-DSA," + schema_dn
    assert(len(res) != 0)
    
    print "Testing objectClass attribute order on "+ base_dn
    res = ldb.search(expression="objectClass=domain", base=base_dn, 
                     scope=SCOPE_BASE, attrs=["objectClass"])
    assertEquals(len(res), 1)

    assertEquals(res[0].objectClass[0], "top")
    assertEquals(res[0].objectClass[1], "domain")
    assertEquals(res[0].objectClass[2], "domainDNS")

#  check enumeration

    attrs = ["cn"]
    print "Testing ldb.search for objectCategory=person"
    res = ldb.search("objectCategory=person", base_dn, ldb.SCOPE_SUBTREE, attrs)
    assert(len(res) > 0)

    attrs = ["cn"]
    controls = ["domain_scope:1"]
    print "Testing ldb.search for objectCategory=person with domain scope control"
    res = ldb.search("objectCategory=person", base_dn, ldb.SCOPE_SUBTREE, attrs, controls)
    assert(len(res) > 0)
 
    attrs = ["cn"]
    print "Testing ldb.search for objectCategory=user"
    res = ldb.search("objectCategory=user", base_dn, ldb.SCOPE_SUBTREE, attrs)
    assert(len(res) > 0)

    attrs = ["cn"]
    controls = ["domain_scope:1"]
    print "Testing ldb.search for objectCategory=user with domain scope control"
    res = ldb.search("objectCategory=user", base_dn, ldb.SCOPE_SUBTREE, attrs, controls)
    assert(len(res) > 0)
    
    attrs = ["cn"]
    print "Testing ldb.search for objectCategory=group"
    res = ldb.search("objectCategory=group", base_dn, ldb.SCOPE_SUBTREE, attrs)
    assert(len(res) > 0)

    attrs = ["cn"]
    controls = ["domain_scope:1"]
    print "Testing ldb.search for objectCategory=group with domain scope control"
    res = ldb.search("objectCategory=group", base_dn, ldb.SCOPE_SUBTREE, attrs, controls)
    assert(len(res) > 0)

def basedn_tests(ldb, gc_ldb):
    print "Testing for all rootDSE attributes"
    res = ldb.search(scope=SCOPE_BASE, attrs=[])
    assertEquals(len(res), 1)

    print "Testing for highestCommittedUSN"
    
    res = ldb.search(scope=SCOPE_BASE, attrs=["highestCommittedUSN"])
    assertEquals(len(res), 1)
    assert(res[0]["highestCommittedUSN"] != 0)

    print "Testing for netlogon via LDAP"
    res = ldb.search(scope=SCOPE_BASE, attrs=["netlogon"])
    assertEquals(len(res), 0)

    print "Testing for netlogon and highestCommittedUSN via LDAP"
    res = ldb.search(scope=SCOPE_BASE, 
            attrs=["netlogon", "highestCommittedUSN"])
    assertEquals(len(res), 0)

def find_basedn(ldb):
    res = ldb.search(scope=SCOPE_BASE, attrs=["defaultNamingContext"])
    assertEquals(len(res), 1)
    return res[0]["defaultNamingContext"]

def find_configurationdn(ldb):
    res = ldb.search(scope=SCOPE_BASE, attrs=["configurationNamingContext"])
    assertEquals(len(res), 1)
    return res[0]["configurationNamingContext"]

def find_schemadn(ldb):
    res = ldb.search(scope=SCOPE_BASE, attrs=["schemaNamingContext"])
    assertEquals(len(res), 1)
    return res[0]["schemaNamingContext"]

if not "://" in host:
    host = "ldap://%s" % host

ldb = Ldb(host, credentials=creds, session_info=system_session(), 
          lp=lp)
base_dn = find_basedn(ldb)

configuration_dn = find_configurationdn(ldb)
schema_dn = find_schemadn(ldb)

print "baseDN: %s\n" % base_dn

gc_ldb = Ldb("%s:3268" % host, credentials=creds, 
             session_info=system_session(), lp=lp)

basic_tests(ldb, gc_ldb, base_dn, configuration_dn, schema_dn)
basedn_tests(ldb, gc_ldb)
