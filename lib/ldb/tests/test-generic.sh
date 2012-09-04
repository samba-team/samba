#!/bin/sh

if [ -z "$LDB_SPECIALS" ]; then
    LDB_SPECIALS=1
    export LDB_SPECIALS
fi

echo "LDB_URL: $LDB_URL"

echo "Adding base elements"
$VALGRIND ldbadd $LDBDIR/tests/test.ldif || exit 1

echo "Adding again - should fail"
$VALGRIND ldbadd $LDBDIR/tests/test.ldif 2> /dev/null && {
    echo "Should have failed to add again - gave $?"
    exit 1
}

echo "Adding LDIF with one already-existing user again - should fail"
$VALGRIND ldbadd $LDBDIR/tests/test-dup.ldif 2> /dev/null && {
    echo "Should have failed to add again - gave $?"
    exit 1
}

echo "Adding again - should succeed (as previous failed)"
$VALGRIND ldbadd $LDBDIR/tests/test-dup-2.ldif || exit 1

echo "Modifying elements"
$VALGRIND ldbmodify $LDBDIR/tests/test-modify.ldif || exit 1

echo "Modify LDIF with one un-met constraint - should fail"
$VALGRIND ldbadd $LDBDIR/tests/test-modify-unmet.ldif 2> /dev/null && {
    echo "Should have failed to modify - gave $?"
    exit 1
}

echo "Modify LDIF with after failure of un-met constraint - should also fail"
$VALGRIND ldbadd $LDBDIR/tests/test-modify-unmet-2.ldif 2> /dev/null && {
    echo "Should have failed to modify - gave $?"
    exit 1
}

echo "Showing modified record"
$VALGRIND ldbsearch '(uid=uham)'  || exit 1

echo "Rename entry with ldbmodify - modrdn"
$VALGRIND ldbmodify $LDBDIR/tests/test-modify-modrdn.ldif || exit 1

echo "Rename entry with ldbrename"
OLDDN="cn=Ursula Hampster,ou=Alumni Association,ou=People,o=University of Michigan,c=TEST"
NEWDN="cn=Hampster Ursula,ou=Alumni Association,ou=People,o=University of Michigan,c=TEST"
$VALGRIND ldbrename "$OLDDN" "$NEWDN"  || exit 1

echo "Showing renamed record"
$VALGRIND ldbsearch '(uid=uham)' || exit 1

echo "Starting ldbtest"
$VALGRIND ldbtest --num-records 100 --num-searches 10  || exit 1

if [ $LDB_SPECIALS = 1 ]; then
 echo "Adding index"
 $VALGRIND ldbadd $LDBDIR/tests/test-index.ldif  || exit 1
fi

echo "Adding bad attributes - should fail"
$VALGRIND ldbadd $LDBDIR/tests/test-wrong_attributes.ldif && {
    echo "Should fhave failed - gave $?"
    exit 1
}

echo "Testing indexed search"
$VALGRIND ldbsearch '(uid=uham)'  || exit 1
$VALGRIND ldbsearch '(&(objectclass=person)(objectclass=person)(objectclass=top))' || exit 1
$VALGRIND ldbsearch '(&(uid=uham)(uid=uham))'  || exit 1
$VALGRIND ldbsearch '(|(uid=uham)(uid=uham))'  || exit 1
$VALGRIND ldbsearch '(|(uid=uham)(uid=uham)(objectclass=OpenLDAPperson))'  || exit 1
$VALGRIND ldbsearch '(&(uid=uham)(uid=uham)(!(objectclass=xxx)))'  || exit 1
$VALGRIND ldbsearch '(&(objectclass=person)(uid=uham)(!(uid=uhamxx)))' uid \* \+ dn  || exit 1
$VALGRIND ldbsearch '(&(uid=uham)(uid=uha*)(title=*))' uid || exit 1

echo "Testing invalid search expression"
$VALGRIND ldbsearch '(&(uid=uham)(title=foo\blah))' uid && exit 1

# note that the "((" is treated as an attribute not an expression
# this matches the openldap ldapsearch behaviour of looking for a '='
# to see if the first argument is an expression or not
$VALGRIND ldbsearch '((' uid || exit 1
$VALGRIND ldbsearch '(objectclass=)' uid || exit 1
$VALGRIND ldbsearch -b 'cn=Hampster Ursula,ou=Alumni Association,ou=People,o=University of Michigan,c=TEST' -s base "" sn || exit 1

echo "Test wildcard match"
$VALGRIND ldbadd $LDBDIR/tests/test-wildcard.ldif  || exit 1
$VALGRIND ldbsearch '(cn=test*multi)'  || exit 1
$VALGRIND ldbsearch '(cn=*test*multi*)'  || exit 1
$VALGRIND ldbsearch '(cn=*test_multi)'  || exit 1
$VALGRIND ldbsearch '(cn=test_multi*)'  || exit 1
$VALGRIND ldbsearch '(cn=test*multi*test*multi)'  || exit 1
$VALGRIND ldbsearch '(cn=test*multi*test*multi*multi_*)' || exit 1

echo "Starting ldbtest indexed"
$VALGRIND ldbtest --num-records 100 --num-searches 500  || exit 1

echo "Testing one level search"
count=`$VALGRIND ldbsearch -b 'ou=Groups,o=University of Michigan,c=TEST' -s one 'objectclass=*' none |grep '^dn' | wc -l`
if [ $count != 3 ]; then
    echo returned $count records - expected 3
    exit 1
fi

echo "Testing binary file attribute value"
$VALGRIND ldbmodify $LDBDIR/tests/photo.ldif || exit 1
count=`$VALGRIND ldbsearch '(cn=Hampster Ursula)' jpegPhoto | grep '^dn' | wc -l`
if [ $count != 1 ]; then
    echo returned $count records - expected 1
    exit 1
fi

echo "*TODO* Testing UTF8 upper lower case searches !!"

echo "Testing compare"
count=`$VALGRIND ldbsearch '(cn>=t)' cn | grep '^dn' | wc -l`
if [ $count != 1 ]; then
    # only "cn: test_multi_test_multi_test_multi" (comes after "t")
    # upper-cased words come before "t" - hence excluded
    echo returned $count records - expected 1
    exit 1
fi
$VALGRIND ldbsearch '(cn>t)' cn && exit 1 # strictly greater should not work

count=`$VALGRIND ldbsearch '(cn<=t)' cn | grep '^dn' | wc -l`
if [ $count != 18 ]; then
    # everything except "cn: test_multi_test_multi_test_multi" (comes after "t")
    # upper-cased letters come before "t" - hence included
    echo returned $count records - expected 18
    exit 1
fi
$VALGRIND ldbsearch '(cn<t)' cn && exit 1 # strictly less should not work

checkcount() {
    count=$1
    scope=$2
    basedn=$3
    expression="$4"
    n=`$VALGRIND ldbsearch -s "$scope" -b "$basedn" "$expression" | grep '^dn' | wc -l`
    if [ $n != $count ]; then
	echo "Got $n but expected $count for $expression"
	exit 1
    fi
    echo "OK: $count $expression"
}

checkcount 0 'base' '' '(uid=uham)'
checkcount 0 'one' '' '(uid=uham)'

checkcount 1 'base' 'cn=Hampster Ursula,ou=Alumni Association,ou=People,o=University of Michigan,c=TEST' '(uid=uham)'
checkcount 1 'one' 'ou=Alumni Association,ou=People,o=University of Michigan,c=TEST' '(uid=uham)'
checkcount 1 'one' 'ou=People,o=University of Michigan,c=TEST' '(ou=ldb  test)'
