echo "LDB_URL: $LDB_URL"

echo "Adding base elements"
$VALGRIND bin/ldbadd tests/test.ldif || exit 1

echo "Modifying elements"
$VALGRIND bin/ldbmodify tests/test-modify.ldif || exit 1

echo "Showing modified record"
$VALGRIND bin/ldbsearch '(uid=uham)'  || exit 1

echo "Rename entry"
OLDDN="cn=Ursula Hampster,ou=Alumni Association,ou=People,o=University of Michigan,c=US"
NEWDN="cn=Hampster Ursula,ou=Alumni Association,ou=People,o=University of Michigan,c=US"
$VALGRIND bin/ldbrename "$OLDDN" "$NEWDN"  || exit 1

echo "Showing renamed record"
$VALGRIND bin/ldbsearch '(uid=uham)' || exit 1

#echo "Starting ldbtest"
#time $VALGRIND bin/ldbtest -r 1000 -s 10  || exit 1

#echo "Adding index"
#$VALGRIND bin/ldbadd tests/test-index.ldif  || exit 1

#echo "Starting ldbtest indexed"
#time $VALGRIND bin/ldbtest -r 1000 -s 5000  || exit 1

echo "Testing one level search"
count=`$VALGRIND bin/ldbsearch -b 'ou=Groups,o=University of Michigan,c=US' -s one 'objectclass=*' none |grep ^dn | wc -l`
if [ "$count" != 3 ]; then
    echo returned $count records - expected 3
    exit 1
fi
