#!/bin/sh

echo "Running tdb feature tests"

rm -f $LDB_URL

checkcount() {
    count=$1
    expression="$2"
    n=`bin/ldbsearch "$expression" | grep ^dn | wc -l`
    if [ $n != $count ]; then
	echo "Got $n but expected $count for $expression"
	bin/ldbsearch "$expression"
	exit 1
    fi
    echo "OK: $count $expression"
}

echo "Testing case sensitve search"
cat <<EOF | bin/ldbadd || exit 1
dn: cn=t1,cn=TEST
test: foo
EOF


echo $ldif | bin/ldbadd || exit 1
bin/ldbsearch

checkcount 1 '(test=foo)'
checkcount 0 '(test=FOO)'
checkcount 0 '(test=fo*)'

echo "Making case insensitive"
cat <<EOF | bin/ldbmodify || exit 1
dn: @ATTRIBUTES
changetype: add
add: test
test: CASE_INSENSITIVE
EOF

echo $ldif | bin/ldbmodify || exit 1
checkcount 1 '(test=foo)'
checkcount 1 '(test=FOO)'
checkcount 0 '(test=fo*)'

echo "adding wildcard"
cat <<EOF | bin/ldbmodify || exit 1
dn: @ATTRIBUTES
changetype: modify
add: test
test: WILDCARD
EOF
checkcount 1 '(test=foo)'
checkcount 1 '(test=FOO)'
checkcount 1 '(test=fo*)'

echo "adding i"
cat <<EOF | bin/ldbmodify || exit 1
dn: cn=t1,cn=TEST
changetype: modify
add: i
i: 0x100
EOF
checkcount 1 '(i=0x100)'
checkcount 0 '(i=256)'

echo "marking i as INTEGER"
cat <<EOF | bin/ldbmodify || exit 1
dn: @ATTRIBUTES
changetype: modify
add: i
i: INTEGER
EOF
checkcount 1 '(i=0x100)'
checkcount 1 '(i=256)'


rm -f $LDB_URL
