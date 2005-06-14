#!/bin/sh

rm -f $LDB_URL

cat <<EOF | bin/ldbadd - || exit 1
dn: testrec1
i1: 1
i2: 0
i3: 1234
i4: 0x7003004

dn: testrec2
i1: 0x800000

dn: testrec3
i1: 0x101010101
i1: 7
EOF

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

checkcount 1 '(i3=1234)'
checkcount 0 '(i3=12345)'

checkcount 2 '(i1:1.2.840.113556.1.4.803:=1)'
checkcount 1 '(i1:1.2.840.113556.1.4.803:=3)'
checkcount 1 '(i1:1.2.840.113556.1.4.803:=7)'
checkcount 0 '(i1:1.2.840.113556.1.4.803:=15)'
checkcount 1 '(i1:1.2.840.113556.1.4.803:=0x800000)'
checkcount 1 '(i1:1.2.840.113556.1.4.803:=8388608)'

checkcount 2 '(i1:1.2.840.113556.1.4.804:=1)'
checkcount 2 '(i1:1.2.840.113556.1.4.804:=3)'
checkcount 2 '(i1:1.2.840.113556.1.4.804:=7)'
checkcount 2 '(i1:1.2.840.113556.1.4.804:=15)'
checkcount 1 '(i1:1.2.840.113556.1.4.804:=0x800000)'
checkcount 1 '(i1:1.2.840.113556.1.4.804:=8388608)'

rm -f $LDB_URL
