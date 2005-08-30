#!/bin/sh

S3URL=$1

if [ -z "$S3URL" ];
then
	rm -f samba3.ldb
	S3URL="tdb://samba3.ldb"
	echo "Adding samba3 LDIF..."
	$VALGRIND ldbadd -H tdb://samba3.ldb < samba3.ldif || exit 1
fi

rm -f samba4.ldb

echo "Initial samba4 LDIF..."
$VALGRIND ldbadd -H tdb://samba4.ldb <<EOF
dn: @MODULES
@LIST: samba3sam

dn: @MAP=samba3sam
@MAP_URL: $S3URL

EOF

LOC="-H tdb://samba4.ldb"

echo "Looking up by non-mapped attribute"
$VALGRIND ldbsearch $LOC "(cn=Administrator)" || exit 1

echo "Looking up by mapped attribute"
$VALGRIND ldbsearch $LOC "(name=Backup Operators)" || exit 1

echo "Looking up by old name of renamed attribute"
$VALGRIND ldbsearch $LOC "(displayName=Backup Operators)" || exit 1

echo "Adding a record"
$VALGRIND ldbadd $LOC <<EOF
dn: cn=Foo,dc=idealx,dc=org
unixName: root
lastLogon: 20000
cn: Foo
showInAdvancedViewOnly: TRUE

EOF

echo "Checking for existance of record"
$VALGRIND ldbsearch $LOC "(cn=Foo)" unixName lastLogon cn showInAdvancedViewOnly || exit 1

echo "Checking for persistence of non-mappable attribute"
$VALGRIND ldbsearch $LOC "(cn=Foo)" showInAdvancedViewOnly | grep showInAdvancedViewOnly || exit 1

echo "Adding record with mapped attribute in dn"
$VALGRIND ldbadd $LOC <<EOF
dn: unixName=nobody,dc=idealx,dc=org
unixName: nobody 
cn: Niemand

EOF

echo "Checking for existance of record (mapped)"
$VALGRIND ldbsearch $LOC "(unixName=nobody)" unixName cn dn || exit 1
