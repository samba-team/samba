#!/bin/sh

rm -f samba3.ldb

echo "Adding samba3 LDIF..."
$VALGRIND ldbadd -H tdb://samba3.ldb < samba3.ldif || exit 1

LOC="-H tdb://samba3.ldb"
OPT="-o modules:samba3sam $LOC"

echo "Looking up by non-mapped attribute"
$VALGRIND ldbsearch $OPT "(cn=Administrator)" || exit 1

echo "Looking up by mapped attribute"
$VALGRIND ldbsearch $OPT "(name=Backup Operators)" || exit 1

echo "Looking up by old name of renamed attribute"
$VALGRIND ldbsearch $OPT "(displayName=Backup Operators)" || exit 1

echo "Adding a record"
$VALGRIND ldbadd $OPT <<EOF
dn: cn=Foo,dc=idealx,dc=org
unixName: root
lastLogon: 20000
cn: Foo

EOF

echo "Checking for existance of record (mapped)"
$VALGRIND ldbsearch $OPT "(cn=Foo)" unixName lastLogon cn || exit 1

echo "Checking for existance of record (non-mapped)"
$VALGRIND ldbsearch $LOC"(cn=foo)" uid sambaLogonTime cn || exit 1

echo "Adding record with mapped attribute in dn"
$VALGRIND ldbadd $OPT <<EOF
dn: unixName=nobody,dc=idealx,dc=org
unixName: nobody 
cn: Niemand

EOF

echo "Checking for existance of record (mapped)"
$VALGRIND ldbsearch $OPT "(unixName=nobody)" unixName cn dn || exit 1

echo "Checking for existance of record (non-mapped)"
$VALGRIND ldbsearch $OPT "(uid=nobody)" unixName cn dn || exit 1
