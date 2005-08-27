#!/bin/sh

rm -f samba3.ldb

$VALGRIND ldbadd -H tdb://samba3.ldb < samba3.ldif

OPT="-o modules:samba3sam -H tdb://samba3.ldb "
$VALGRIND ldbsearch $OPT "(cn=Administrator)"
