#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3

incdir=`dirname $0`
. $incdir/test_functions.sh

BINDIR=$incdir/../../bin

plantest "talloctort" none $VALGRIND $BINDIR/talloctort 
plantest "replacetort" none $VALGRIND $BINDIR/replacetort 
plantest "tdbtorture" none $VALGRIND $BINDIR/tdbtorture 
