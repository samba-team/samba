#!/bin/sh
# Verify that samba3dump completes.

. lib/subunit/shell/share/subunit.sh

subunit_start_test samba3dump

SRCDIR=`dirname $0`/../..

if $SRCDIR/source4/scripting/bin/samba3dump $SRCDIR/testdata/samba3; then
	subunit_pass_test samba3dump
else
	echo | subunit_fail_test samba3dump
fi
