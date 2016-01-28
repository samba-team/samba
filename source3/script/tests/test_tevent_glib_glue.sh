#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0
TESTNAME="tevent_glib_glue_test"

if [ ! -x $BINDIR/tevent_glib_glue_test ] ; then
	subunit_start_test "$TESTNAME"
	subunit_skip_test "$TESTNAME" <<EOF
Test needs glib2-devel
EOF
	testok $0 $failed
fi


testit "$TESTNAME" $VALGRIND $BINDIR/tevent_glib_glue_test ||
	failed=`expr $failed + 1`

testok $0 $failed
