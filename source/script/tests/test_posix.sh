#!/bin/sh

# this runs the file serving tests that are expected to pass with the
# current posix ntvfs backend

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_posix.sh UNC USERNAME PASSWORD <first> <smbtorture args>
EOF
exit 1;
fi

unc="$1"
username="$2"
password="$3"
start="$4"
shift 4
ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

smb2=`bin/smbtorture --list | grep "^SMB2-" | xargs`
raw=`bin/smbtorture --list | grep "^RAW-" | xargs`
base=`bin/smbtorture --list | grep "^BASE-" | xargs`
tests="$base $raw $smb2"

#
# please add tests you want to be skipped here!
#
skipped="BASE-CHARSET BASE-DEFER_OPEN BASE-DELAYWRITE RAW-COMPOSITE RAW-OPLOCK RAW-ACLS BASE-IOMETER"
skipped="$skipped BASE-SAMBA3ERROR BASE-CASETABLE BASE-NTTRANS BASE-BENCH-HOLDCON BASE-SCAN-MAXFID"
skipped="$skipped RAW-BENCH-OPLOCK RAW-SAMBA3HIDE RAW-SAMBA3CLOSEERR RAW-SAMBA3CHECKFSP RAW-SAMBA3BADPATH"
skipped="$skipped RAW-SCAN-EAMAX SMB2-LOCK SMB2-NOTIFY"

echo "WARNING: Skipping tests $skipped"

failed=0
for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    skip=0
    for s in $skipped; do
    	if [ x"$s" = x"$t" ]; then
    	    skip=1;
	    break;
	fi
    done
    if [ $skip = 1 ]; then
    	continue;
    fi
    start=""
    name="$t"
    testit "$name" $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS $unc -U"$username"%"$password" $t
done

testok $0 $failed
