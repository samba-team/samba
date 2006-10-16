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

#
# please don't remove tests here, when you want them to be skipped!
# just add them to the skipped line below
# this should be the complete list smbtorture offers as BASE-* tests
#
base="BASE-ATTR BASE-CHARSET BASE-CHKPATH BASE-DEFER_OPEN BASE-DELAYWRITE BASE-DELETE"
base="$base BASE-DENY1 BASE-DENY2 BASE-DENY3 BASE-DENYDOS BASE-DIR1 BASE-DIR2"
base="$base BASE-DISCONNECT BASE-FDPASS BASE-LOCK "
base="$base BASE-MANGLE BASE-NEGNOWAIT BASE-NTDENY1"
base="$base BASE-NTDENY2 BASE-OPEN BASE-OPENATTR BASE-PROPERTIES BASE-RENAME BASE-RW1"
base="$base BASE-SECLEAK BASE-TCON BASE-TCONDEV BASE-TRANS2 BASE-UNLINK BASE-VUID"
base="$base BASE-XCOPY"

#
# please don't remove tests here, when you want them to be skipped!
# just add them to the skipped line below
# this should be the complete list smbtorture offers as RAW-* tests
#
raw="RAW-CHKPATH RAW-CLOSE RAW-COMPOSITE RAW-CONTEXT RAW-EAS"
raw="$raw RAW-IOCTL RAW-LOCK RAW-MKDIR RAW-MUX RAW-NOTIFY RAW-OPEN RAW-OPLOCK"
raw="$raw RAW-QFILEINFO RAW-QFSINFO RAW-READ RAW-RENAME RAW-SEARCH RAW-SEEK"
raw="$raw RAW-SFILEINFO RAW-SFILEINFO-BUG RAW-STREAMS RAW-UNLINK RAW-WRITE"

smb2="SMB2-CONNECT SMB2-GETINFO SMB2-SETINFO SMB2-FIND"

tests="$base $raw $smb2"

#
# please add tests you want to be skipped here!
#
skipped="BASE-CHARSET BASE-DEFER_OPEN BASE-DELAYWRITE RAW-COMPOSITE RAW-OPLOCK RAW-ACLS"

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
    testit "$name" $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS $unc -U"$username"%"$password" $t || failed=`expr $failed + 1`
done

testok $0 $failed
