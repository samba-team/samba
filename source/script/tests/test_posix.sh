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

for t in $tests; do
    if [ ! -z "$start" -a "$start" != $t ]; then
	continue;
    fi
    start=""
    testit "$t" smb $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS $unc -U"$username"%"$password" $t
done
