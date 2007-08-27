#!/bin/sh

# this runs the file serving tests that are expected to pass with the
# current posix ntvfs backend

ADDARGS="$*"

incdir=`dirname $0`
. $incdir/test_functions.sh

smb2=`bin/smbtorture --list | grep "^SMB2-" | xargs`
raw=`bin/smbtorture --list | grep "^RAW-" | xargs`
base=`bin/smbtorture --list | grep "^BASE-" | xargs`
tests="$base $raw $smb2"

for t in $tests; do
    plantest "$t" dc $VALGRIND bin/smbtorture $TORTURE_OPTIONS $ADDARGS //\$SERVER/tmp -U"\$USERNAME"%"\$PASSWORD" $t
done
