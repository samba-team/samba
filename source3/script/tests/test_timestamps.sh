#!/bin/sh
#
# This verifies getting and setting timestamps with non-trivial values like 0
# and < 0 works.
#

if [ $# -lt 5 ]; then
    echo "Usage: $0 SERVER_IP USERNAME PASSWORD PREFIX SMBCLIENT"
    exit 1
fi

SERVER_IP="$1"
USERNAME="$2"
PASSWORD="$3"
PREFIX="$4"
SMBCLIENT="$5"

SMBCLIENT="$VALGRIND ${SMBCLIENT}"
failed=0

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

export TZ=GMT

setup_testfiles() {
    touch -d "$(date --date=@0)" $PREFIX/time_0
    touch -d "$(date --date=@-1)" $PREFIX/time_-1
    touch -d "$(date --date=@-2)" $PREFIX/time_-2
    touch -t 196801010000 $PREFIX/time_1968
}

remove_testfiles() {
    rm $PREFIX/time_0
    rm $PREFIX/time_-1
    rm $PREFIX/time_-2
    rm $PREFIX/time_1968
}

test_time() {
    local file="$1"
    local expected="$2"

    $SMBCLIENT //$SERVER/tmp -U $USERNAME%$PASSWORD -c "allinfo $file"
    out=$($SMBCLIENT //$SERVER/tmp -U $USERNAME%$PASSWORD -c "allinfo $file" 2>&1) || return 1
    echo "smbclient allinfo on $fname returned: \"$out\""

    # Ignore create_time as that is synthesized
    for time in access_time write_time change_time ; do
	echo "$out" | grep "$time" | grep "$expected" || {
            echo "Expected \"$expected\", got: \"$(echo $out | grep $time)\""
	    return 1
	}
    done
}

#Setup
testit "create testfiles" setup_testfiles || failed=`expr $failed + 1`

# Tests
testit "time=0" test_time time_0 "Thu Jan  1 12:00:00 AM 1970 GMT" || failed=`expr $failed + 1`
testit "time=-1" test_time time_-1 "Wed Dec 31 11:59:59 PM 1969 GMT" || failed=`expr $failed + 1`
testit "time=-2" test_time time_-2 "Wed Dec 31 11:59:58 PM 1969 GMT" || failed=`expr $failed + 1`
testit "time=1968" test_time time_1968 "Mon Jan  1 12:00:00 AM 1968 GMT" || failed=`expr $failed + 1`

# Cleanup
testit "delete testfile" remove_testfiles || failed=`expr $failed + 1`

exit $failed
