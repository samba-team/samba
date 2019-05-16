#!/bin/sh
#
# Test guest authentication
#
# Copyright (C) 2019 Ralph Boehme
#

if [ $# -lt 5 ]; then
cat <<EOF
Usage: $0 SERVER SMBCLIENT SMBCONTROL NET CONFIGURATION
EOF
exit 1;
fi

SERVER=$1
SMBCLIENT=$2
SMBCONTROL=$3
NET=$4
CONFIGURATION=$5

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0
SIDS=""

prepare_empty_builtin_guests() {
    TMP=$($NET $CONFIGURATION groupmap listmem S-1-5-32-546 2>&1)
    bg_exists=$?
    if [ $bg_exists != 0 ] ; then
	printf "Group map for BUILTIN\\Guests must exist for test\n"
	return 1
    fi

    SIDS=$($NET $CONFIGURATION groupmap listmem S-1-5-32-546)
    if [ $? != 0 ] ; then
	printf "$NET $CONFIGURATION groupmap listmem S-1-5-32-546 failed. Returned:\n"
	printf "$SIDS\n"
	return 1
    fi
    printf "Got S-1-5-32-546 members:\n$SIDS\n"

    if [ "$SIDS" != "" ] ; then
	for SID in $SIDS ; do
	    printf "Deleting member $SID from S-1-5-32-546\n"
	    $NET $CONFIGURATION groupmap delmem S-1-5-32-546 $SID || return 1
	done
    fi

    return 0
}

add_local_guest_to_builtin_guests() {
    if [ "$SIDS" != "" ] ; then
	for SID in $SIDS ; do
	    printf "Adding $SID as member to S-1-5-32-546\n"
	    $NET $CONFIGURATION groupmap addmem S-1-5-32-546 $SID || return 1
	done
    fi
}

test_smbclient() {
    $SMBCLIENT -U foo%bar //$SERVER/tmpguest -c exit
    if [ $? != 0 ] ; then
	printf "smbclient failed\n"
	return 1
    fi
    return 0
}

testit "smbclient_guest_at_startup" \
    test_smbclient  ||
    failed=$(expr $failed + 1)

printf "Prepare BUILTIN\\Guests group mapping without members\n"

prepare_empty_builtin_guests || {
    printf "Setting up BUILTIN\\Guests without members failed\n"
    exit 1
}

$SMBCONTROL $CONFIGURATION smbd reload-config || {
    printf "Reloading parent smbd guest info failed\n"
    exit 1
}

testit "smbclient_guest_auth_without_members" \
    test_smbclient &&
    failed=$(expr $failed + 1)

# restore config
add_local_guest_to_builtin_guests

$SMBCONTROL $CONFIGURATION smbd reload-config || {
    printf "Reloading parent smbd guest info failed\n"
    exit 1
}

testit "smbclient_works_after_restored_setup" \
    test_smbclient  ||
    failed=$(expr $failed + 1)

testok $0 $failed
