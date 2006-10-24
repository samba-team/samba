#!/bin/sh

# A shell script to connect to a windows host over telnet,
# setup for a smbtorture test,
# run the test,
# and remove the previously configured directory and share.
# Copyright Brad Henry <brad@samba.org> 2006
# Released under the GNU GPL v2 or later.

# Index variable to count the total number of tests which fail.
all_errs=0

export SMBTORTURE_REMOTE_HOST=`perl -I$WINTEST_DIR $WINTEST_DIR/vm_get_ip.pl`
if [ -z $SMBTORTURE_REMOTE_HOST ]; then
	# Restore snapshot to ensure VM is in a known state, then exit.
	restore_snapshot "Test failed to get the IP address of the windows host."
	exit 1
fi

$WINTEST_DIR/wintest_base.sh $SMBTORTURE_REMOTE_HOST $SMBTORTURE_USERNAME \
	$SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP \
	|| all_errs=`expr $all_errs + $?`

$WINTEST_DIR/wintest_raw.sh $SMBTORTURE_REMOTE_HOST $SMBTORTURE_USERNAME \
	$SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP \
	|| all_errs=`expr $all_errs + $?`

$WINTEST_DIR/wintest_rpc.sh $SMBTORTURE_REMOTE_HOST $SMBTORTURE_USERNAME \
	$SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP \
	|| all_errs=`expr $all_errs + $?`

$WINTEST_DIR/wintest_net.sh $SMBTORTURE_REMOTE_HOST $SMBTORTURE_USERNAME \
	$SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP \
	|| all_errs=`expr $all_errs + $?`

$WINTEST_DIR/wintest_client.sh || all_errs=`expr $all_errs + $?`
