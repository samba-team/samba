#!/bin/sh

# A shell script to connect to a windows host over telnet,
# setup for a smbtorture test,
# run the test,
# and remove the previously configured directory and share.
# Copyright Brad Henry <brad@samba.org> 2006
# Released under the GNU GPL v2 or later.

. script/tests/test_functions.sh

. script/tests/wintest_functions.sh

# This variable is defined in the per-hosts .fns file.
. $WINTESTCONF

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

rpc_tests="RPC-WINREG RPC-ASYNCBIND RPC-ATSVC RPC-DSSETUP RPC-EPMAPPER"
rpc_tests="$rpc_tests RPC-INITSHUTDOWN RPC-LSA-GETUSER RPC-MULTIBIND RPC-ROT"
rpc_tests="$rpc_tests RPC-SECRETS RPC-SRVSVC RPC-SVCCTL RPC-WKSSVC"

for t in $rpc_tests; do
	test_name="$t / WINDOWS SERVER"
	old_errs=$all_errs

	testit "$test_name" $SMBTORTURE_BIN_PATH \
		-U $SMBTORTURE_USERNAME%$SMBTORTURE_PASSWORD \
		-W $SMBTORTURE_WORKGROUP \
		ncacn_np:$SMBTORTURE_REMOTE_HOST \
		$t || all_errs=`expr $all_errs + 1`
	if [ $old_errs -lt $all_errs ]; then
		restore_snapshot "\n$test_name failed."
	fi
done

test_name="WINDOWS CLIENT / SAMBA SERVER SHARE"
old_errs=$all_errs
cat $WINTEST_DIR/common.exp > $TMPDIR/client_test.exp
cat $WINTEST_DIR/wintest_client.exp >> $TMPDIR/client_test.exp

testit "$test_name" \
	expect $TMPDIR/client_test.exp || all_errs=`expr $all_errs + 1`

if [ $old_errs -lt $all_errs ]; then
	# Restore snapshot to ensure VM is in a known state.
	restore_snapshot "\n$test_name failed."
	echo "Snapshot restored."
fi
rm -f $TMPDIR/client_test.exp

testok $0 $all_errs
