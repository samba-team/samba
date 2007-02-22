#!/bin/sh

# A shell script to connect to a windows host over telnet,
# setup for a smbtorture test,
# run the test,
# and remove the previously configured directory and share.
# Copyright Brad Henry <brad@samba.org> 2006
# Released under the GNU GPL v2 or later.

. script/tests/test_functions.sh

export SMBTORTURE_REMOTE_HOST=`perl -I$WINTEST_DIR $WINTEST_DIR/vm_get_ip.pl VM_CFG_PATH`
if [ -z $SMBTORTURE_REMOTE_HOST ]; then
	# Restore snapshot to ensure VM is in a known state, then exit.
	restore_snapshot "Test failed to get the IP address of the windows host." "$VM_CFG_PATH"
	exit 1
fi

name="BASE against Windows 2003"
testit "$name" $WINTEST_DIR/wintest_base.sh $SMBTORTURE_REMOTE_HOST \
	$SMBTORTURE_USERNAME $SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP

name="RAW against Windows 2003"
testit "$name" $WINTEST_DIR/wintest_raw.sh $SMBTORTURE_REMOTE_HOST \
	$SMBTORTURE_USERNAME $SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP

name="RPC against Windows 2003"
testit "$name" $WINTEST_DIR/wintest_rpc.sh $SMBTORTURE_REMOTE_HOST \
	$SMBTORTURE_USERNAME $SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP

name="NET against Windows 2003"
testit "$name" $WINTEST_DIR/wintest_net.sh $SMBTORTURE_REMOTE_HOST \
	$SMBTORTURE_USERNAME $SMBTORTURE_PASSWORD $SMBTORTURE_WORKGROUP

name="Windows 2003 against smbd"
testit "$name" $WINTEST_DIR/wintest_client.sh $SMBTORTURE_REMOTE_HOST

dc_tests="RPC-DRSUAPI RPC-SPOOLSS ncacn_np ncacn_ip_tcp"
for name in $dc_tests; do
	testit "$name against Windows 2003 DC" $WINTEST_DIR/wintest_2k3_dc.sh \
		"$name" "$WIN2K3_DC_VM_CFG_PATH"
done
