#!/bin/sh

. script/tests/test_functions.sh

. script/tests/win/wintest_functions.sh

# This variable is defined in the per-hosts .fns file.
. $WINTESTCONF

test_name="WINDOWS CLIENT / SAMBA SERVER SHARE"

cat $WINTEST_DIR/common.exp > $TMPDIR/client_test.exp
cat $WINTEST_DIR/wintest_client.exp >> $TMPDIR/client_test.exp

testit "$test_name" \
	expect $TMPDIR/client_test.exp || all_errs=`expr $all_errs + 1`

if [ $all_errs > 0 ]; then
	# Restore snapshot to ensure VM is in a known state.
	restore_snapshot "\n$test_name failed."
	echo "Snapshot restored."
fi

rm -f $TMPDIR/client_test.exp

testok $0 $all_errs
