#!/bin/sh

# A shell script to connect to a windows host over telnet,
# setup for a smbtorture test,
# run the test,
# and remove the previously configured directory and share.
# Copyright Brad Henry <brad@samba.org> 2006
# Released under the GNU GPL v2 or later.


# This variable is defined in the per-hosts .fns file.
. $WINTESTCONF

# Setup the windows environment.
# This was the best way I could figure out including library files
# for the moment.
# I was finding that "cat common.exp wintest_setup.exp | expect -f -"
# fails to run, but exits with 0 status something like 1% of the time.

setup_win_server_test()
{
	echo -e "\nSetting up windows environment."
	cat $WINTEST_DIR/common.exp > $TMPDIR/setup.exp
	cat $WINTEST_DIR/wintest_setup.exp >> $TMPDIR/setup.exp
	expect $TMPDIR/setup.exp
	err_rtn=$?
	rm -f $TMPDIR/setup.exp
}

# Run the smbtorture test.
run_win_server_test()
{
        winfailed=0
	echo -e "\nRunning smbtorture tests."
	echo -e "\nRunning RAW-QFILEINFO"
	$SMBTORTURE_BIN_PATH \
		-U $SMBTORTURE_USERNAME%$SMBTORTURE_PASSWORD \
		-d 10 -W $SMBTORTURE_WORKGROUP \
		//$SMBTORTURE_REMOTE_HOST/$SMBTORTURE_REMOTE_SHARE_NAME \
		RAW-QFILEINFO || winfailed=`expr $winfailed + 1`
	
	echo -e "\nRunning RPC-WINREG"
	$SMBTORTURE_BIN_PATH \
		-U $SMBTORTURE_USERNAME%$SMBTORTURE_PASSWORD \
		-W $SMBTORTURE_WORKGROUP \
		ncacn_np:$SMBTORTURE_REMOTE_HOST \
		RPC-WINREG || winfailed=`expr $winfailed + 1`
	err_rtn=$winfailed
}

# Clean up the windows environment after the test has run or failed.
remove_win_server_test()
{
	echo -e "\nCleaning up windows environment."
	cat $WINTEST_DIR/common.exp > $TMPDIR/remove.exp
	cat $WINTEST_DIR/wintest_remove.exp >> $TMPDIR/remove.exp
	expect $TMPDIR/remove.exp
	err_rtn=$?
	rm -f $TMPDIR/remove.exp
}

# Test windows as a server against samba as a client.
win_server_test()
{
	echo -e "\nSETUP PHASE"
	setup_win_server_test
	if [ $err_rtn -ne 0 ]; then
		echo -e "\nSamba CLIENT test setup failed."
		return $err_rtn
	fi
	echo -e "\nSamba CLIENT test setup completed successfully."

	echo -e "\nTEST PHASE"
	run_win_server_test
	if [ $err_rtn -ne 0 ]; then
		echo -e "\nSamba CLIENT test run failed."
		return $err_rtn
	fi
	echo -e "\nSamba CLIENT test run completed successfully."

	echo -e "\nCLEANUP PHASE"
	remove_win_server_test
	if [ $err_rtn -ne 0 ]; then
		echo -e "\nSamba CLIENT test removal failed."
		return $err_rtn
	fi
	echo -e "\nSamba CLIENT test removal completed successfully."
}

# Test windows as a client against samba as a server.
win_client_test()
{
	cat $WINTEST_DIR/common.exp > $TMPDIR/client_test.exp
	cat $WINTEST_DIR/wintest_client.exp >> $TMPDIR/client_test.exp
	expect $TMPDIR/client_test.exp
	err_rtn=$?
	rm -f $TMPDIR/client_test.exp
}

check_error()
{
	if [ $err_rtn -ne 0 ]; then
		# Restore snapshot to ensure VM is in a known state.
		perl -I$WINTEST_DIR $WINTEST_DIR/vm_load_snapshot.pl
		echo "Snapshot restored."
		echo "=========================================="
		echo $err_str
		echo "=========================================="
	else
		echo -e "\nALL OK: $cmdline"
		echo "=========================================="
		echo $err_ok_str
		echo "=========================================="
	fi

	all_errs=`expr $all_errs + $err_rtn`
}

get_remote_ip()
{
	export SMBTORTURE_REMOTE_HOST=`perl -I$WINTEST_DIR $WINTEST_DIR/vm_get_ip.pl`
	err_rtn=$?
}

# Index variable to count the total number of tests which fail.
all_errs=0

# Get ip address of windows vmware host.
err_str="Test failed to get the IP address of the windows host."
err_ok_str="Windows host IP address discovered successfully."

get_remote_ip
check_error

test_name="SAMBA CLIENT / WINDOWS SERVER"
echo "--==--==--==--==--==--==--==--==--==--==--"
echo "Running test $test_name (level 0 stdout)"
echo "--==--==--==--==--==--==--==--==--==--==--"
date
echo "Testing $test_name"

err_str="TEST FAILED: $test_name"
err_ok_str="TEST PASSED: $test_name"

win_server_test
check_error

test_name="WINDOWS CLIENT / SAMBA SERVER"
echo "--==--==--==--==--==--==--==--==--==--==--"
echo "Running test $test_name (level 0 stdout)"
echo "--==--==--==--==--==--==--==--==--==--==--"
date
echo "Testing $test_name"

err_str="TEST FAILED: $test_name"
err_ok_str="TEST PASSED: $test_name"

win_client_test
check_error

exit $all_errs
