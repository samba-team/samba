#!/bin/sh

. script/tests/test_functions.sh

. script/tests/win/wintest_functions.sh

# This variable is defined in the per-hosts .fns file.
. $WINTESTCONF

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

server="$1"
username="$2"
password="$3"
domain="$4"
shift 4

base_tests="BASE-UNLINK BASE-ATTR BASE-DELETE BASE-TCON BASE-OPEN BASE-CHKPATH"

all_errs=0

for t in $base_tests; do
	test_name="$t / WINDOWS SERVER"
	echo -e "\n$test_name SETUP PHASE"

	setup_share_test

	if [ $err_rtn -ne 0 ]; then
		# If test setup fails, load VM snapshot and skip test.
		restore_snapshot "\n$test_name setup failed, skipping test."
	else
		echo -e "\n$test_name setup completed successfully."
		old_errs=$all_errs

		testit "$test_name" $SMBTORTURE_BIN_PATH \
			-U $username%$password \
			-W $domain //$server/$SMBTORTURE_REMOTE_SHARE_NAME \
			$t || all_errs=`expr $all_errs + 1`
		if [ $old_errs -lt $all_errs ]; then
			restore_snapshot "\n$test_name failed."
		else
			echo -e "\n$test_name CLEANUP PHASE"
			remove_share_test
			if [ $err_rtn -ne 0 ]; then
				# If cleanup fails, restore VM snapshot.
				restore_snapshot "\n$test_name removal failed."
			else
				echo -e "\n$test_name removal completed successfully."
			fi
		fi
	fi
done

testok $0 $all_errs
