#!/bin/sh
#
# Test smbd with failing chdir system call.
#
# Verify that smbd does not panic when the chdir system call is
# returning an error.  ensure that the output format for ACL entries
#
# Copyright (C) 2017 Christof Schmitt

. $(dirname $0)/../../../testprogs/blackbox/subunit.sh
failed=0

if [ $SMBD_DONT_LOG_STDOUT -eq 1 ]; then
	subunit_start_test "check_panic_0"
	subunit_skip_test "check_panic_0" <<EOF
logging to stdout disabled
EOF

	testok $0 $failed
fi

error_inject_conf=$(dirname $SMB_CONF_PATH)/error_inject.conf

panic_count_0=$(grep -c PANIC $SMBD_TEST_LOG)

#
# Verify that a panic in smbd will result in a PANIC message in the log
#

# As a panic is expected here, also overwrite the default "panic
# action" in selftest to not start a debugger
echo 'error_inject:chdir = panic' > $error_inject_conf
echo '[global]' >> $error_inject_conf
echo 'panic action = ""' >> $error_inject_conf

testit_expect_failure "smbclient" $VALGRIND \
		      $BINDIR/smbclient //$SERVER_IP/error_inject \
		      -U$USERNAME%$PASSWORD  -c dir ||
	failed=$(expr $failed + 1)

rm $error_inject_conf

panic_count_1=$(grep -c PANIC $SMBD_TEST_LOG)

testit "check_panic_1" test $(expr $panic_count_0 + 1) -eq $panic_count_1 ||
	failed=$(expr $failed + 1)

#
# Verify that a failing chdir vfs call does not result in a smbd panic
#

echo 'error_inject:chdir = ESTALE' > $error_inject_conf

testit_expect_failure "smbclient" $VALGRIND \
		      $BINDIR/smbclient //$SERVER_IP/error_inject \
		      -U$USERNAME%$PASSWORD  -c dir ||
	failed=$(expr $failed + 1)

panic_count_2=$(grep -c PANIC $SMBD_TEST_LOG)

testit "check_panic_2" test $panic_count_1 -eq $panic_count_2 ||
	failed=$(expr $failed + 1)

rm $error_inject_conf

testok $0 $failed
