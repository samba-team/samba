#!/bin/sh
#
# Verify that smbtorture tests for manually testing ZERO_DATA
#
# Copyright (C) 2019 Christof Schmitt

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_zero_data.sh SERVER_IP USERNAME PASSWORD LOCAL_PATH
EOF
exit 1;
fi

SERVER=${1}
USERNAME=${2}
PASSWORD=${3}
LOCAL_PATH=${4}

. $(dirname $0)/../../../testprogs/blackbox/subunit.sh
failed=0

TESTDIR=$LOCAL_PATH/zero_data

mkdir -p $TESTDIR
chmod 777 p $TESTDIR

dd if=/dev/urandom of=$TESTDIR/testfile bs=1024 count=128
chmod 777 $TESTDIR/testfile

alloc_kb=$(du -k $TESTDIR/testfile | sed -e 's/\t.*//')
testit "check allocation before zero-data" test $alloc_kb -eq 128 ||
	failed=$(expr $failed + 1)

testit "set-sparse" $VALGRIND $BINDIR/smbtorture //$SERVER_IP/tmp \
       -U$USERNAME%$PASSWORD smb2.set-sparse-ioctl \
       --option=torture:filename=zero_data/testfile ||
	failed=$(expr $failed + 1)

testit "zero-data" $VALGRIND $BINDIR/smbtorture //$SERVER_IP/tmp \
       -U$USERNAME%$PASSWORD smb2.zero-data-ioctl \
       --option=torture:filename=zero_data/testfile \
       --option=torture:offset=0 \
       --option=torture:beyond_final_zero=131072 ||
	failed=$(expr $failed + 1)

alloc_kb=$(du -k $TESTDIR/testfile | sed -e 's/\t.*//')
testit "check allocation after zero-data" test $alloc_kb -eq 0 ||
	failed=$(expr $failed + 1)

rm -rf $TESTDIR

testok $0 $failed
