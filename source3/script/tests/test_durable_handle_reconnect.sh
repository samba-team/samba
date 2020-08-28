#!/bin/sh
#
# Test Durable Handle reconnect with injected delay in the disconnect.
#
# Copyright (C) 2018 Ralph Boehme

. $(dirname $0)/../../../testprogs/blackbox/subunit.sh
failed=0

delay_inject_conf=$(dirname $SMB_CONF_PATH)/delay_inject.conf

echo 'delay_inject:ntimes = 5000' > $delay_inject_conf

testit "durable_v2_delay.durable_v2_reconnect_delay" $VALGRIND \
       $BINDIR/smbtorture //$SERVER_IP/delay_inject \
       -U$USERNAME%$PASSWORD \
       smb2.durable-v2-delay.durable_v2_reconnect_delay ||
	failed=$(expr $failed + 1)

SMBD_LOG_FILES="$SMBD_TEST_LOG"
if [ $SMBD_DONT_LOG_STDOUT -eq 1 ]; then
	_SMBD_LOG_FILE=$(dirname $SMBD_TEST_LOG)/logs/log.smbd
	SMBD_LOG_FILES="$SMBD_LOG_FILES $_SMBD_LOG_FILE"
fi

testit "durable_v2_delay.durable_v2_reconnect_delay_msec" $VALGRIND \
       $BINDIR/smbtorture //$SERVER_IP/durable \
       -U$USERNAME%$PASSWORD \
       smb2.durable-v2-delay.durable_v2_reconnect_delay_msec ||
	failed=$(expr $failed + 1)

rm $delay_inject_conf

testok $0 $failed
