#!/bin/sh
#
# Test Durable Handle reconnect with injected delay in the disconnect.
#
# Copyright (C) 2018 Ralph Boehme

. $(dirname $0)/../../../testprogs/blackbox/subunit.sh
failed=0

cd $SELFTEST_TMPDIR || exit 1

delay_inject_conf=$(dirname $SMB_CONF_PATH)/delay_inject.conf

echo 'delay_inject:fntimes = 5000' >$delay_inject_conf

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

error_inject_conf=$(dirname $SMB_CONF_PATH)/error_inject.conf

cat > $error_inject_conf << _EOF
	kernel share modes = no
	kernel oplocks = no
	posix locking = no
	error_inject:durable_reconnect = st_ex_nlink
_EOF

testit "durable-v2-regressions.durable_v2_reconnect_bug15624" \
	$VALGRIND $BINDIR/smbtorture //$SERVER_IP/error_inject \
	-U$USERNAME%$PASSWORD \
	--option=torture:bug15624=yes \
	smb2.durable-v2-regressions.durable_v2_reconnect_bug15624 ||
	failed=$(expr $failed + 1)

rm $error_inject_conf

testok $0 $failed
