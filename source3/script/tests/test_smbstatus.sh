#!/bin/sh

# This runs smbstatus tests

if [ $# -lt 12 ]; then
	echo "Usage: test_smbstatus.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD USERID LOCAL_PATH PREFIX SMBCLIENT CONFIGURATION PROTOCOL"
	exit 1
fi

SERVER="${1}"
SERVER_IP="${2}"
DOMAIN="${3}"
USERNAME="${4}"
PASSWORD="${5}"
USERID="${6}"
LOCAL_PATH="${7}"
PREFIX="${8}"
SMBCLIENT="${9}"
SMBSTATUS="${10}"
CONFIGURATION="${11}"
PROTOCOL="${12}"

shift 12

RAWARGS="${CONFIGURATION} -m${PROTOCOL}"
ADDARGS="${RAWARGS} $@"

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_smbstatus()
{
	local cmdfile=$PREFIX/smbclient_commands
	local tmpfile=$PREFIX/smclient_lock_file
	local file=smclient_lock_file
	local cmd=""
	local ret=0
	local userid=$(id -u $USERNAME)

	cat >$tmpfile <<EOF
What a Wurst!
EOF
	cat >$cmdfile <<EOF
lcd $PREFIX_ABS
put $file
open $file
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS
close 1
rm $file
quit
EOF

	cmd="CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $cmdfile 2>&1"
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $cmpfile
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to run smbclient with error $ret"
		echo "$out"
		false
		return
	fi

	echo "$out" | grep -c 'NT_STATUS_'
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Failed: got an NT_STATUS error!"
		echo "$out"
		false
		return
	fi

	echo "$out" | grep "$userid[ ]*DENY_NONE"
	ret=$?
	if [ $ret != 0 ]; then
		echo "Failed to find userid in smbstatus locked file output"
		echo "$out"
		false
		return
	fi

	return 0
}

test_smbstatus_resolve_uids()
{
	local cmdfile=$PREFIX/smbclient_commands
	local tmpfile=$PREFIX/smclient_lock_file
	local file=smclient_lock_file
	local cmd=""
	local ret=0
	local userid=$(id -u $USERNAME)

	cat >$tmpfile <<EOF
What a Wurst!
EOF
	cat >$cmdfile <<EOF
lcd $PREFIX_ABS
put $file
open $file
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --resolve-uids
close 1
rm $file
quit
EOF

	cmd="CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $cmdfile 2>&1"
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $cmpfile
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to run smbclient with error $ret"
		echo "$out"
		false
		return
	fi

	echo "$out" | grep -c 'NT_STATUS_'
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Failed: got an NT_STATUS error!"
		echo "$out"
		false
		return
	fi

	echo "$out" | grep "$USERNAME[ ]*DENY_NONE"
	ret=$?
	if [ $ret != 0 ]; then
		echo "Failed to find userid in smbstatus locked file output"
		echo "$out"
		false
		return
	fi

	return 0
}

test_smbstatus_output()
{
	local cmdfile=$PREFIX/smbclient_commands
	local tmpfile=$PREFIX/smbclient_lock_file
	local file=smbclient_lock_file
	local status_shares=smbstatus_output_shares
	local status_processes=smbstatus_output_processes
	local status_locks=smbstatus_output_locks

	cat >$tmpfile <<EOF
Hello World!
EOF
	cat >$cmdfile <<EOF
lcd $PREFIX_ABS
put $file
open $file
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --shares > $status_shares
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --processes > $status_processes
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --locks > $status_locks
close 1
rm $file
quit
EOF

	cmd="CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $cmdfile 2>&1"
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?

	rm -f $cmpfile
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to run smbclient with error $ret"
		echo "$out"
		return 1
	fi

	out=$(cat $PREFIX/$status_processes)
	echo "$out" | grep -c 'PID *Username'
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "Failed: Could not start smbstatus"
		echo "$out"
		return 1
	fi
	echo "$out" | grep -c "$USERNAME"
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "Failed: open connection not found"
		echo "$out"
		return 1
	fi

	out=$(cat $PREFIX/$status_shares)
	echo "$out" | grep -c 'Service *pid'
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "Failed: Could not start smbstatus"
		echo "$out"
		return 1
	fi
	echo "$out" | grep -c "tmp"
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "Failed: shares not found"
		echo "$out"
		return 1
	fi

	out=$(cat $PREFIX/$status_locks)
	echo "$out" | grep -c "Locked files:"
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "Failed: locked file not found"
		echo "$out"
		return 1
	fi
	echo "$out" | grep -c "$file"
	ret=$?
	if [ $ret -eq 1 ]; then
		echo "Failed: wrong file locked"
		echo "$out"
		return 1
	fi

	rm $PREFIX/$status_shares
	rm $PREFIX/$status_processes
	rm $PREFIX/$status_locks

	return 0
}

testit "plain" \
	test_smbstatus ||
	failed=$(expr $failed + 1)

testit "resolve_uids" \
	test_smbstatus ||
	failed=$(expr $failed + 1)

testit "test_output" \
	test_smbstatus_output ||
	failed=$(expr $failed + 1)

testok $0 $failed
