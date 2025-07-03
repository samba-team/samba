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
lcd $PREFIX
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

	echo "$out" | grep "${userid}[ ]*DENY_NONE"
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
lcd $PREFIX
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

	echo "$out" | grep "${USERNAME}[ ]*DENY_NONE"
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
lcd $PREFIX
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

test_smbstatus_json()
{
	local cmdfile=$PREFIX/smbclient_commands
	local tmpfile=$PREFIX/smbclient_lock_file
	local file=smbclient_lock_file
	local status_json=smbstatus_output_json
	local status_json_long=smbstatus_output_json_long

	cat > $tmpfile <<EOF
Hello World!
EOF
	cat > $cmdfile <<EOF
lcd $PREFIX
put $file
open $file
posix
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --json > $status_json
!UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --json -vBN > $status_json_long
close 1
rm $file
quit
EOF

	cmd="CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/tmp -I $SERVER_IP $ADDARGS --quiet < $cmdfile 2>&1"
	out=$(eval $cmd)
	echo $out
	ret=$?

	rm -f $cmdfile
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to run smbclient with error $ret"
		echo "$out"
		return 1
	fi

	echo $out | grep -c 'JSON support not available, please install lib Jansson'
	ret=$?
	if [ $ret -eq 0 ]; then
		subunit_start_test "test_smbstatus_json"
		subunit_skip_test "test_smbstatus_json" <<EOF
Test needs Jansson
EOF
		return 0
	fi

	out=$(cat $PREFIX/$status_json)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed: Could not print json output with error $ret"
		echo "$out"
		return 1
	fi

	out=$(cat $PREFIX/$status_json | jq ".")
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed: Could not parse json output from smbstatus with error $ret"
		echo "$out"
		return 1
	fi

	# keys in --json
	expected='["open_files","sessions","smb_conf","tcons","timestamp","version"]'
	out=$(cat $PREFIX/$status_json | jq keys -c)
	if [ "$expected" != "$out" ]; then
		echo "Failed: Unexpected keys in smbstatus --json"
		echo "Expected: $expected"
		echo "Output: $out"
		return 1
	fi

	# keys in --json -vBN
	expected='["byte_range_locks","notifies","open_files","sessions","smb_conf","tcons","timestamp","version"]'
	out=$(cat $PREFIX/$status_json_long | jq keys -c)
	if [ "$expected" != "$out" ]; then
		echo "Failed: Unexpected keys in smbstatus --json"
		echo "Expected: $expected"
		echo "Output: $out"
		return 1
	fi

	# shares information in --json
	out=$(cat $PREFIX/$status_json | jq ".tcons|.[].machine")
	if [ "\"$SERVER_IP\"" != "$out" ]; then
		echo "Failed: Unexpected value for tcons.machine in smbstatus --json"
		echo "Expected: $SERVER_IP"
		echo "Output: $out"
		return 1
	fi
	out=$(cat $PREFIX/$status_json | jq ".tcons|.[].service")
	if [ '"tmp"' != "$out" ]; then
		echo "Failed: Unexpected value for tcons.service in smbstatus --json"
		echo "Expected: tmp"
		echo "Output: $out"
		return 1
	fi

	# session information in --json
	out=$(cat $PREFIX/$status_json | jq ".sessions|.[].username")
	if [ "\"$USER\"" != "$out" ]; then
		echo "Failed: Unexpected value for sessions.username in smbstatus --json"
		echo "Expected: $USER"
		echo "Output: $out"
		return 1
	fi
	out=$(cat $PREFIX/$status_json | jq -c ".sessions|.[].signing")
	expected='{"cipher":"AES-128-GMAC","degree":"partial"}'
	if [ "$expected" != "$out" ]; then
		echo "Failed: Unexpected value for sessions.signing in smbstatus --json"
		echo "Expected: partial(AES-128-GMAC)"
		echo "Output: $out"
		return 1
	fi
	out=$(cat $PREFIX/$status_json | jq ".sessions|.[].remote_machine")
	if [ "\"$SERVER_IP\"" != "$out" ]; then
		echo "Failed: Unexpected value for sessions.remote_machine in smbstatus --json"
		echo "Expected: $SERVER_IP"
		echo "Output: $out"
		return 1
	fi

	# open_files information in --json
	out=$(cat $PREFIX/$status_json | jq ".open_files|.[].filename")
	if [ "\"$file\"" != "$out" ]; then
		echo "Failed: Unexpected value for open_files.denymode in smbstatus --json"
		echo "Expected: \"$file\""
		echo "Output: $out"
		return 1
	fi
	out=$(cat $PREFIX/$status_json | jq ".open_files|.[].opens|.[].access_mask.hex")
	if [ '"0x00000003"' != "$out" ]; then
		echo "Failed: Unexpected value for open_files.access_mask.hex in smbstatus --json"
		echo "Expected: 0x00000003"
		echo "Output: $out"
		return 1
	fi

	rm $PREFIX/$status_json
	rm $PREFIX/$status_json_long

	return 0
}
test_smbstatus_json_profile()
{
	local status_json=smbstatus_output_json_profile

	cmd="UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $SMBSTATUS --json --profile > $PREFIX/$status_json"
	out=$(eval $cmd)
	ret=$?

	if [ $ret -ne 0 ]; then
		echo "Failed to run smbstatus -jP with error $ret"
		echo "$out"
		return 1
	fi

	echo $out | grep -c 'JSON support not available, please install lib Jansson'
	ret=$?
	if [ $ret -eq 0 ]; then
		subunit_start_test "test_smbstatus_json_profile"
		subunit_skip_test "test_smbstatus_json_profile" <<EOF
Test needs Jansson
EOF
		return 0
	fi

	out=$(cat $PREFIX/$status_json)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed: Could not print json profile output with error $ret"
		echo "$out"
		return 1
	fi

	out=$(cat $PREFIX/$status_json | jq ".")
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed: Could not parse json output from smbstatus -jP with error $ret"
		echo "$out"
		return 1
	fi

	# keys in --json --profile
	expected='["ACL Calls","Authentication","NT Transact Calls","SMB Calls","SMB2 Calls","SMBD loop","Stat Cache","System Calls","Trans2 Calls","smb_conf","timestamp","version"]'
	out=$(cat $PREFIX/$status_json | jq keys -c)
	if [ "$expected" != "$out" ]; then
		echo "Failed: Unexpected keys in smbstatus -jP"
		echo "Expected: $expected"
		echo "Output: $out"
		return 1
	fi

	# keys in ACL Calls
	expected='["fget_nt_acl","fset_nt_acl","get_nt_acl","get_nt_acl_at"]'
	out=$(cat $PREFIX/$status_json | jq -c '."ACL Calls"|keys')
	if [ "$expected" != "$out" ]; then
		echo "Failed: Unexpected keys in smbstatus -jP"
		echo "Expected: $expected"
		echo "Output: $out"
		return 1
	fi

	# keys in ACL Calls, fget_nt_acl
	expected='["count","time"]'
	out=$(cat $PREFIX/$status_json | jq -c '."ACL Calls"."fget_nt_acl"|keys')
	if [ "$expected" != "$out" ]; then
		echo "Failed: Unexpected keys in smbstatus -jP"
		echo "Expected: $expected"
		echo "Output: $out"
		return 1
	fi

	rm $PREFIX/$status_json

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

testit "test_json" \
	test_smbstatus_json || \
	failed=`expr $failed + 1`

testit "test_json_profile" \
	test_smbstatus_json_profile || \
	failed=`expr $failed + 1`

testok $0 $failed
