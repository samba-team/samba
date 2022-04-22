#!/bin/sh
#
# Ensure we don't get an error smb1cli_req_writev_submit: called for dialect[SMB3_11]
# when listing servers via -L.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14939

if [ $# -lt 5 ]; then
	cat <<EOF
Usage: test_smbclient_list_servers.sh SERVER SERVER_IP USERNAME PASSWORD SMBCLIENT
EOF
	exit 1
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
SMBCLIENT="$5"
shift 5
ADDARGS="$@"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir/subunit.sh"

failed=0

test_smbclient_list_servers()
{
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -L //$SERVER -U$USERNAME%$PASSWORD -I $SERVER_IP -p139 "$ADDARGS" </dev/null 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")

	echo "$out" | grep 'smb1cli_req_writev_submit:'
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "$out"
		echo 'failed - should not get: smb1cli_req_writev_submit: error.'
		return 1
	fi

	return 0
}

testit "smb1_list_servers" test_smbclient_list_servers || failed=$((failed + 1))
testok "$0" "$failed"
