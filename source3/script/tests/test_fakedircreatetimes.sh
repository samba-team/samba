#!/bin/sh

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_fakedircreatetimes.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT ADDARGS
EOF
	exit 1
fi

SERVER="${1}"
SERVER_IP="${2}"
USERNAME="${3}"
PASSWORD="${4}"
LOCAL_PATH="${5}"
PREFIX="${6}"
SMBCLIENT="${7}"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 7
ADDARGS="$*"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

failed=0

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

# Define the test environment/filenames.
#
share_test_dir="$LOCAL_PATH"


test_fakedircreatetimes()
{
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/recycle -I$SERVER_IP $ADDARGS < $tmpfile 2>&1'
	cmd="LC_ALL=C TZ=UTC CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/fakedircreatetimes -I$SERVER_IP $ADDARGS -c 'allinfo \\'"
	eval echo "$cmd"
	out=$(eval "$cmd")

	ret=$?

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed recycle smbclient run with error %s\n" "$ret"
		return 1
	fi

	echo "$out" | grep -q "create_time:.*1979 UTC" && {
		return 0
	}

	echo "ERROR: create_time does not match 1979 UTC:"
	echo "$out"
	return 1
}


testit "fakedircreatetimes" \
	test_fakedircreatetimes ||
	failed=$((failed + 1))


testok "$0" "$failed"
