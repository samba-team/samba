#!/bin/sh

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_symlink_dosmode.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT
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
shift 6

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

failed=0

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

# Define the test environment/filenames.
#
share_test_dir="$LOCAL_PATH"

rm -rf "$share_test_dir/testdir"

mkdir -p "$share_test_dir/testdir/dir"
touch "$share_test_dir/testdir/file"
ln -s "../file" "$share_test_dir/testdir/dir/symlink"

test_symlink_dosmode()
{
	tmpfile=$PREFIX/smbclient_interactive_prompt_commands
	cat >"$tmpfile" <<EOF
ls testdir/dir/*
quit
EOF
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/local_symlinks -I$SERVER_IP < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed accessing local_symlinks with error %s\n" "$ret"
		return 1
	fi

	mode=$(printf "%s" "$out" | awk '/symlink/ {print $2}')
	echo "mode: $mode"
	if [ x"$mode" != x"N" ] ; then
		printf "Bad mode: '%s', expected 'N'\n" "$mode"
		printf "%s\n" "$out"
		return 1
	fi
	return 0
}

testit "symlink_dosmode" \
	test_symlink_dosmode ||
	failed=$((failed + 1))

rm -rf "$share_test_dir/testdir"

testok "$0" "$failed"
