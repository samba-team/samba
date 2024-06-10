#!/bin/sh

# regression test for dfs access with wide links enabled on dfs share
# Ensure we still maintain case insensitivity.

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_widelink_dfs_ci.sh SERVER SERVER_IP SHARE USERNAME PASSWORD PREFIX SMBCLIENT <smbclient arguments>
EOF
	exit 1
fi

SERVER="$1"
SERVER_IP="$2"
SHARE="$3"
USERNAME="$4"
PASSWORD="$5"
PREFIX="$6"
SMBCLIENT="$7"
shift 7
ADDARGS="$@"

incdir=$(dirname "$0")"/../../../testprogs/blackbox"
. "$incdir/subunit.sh"
. "$incdir/common_test_fns.inc"

failed=0

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

# Test chdir'ing into a lowercase directory with upper case.
test_ci()
{
        tmpfile="$PREFIX/smbclient_ci_commands"

        cat >"$tmpfile" <<EOF
mkdir x
cd X
cd ..
rmdir x
quit
EOF

        cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/msdfs-share-wl -I $SERVER_IP $ADDARGS < $tmpfile 2>&1'
        eval echo "$cmd"
        out=$(eval "$cmd")
        ret=$?
        rm -f "$tmpfile"

        if [ $ret != 0 ]; then
                echo "$out"
                echo "failed create x then chdir into X with error $ret"
                return 1
        fi

	echo "$out" | grep 'NT_STATUS_'
	ret="$?"
	if [ "$ret" -eq 0 ]; then
		echo "$out"
		echo "Error create x then chdir into X"
		return 1
        fi
	return 0
}

testit "creating a directory x and chdir into it" \
        test_ci ||
	failed=$((failed + 1))

testok "$0" "$failed"
