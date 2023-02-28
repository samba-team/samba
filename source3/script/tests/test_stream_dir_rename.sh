#!/bin/sh
#
# Test a stream can rename a directory once an invalid stream path below it was requested.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15314

if [ $# -lt 5 ]; then
        cat <<EOF
Usage: test_stream_dir_rename.sh SERVER USERNAME PASSWORD PREFIX SMBCLIENT
EOF
        exit 1
fi

SERVER="${1}"
USERNAME="${2}"
PASSWORD="${3}"
PREFIX="${4}"
SMBCLIENT="${5}"
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
shift 5

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

test_stream_xattr_rename()
{
	tmpfile=$PREFIX/smbclient_interactive_prompt_commands
	#
	# Test against streams_xattr_nostrict
	#
	cat >$tmpfile <<EOF
deltree stream_xattr_test
deltree stream_xattr_test1
mkdir stream_xattr_test
put ${PREFIX}/smbclient_interactive_prompt_commands stream_xattr_test/file.txt
get stream_xattr_test/file.txt:abcf
rename stream_xattr_test stream_xattr_test1
deltree stream_xattr_test
deltree stream_xattr_test1
quit
EOF
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT "$@" -U$USERNAME%$PASSWORD //$SERVER/streams_xattr_nostrict < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "$out"
		echo "failed rename on xattr stream test to test1 with error $ret"
		return 1
	fi

	echo "$out" | grep "NT_STATUS_ACCESS_DENIED"
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "$out"
		echo "failed rename on xattr stream with NT_STATUS_ACCESS_DENIED"
		return 1
	fi
}

testit "stream_rename" \
	test_stream_xattr_rename ||
	failed=$((failed + 1))

testok "$0" "$failed"
