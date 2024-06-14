#!/bin/sh

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_recycle.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT ADDARGS
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

#
# Cleanup function.
#
do_cleanup()
{
	(
		#subshell.
		cd "$share_test_dir" || return
		rm -f testfile1
		rm -f testfile2.tmp
		rm -rf .trash
	)
}

#
# Ensure we start from a clean slate.
#
do_cleanup


test_recycle()
{
	tmpfile=$PREFIX/smbclient_interactive_prompt_commands
	echo "
put $tmpfile testfile1
put $tmpfile testfile2.tmp
del testfile1
del testfile2.tmp
quit
" > $tmpfile
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/recycle -I$SERVER_IP $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed recycle smbclient run with error %s\n" "$ret"
		return 1
	fi

	test -e "$share_test_dir/.trash/testfile1" || {
		printf ".trash/testfile1 expected to exist but does NOT exist\n"
		return 1
	}
	test -e "$share_test_dir/.trash/testfile2.tmp" && {
		printf ".trash/testfile2.tmp not expected to exist but DOES exist\n"
		return 1
	}
	perm_want=755
	perm_is=`stat -c '%a' "$share_test_dir/.trash/"`
	test "$perm_is" = "$perm_want" || {
		printf ".trash/ permission should be $perm_want but is $perm_is\n"
		return 1
	}
	return 0
}

panic_count_0=$(grep -c PANIC $SMBD_TEST_LOG)

testit "recycle" \
	test_recycle ||
	failed=$((failed + 1))

panic_count_1=$(grep -c PANIC $SMBD_TEST_LOG)

testit "check_panic" test $panic_count_0 -eq $panic_count_1 || failed=$(expr $failed + 1)

#
# Cleanup.
do_cleanup

testok "$0" "$failed"
