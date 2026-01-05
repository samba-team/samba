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
share_test_dir="$LOCAL_PATH/recycle"
share_test_dir2="$LOCAL_PATH/recycle2"

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
		rm -f test_mtime
		rm -rf .trash
	)
	(
		#subshell.
		cd "$share_test_dir2" || return
		rm -f testfile3
		rm -f testfile4.tmp
		rm -rf .trash
	)
}

#
# Ensure we start from a clean slate.
#
do_cleanup

# Setup .trash on a different filesystem to test crossrename
# /tmp or /dev/shm should provide tmpfs
#
for T in /tmp /dev/shm
do
	if df --portability --print-type $T 2>/dev/null | grep -q tmpfs; then
		TRASHDIR=$T
		break
	fi
done

if [ -z $TRASHDIR ]; then
	echo "No tmpfs filesystem found."
	exit 1
fi

TRASHDIR=$(mktemp -d /$TRASHDIR/.trash_XXXXXX)
chmod 0755 $TRASHDIR
ln -s $TRASHDIR $share_test_dir2/.trash

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

test_touch()
{
	tmpfile=$PREFIX/test_mtime
	touch "$tmpfile"
	if ! $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/recycle -I$SERVER_IP $ADDARGS -c "put $tmpfile test_mtime" ; then
		printf "failed recycle smbclient"
		return 1
	fi
	rm -f "$tmpfile"
	atime1=`stat -c '%x' "$share_test_dir/test_mtime"`
	mtime1=`stat -c '%y' "$share_test_dir/test_mtime"`
	sleep 1
	if ! $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/recycle -I$SERVER_IP $ADDARGS -c 'del test_mtime' ; then
		printf "failed recycle smbclient"
		return 1
	fi
	test -e "$share_test_dir/.trash/test_mtime" || {
		printf ".trash/test_mtime expected to exist but does NOT exist\n"
		return 1
	}
	atime2=`stat -c '%x' "$share_test_dir/.trash/test_mtime"`
	mtime2=`stat -c '%y' "$share_test_dir/.trash/test_mtime"`
	test "$atime1" != "$atime2" || {
		printf "recycle:touch failed: atime should differ: $atime1, $atime2\n"
		return 1
	}
	test "$mtime1" != "$mtime2" || {
		printf "recycle:touch_mtime failed: mtime should differ: $mtime1, $mtime2\n"
		return 1
	}
	return 0
}

test_recycle_crossrename()
{
	tmpfile=$PREFIX/smbclient_interactive_prompt_commands
	echo "
put $tmpfile testfile3
put $tmpfile testfile4.tmp
del testfile3
del testfile4.tmp
quit
" > $tmpfile
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/recycle2 -I$SERVER_IP $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed recycle smbclient run with error %s\n" "$ret"
		return 1
	fi

	test -e "$share_test_dir2/.trash/testfile3" || {
		printf ".trash/testfile3 expected to exist but does NOT exist\n"
		return 1
	}
	test -e "$share_test_dir2/.trash/testfile4.tmp" && {
		printf ".trash/testfile4.tmp not expected to exist but DOES exist\n"
		return 1
	}
	deviceid1=`stat -c '%d' "$share_test_dir2/"`
	deviceid2=`stat -c '%d' "$share_test_dir2/.trash/"`
	test "$deviceid1=" != "$deviceid2" || {
		printf ".trash/ should be on a different filesystem!\n"
		return 1
	}
	perm_want=755
	perm_is=`stat -c '%a' "$share_test_dir2/.trash/"`
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

testit "recycle_touch" \
	test_touch ||
	failed=$((failed + 1))

testit "recycle_crossrename" \
	test_recycle_crossrename ||
	failed=$((failed + 1))

panic_count_1=$(grep -c PANIC $SMBD_TEST_LOG)

testit "check_panic" test $panic_count_0 -eq $panic_count_1 || failed=$(expr $failed + 1)

#
# Cleanup.
do_cleanup
# Cleanup above only deletes a symlink, delete also /tmp/.trash_XXXXXX dir
rm -rf "$TRASHDIR"

testok "$0" "$failed"
