#!/bin/sh

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_worm.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT ADDARGS
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
		rm -f must-be-deleted must-not-be-deleted must-be-deleted-after-ctime-refresh
		rm -f must-not-be-overwritten sentinel-value
	)
	rm -f $tmpfile
}

#
# Ensure we start from a clean slate.
#
do_cleanup

tmpfile=$PREFIX/smbclient_interactive_prompt_commands

tmp_sentinel=$PREFIX/sentinel_value
SENTINEL_VALUE='1'
echo $SENTINEL_VALUE > $tmp_sentinel

test_worm()
{
	# use echo because helo scripts don't support variables
	echo "
put $tmpfile must-be-deleted
put $tmpfile must-be-deleted-after-ctime-refresh
put $tmpfile must-not-be-deleted
put $tmpfile must-not-be-overwritten
del must-be-deleted
quit" > $tmpfile
	# make sure the directory is not too old for worm:
	touch $share_test_dir
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/worm -I$SERVER_IP $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed worm smbclient run with error %s\n" "$ret"
		return 1
	fi
	test -e $share_test_dir/must-be-deleted && {
		printf "$0: ERROR: must-be-deleted was NOT deleted\n"
		return 1
	}

	# now sleep grace_period (1s) and check if worm works properly:
	sleep 1
	echo "
posix
chmod 700 must-not-be-deleted
del must-not-be-deleted
del must-be-deleted-after-ctime-refresh
quit" > $tmpfile
	# make sure the directory itself is not too old for worm:
	touch $share_test_dir
	# set a fresh ctime by doing a chmod:
	chmod 644 $share_test_dir/must-be-deleted-after-ctime-refresh
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/worm -I$SERVER_IP $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	test -e $share_test_dir/must-not-be-deleted || {
		printf "$0: ERROR: must-not-be-deleted WAS deleted\n"
		return 1
	}

	# Check we can't change a protected file by renaming over it.
	# The source file needs to recently created or access will be
	# denied before RENAME_AT is reached, which is the thing we
	# want to test.
	original_contents=`cat $share_test_dir/must-not-be-overwritten`
	echo "
put $tmp_sentinel sentinel-value
rename sentinel-value must-not-be-overwritten  -f
quit" > $tmpfile
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/worm -I$SERVER_IP $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	new_contents=`cat $share_test_dir/must-not-be-overwritten`

	if [ "$new_contents" = "$SENTINEL_VALUE" ]; then
	    echo "must-not-be-overwritten was overwritten"
	    return 1
	fi
	if [ "$new_contents" != "$original_contents" ]; then
	    echo "must-not-be-overwritten was changed (but not precisely overwritten)"
	    return 1
	fi

	# if we're not root, return here:
	test "$UID" = "0" ||  {
		return 0
	}

	test -e $share_test_dir/must-be-deleted-after-ctime-refresh && {
		printf "$0: ERROR: must-be-deleted-after-ctime-refresh was NOT deleted\n"
		return 1
	}
	return 0
}


testit "worm" \
	test_worm ||
	failed=$((failed + 1))

#
# Cleanup.
do_cleanup

testok "$0" "$failed"
