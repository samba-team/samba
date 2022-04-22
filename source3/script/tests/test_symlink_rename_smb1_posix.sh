#!/bin/sh

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_symlink_rename_smb1_posix.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT
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
#
# These files/directories will be created.
#
file_outside_share="/tmp/symlink_rename_test_file.$$"
dir_outside_share="/tmp/symlink_rename_test_dir.$$"
file_outside_share_noperms="/tmp/symlink_rename_test_file_noperm.$$"
dir_outside_share_noperms="/tmp/symlink_rename_test_dir_noperm.$$"
#
# These two objects do not exist.
#
file_outside_share_noexist="/tmp/symlink_rename_test_noexist.$$"
dir_outside_share_noexist="/tmp/symlink_rename_test_dir_noexist.$$"

#
# Cleanup function.
#
do_cleanup()
{
	(
		#subshell.
		cd "$share_test_dir" || return
		rm -f "file_exists"
		rm -f "symlink_noexist"
		rm -f "symlink_file_outside_share"
		rm -f "symlink_file_outside_share_noexist"
		rm -f "symlink_dir_outside_share"
		rm -f "symlink_dir_outside_share_noexist"
		rm -f "symlink_file_outside_share_noperms"
		rm -f "symlink_dir_outside_share_noperms"
		# Links inside share.
		rm -f "symlink_file_inside_share_noperms"
		rm -f "file_inside_share_noperms"
		rm -f "symlink_dir_inside_share_noperms"
		chmod 755 "dir_inside_share_noperms"
		rm -rf "dir_inside_share_noperms"
	)
	rm -f "$file_outside_share"
	rm -rf "$dir_outside_share"
	rm -f "$file_outside_share_noperms"
	rm -rf "$dir_outside_share_noperms"
}

#
# Ensure we start from a clean slate.
#
do_cleanup

#
# Create the test files/directories/symlinks.
#
# File/directory explicitly outside share.
touch "$file_outside_share"
mkdir "$dir_outside_share"
# File/directory explicitly outside share with permission denied.
touch "$file_outside_share_noperms"
chmod 0 "$file_outside_share_noperms"
mkdir "$dir_outside_share_noperms"
chmod 0 "$dir_outside_share_noperms"
#
# Create links to these objects inside the share definition.
(
	#subshell.
	cd "$share_test_dir" || return
	# Source file for all renames. None of these should succeed.
	touch "file_exists"
	ln -s "noexist" "symlink_noexist"
	ln -s "$file_outside_share" "symlink_file_outside_share"
	ln -s "$file_outside_share_noexist" "symlink_file_outside_share_noexist"
	ln -s "$dir_outside_share" "symlink_dir_outside_share"
	ln -s "$dir_outside_share_noexist" "symlink_dir_outside_share_noexist"
	ln -s "$file_outside_share_noperms" "symlink_file_outside_share_noperms"
	ln -s "$dir_outside_share_noperms" "symlink_dir_outside_share_noperms"
	#
	# Create symlinks to access denied file and directory
	# objects within the share
	touch "file_inside_share_noperms"
	chmod 0 "file_inside_share_noperms"
	ln -s "file_inside_share_noperms" "symlink_file_inside_share_noperms"
	mkdir "dir_inside_share_noperms"
	touch "dir_inside_share_noperms/noperm_file_exists"
	chmod 0 "dir_inside_share_noperms"
	ln -s "dir_inside_share_noperms" "symlink_dir_inside_share_noperms"
)

#
# smbclient function given command, path, expected error, and posix.
#
smbclient_expect_error()
{
	filecmd="$1"
	filename1="$2"
	filename2="$3"
	expected_error="$4"
	tmpfile=$PREFIX/smbclient_interactive_prompt_commands
	cat >"$tmpfile" <<EOF
posix
$filecmd $filename1 $filename2
quit
EOF
	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/local_symlinks -I$SERVER_IP -mNT1 < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed accessing local_symlinks with error %s\n" "$ret"
		return 1
	fi

	if [ "$expected_error" = "NT_STATUS_OK" ]; then
		printf "%s" "$out" | grep -v "NT_STATUS_"
	else
		printf "%s" "$out" | grep "$expected_error"
	fi
	ret=$?
	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed - should get %s doing posix \"%s %s %s\"\n" "$expected_error" "$filecmd" "$filename1" "$filename2"
		return 1
	fi
}

#
# SMB1+posix tests.
#
test_symlink_rename_SMB1_posix()
{
	#
	# rename commands.
	# As all the targets exist as symlinks, these should all fail.
	#
	smbclient_expect_error "rename" "file_exists" "symlink_noexist" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_file_outside_share" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_file_outside_share_noexist" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_dir_outside_share" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_dir_outside_share_noexist" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_file_outside_share_noperms" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_dir_outside_share_noperms" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_file_inside_share_noperms" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	smbclient_expect_error "rename" "file_exists" "symlink_dir_inside_share_noperms" "NT_STATUS_OBJECT_NAME_COLLISION" || return 1
	return 0
}

testit "symlink_rename_SMB1_posix" \
	test_symlink_rename_SMB1_posix ||
	failed=$((failed + 1))

#
# Cleanup.
do_cleanup

testok "$0" "$failed"
