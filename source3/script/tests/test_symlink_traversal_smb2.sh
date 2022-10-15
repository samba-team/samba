#!/bin/sh

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_symlink_traversal_smb2.sh SERVER SERVER_IP USERNAME PASSWORD LOCAL_PATH PREFIX SMBCLIENT
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
file_outside_share="/tmp/symlink_traverse_test_file.$$"
dir_outside_share="/tmp/symlink_traverse_test_dir.$$"
file_outside_share_noperms="/tmp/symlink_traverse_test_file_noperm.$$"
dir_outside_share_noperms="/tmp/symlink_traverse_test_dir_noperm.$$"
#
# These two objects do not exist.
#
file_outside_share_noexist="/tmp/symlink_traverse_test_noexist.$$"
dir_outside_share_noexist="/tmp/symlink_traverse_test_dir_noexist.$$"

#
# Cleanup function.
#
do_cleanup()
{
	(
		#subshell.
		cd "$share_test_dir" || return
		rm -f "symlink_to_dot"
		rm -f "file_exists"
		rm -f "symlink_to_file_exists"
		rm -rf "dir_exists"
		rm -f "symlink_to_dir_exists"
		rm -f "symlink_noexist"
		rm -f "symlink_file_outside_share"
		rm -f "symlink_file_outside_share_noexist"
		rm -f "symlink_dir_outside_share"
		rm -f "symlink_dir_outside_share_noexist"
		rm -f "symlink_file_outside_share_noperms"
		rm -f "symlink_dir_outside_share_noperms"
		rm -rf "emptydir"
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
	ln -s "." "symlink_to_dot"
	touch "file_exists"
	ln -s "file_exists" "symlink_to_file_exists"
	mkdir "dir_exists"
	ln -s "dir_exists" "symlink_to_dir_exists"
	touch "dir_exists/subfile_exists"
	mkdir "dir_exists/subdir_exists"
	ln -s "noexist" "symlink_noexist"
	ln -s "$file_outside_share" "symlink_file_outside_share"
	ln -s "$file_outside_share_noexist" "symlink_file_outside_share_noexist"
	ln -s "$dir_outside_share" "symlink_dir_outside_share"
	ln -s "$dir_outside_share_noexist" "symlink_dir_outside_share_noexist"
	ln -s "$file_outside_share_noperms" "symlink_file_outside_share_noperms"
	ln -s "$dir_outside_share_noperms" "symlink_dir_outside_share_noperms"
	#
	# Create the identical symlink set underneath "emptydir"
	mkdir "emptydir"
	(
		#subshell
		cd "emptydir" || return
		ln -s "." "symlink_to_dot"
		touch "file_exists"
		ln -s "file_exists" "symlink_to_file_exists"
		mkdir "dir_exists"
		ln -s "dir_exists" "symlink_to_dir_exists"
		touch "dir_exists/subfile_exists"
		mkdir "dir_exists/subdir_exists"
		ln -s "noexist" "symlink_noexist"
		ln -s "$file_outside_share" "symlink_file_outside_share"
		ln -s "$file_outside_share_noexist" "symlink_file_outside_share_noexist"
		ln -s "$dir_outside_share" "symlink_dir_outside_share"
		ln -s "$dir_outside_share_noexist" "symlink_dir_outside_share_noexist"
		ln -s "$file_outside_share_noperms" "symlink_file_outside_share_noperms"
		ln -s "$dir_outside_share_noperms" "symlink_dir_outside_share_noperms"
	)
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
	mkdir "dir_inside_share_noperms/noperm_subdir_exists"
	touch "dir_inside_share_noperms/noperm_subdir_exists/noperm_subdir_file_exists"

	# Symlink pointing out of the share
	ln -s "$share_test_dir"a"/etc" x
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
$filecmd $filename1 $filename2
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

	if [ "$expected_error" = "NT_STATUS_OK" ]; then
		printf "%s" "$out" | grep -v "NT_STATUS_"
	else
		printf "%s" "$out" | grep "$expected_error"
	fi
	ret=$?
	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed - should get %s doing \"%s %s %s\"\n" "$expected_error" "$filecmd" "$filename1" "$filename2"
		return 1
	fi
}

#
# SMB2 tests.
#
test_symlink_traversal_SMB2_onename()
{
	name="$1"
	do_rename="$2"
	#
	# get commands.
	#
	smbclient_expect_error "get" "$name" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "$name/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "$name/noexistsdir/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "$name/*" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "get" "$name/*/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "get" "$name/*/noexistsdir/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	# Now in subdirectory emptydir
	smbclient_expect_error "get" "emptydir/$name" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "emptydir/$name/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "emptydir/$name/noexistsdir/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "emptydir/$name/*" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "get" "emptydir/$name/*/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "get" "emptydir/$name/*/noexistsdir/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	#
	# ls commands.
	#
	smbclient_expect_error "ls" "$name" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "$name/noexist" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "$name/noexistsdir/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "$name/*" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "$name/*/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "ls" "$name/*/noexistsdir/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	# Now in subdirectory emptydir
	smbclient_expect_error "ls" "emptydir/$name" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "emptydir/$name/noexist" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "emptydir/$name/noexistsdir/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "emptydir/$name/*" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "emptydir/$name/*/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "ls" "emptydir/$name/*/noexistsdir/noexist" "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1

	#
	# del commands.
	# smbclient internally does a cli_list, so we expect similar errors.
	#
	smbclient_expect_error "del" "$name" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "del" "$name/noexist" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	# Now in subdirectory emptydir
	smbclient_expect_error "del" "emptydir/$name" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "del" "emptydir/$name/noexist" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1

	if [ "$do_rename" = "do rename" ]; then
		#
		# rename commands.
		#
		smbclient_expect_error "rename" "file_exists" "$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "file_exists" "$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_file_exists" "$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_file_exists" "$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "dir_exists" "$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "dir_exists" "$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_dir_exists" "$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_dir_exists" "$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		# Now in subdirectory emptydir
		smbclient_expect_error "rename" "file_exists" "emptydir/$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "file_exists" "emptydir/$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_file_exists" "emptydir/$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_file_exists" "emptydir/$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "dir_exists" "emptydir/$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "dir_exists" "emptydir/$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_dir_exists" "emptydir/$name" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
		smbclient_expect_error "rename" "symlink_to_dir_exists" "emptydir/$name/noexist" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	fi
	return 0
}

#
# Check error code returns traversing through different
# kinds of symlinks over SMB2.
#
test_symlink_traversal_SMB2()
{
	test_symlink_traversal_SMB2_onename "symlink_noexist" "no rename" || return 1
	test_symlink_traversal_SMB2_onename "symlink_file_outside_share" "do rename" || return 1
	test_symlink_traversal_SMB2_onename "symlink_dir_outside_share" "do rename" || return 1
	test_symlink_traversal_SMB2_onename "symlink_dir_outside_share_noexist" "no rename" || return 1
	test_symlink_traversal_SMB2_onename "symlink_file_outside_share_noperms" "do rename" || return 1
	test_symlink_traversal_SMB2_onename "symlink_dir_outside_share_noperms" "do rename" || return 1

	# Note the share has 'follow symlinks = yes'
	smbclient_expect_error "ls" "." "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "noexist1" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "noexist1/noexist2" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dot" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_to_dot/noexist1" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "symlink_to_dot/noexist1/noexist2" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dot/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "file_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "file_exists/noexist1" "" "NT_STATUS_NOT_A_DIRECTORY" || return 1
	smbclient_expect_error "ls" "file_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "file_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_file_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_to_file_exists/noexist1" "" "NT_STATUS_NOT_A_DIRECTORY" || return 1
	smbclient_expect_error "ls" "symlink_to_file_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_file_exists/noexist1/noexist2/noexist" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "dir_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "dir_exists/noexist1" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "dir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "dir_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "dir_exists/subfile_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "dir_exists/subfile_exists/noexist1" "" "NT_STATUS_NOT_A_DIRECTORY" || return 1
	smbclient_expect_error "ls" "dir_exists/subfile_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "dir_exists/subfile_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "dir_exists/subdir_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "dir_exists/subdir_exists/noexist1" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "dir_exists/subdir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "dir_exists/subdir_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/noexist1" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subfile_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subfile_exists/noexist1" "" "NT_STATUS_NOT_A_DIRECTORY" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subfile_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subfile_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subdir_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subdir_exists/noexist1" "" "NT_STATUS_NO_SUCH_FILE" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subdir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "ls" "symlink_to_dir_exists/subdir_exists/noexist1/noexist2/noexist3" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	smbclient_expect_error "get" "." "" "NT_STATUS_OBJECT_NAME_INVALID" || return 1
	smbclient_expect_error "get" "noexist1" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dot" "" "NT_STATUS_FILE_IS_A_DIRECTORY" || return 1
	smbclient_expect_error "get" "symlink_to_dot/noexist1" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dot/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "file_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "get" "file_exists/noexist1" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "file_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_file_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "get" "symlink_to_file_exists/noexist1" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_file_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "dir_exists" "" "NT_STATUS_FILE_IS_A_DIRECTORY" || return 1
	smbclient_expect_error "get" "dir_exists/noexist1" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "dir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "dir_exists/subfile_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "get" "dir_exists/subfile_exists/noexist1" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "dir_exists/subfile_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "dir_exists/subdir_exists" "" "NT_STATUS_FILE_IS_A_DIRECTORY" || return 1
	smbclient_expect_error "get" "dir_exists/subdir_exists/noexist1" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "dir_exists/subdir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists" "" "NT_STATUS_FILE_IS_A_DIRECTORY" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/noexist1" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/subfile_exists" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/subfile_exists/noexist1" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/subfile_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/subdir_exists" "" "NT_STATUS_FILE_IS_A_DIRECTORY" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/subdir_exists/noexist1" "" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_expect_error "get" "symlink_to_dir_exists/subdir_exists/noexist1/noexist2" "" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_expect_error "get" "x/passwd" "passwd" "NT_STATUS_CONNECTION_DISCONNECTED" || return 1

	#
	# Test paths within share with no permissions.
	#
	# Can't 'get' file with no perms or a symlink to it.
	smbclient_expect_error "get" "file_inside_share_noperms" "" "NT_STATUS_ACCESS_DENIED" || return 1
	smbclient_expect_error "get" "symlink_file_inside_share_noperms" "" "NT_STATUS_ACCESS_DENIED" || return 1
	# But can list it and the symlink to it.
	smbclient_expect_error "ls" "file_inside_share_noperms" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_file_inside_share_noperms" "" "NT_STATUS_OK" || return 1
	# Can't 'get' file inside a directory with no perms or a symlink to it.
	smbclient_expect_error "get" "dir_inside_share_noperms/noperm_file_exists" "" "NT_STATUS_ACCESS_DENIED" || return 1
	smbclient_expect_error "get" "symlink_dir_inside_share_noperms/noperm_file_exists" "" "NT_STATUS_ACCESS_DENIED" || return 1
	# But can list the directory with no perms and the symlink to it.
	smbclient_expect_error "ls" "dir_inside_share_noperms" "" "NT_STATUS_OK" || return 1
	smbclient_expect_error "ls" "symlink_dir_inside_share_noperms" "" "NT_STATUS_OK" || return 1
	# Check that 'get' on non existing subpaths also returns NT_STATUS_ACCESS_DENIED
	smbclient_expect_error "get" "symlink_dir_inside_share_noperms/noperm_file_exists/_none_" "" "NT_STATUS_ACCESS_DENIED" || return 1
	smbclient_expect_error "get" "symlink_dir_inside_share_noperms/noperm_subdir_exists/noperm_subdir_file_exists" "" "NT_STATUS_ACCESS_DENIED" || return 1
	smbclient_expect_error "get" "symlink_dir_inside_share_noperms/noperm_subdir_exists/noperm_subdir_file_exists/_none_" "" "NT_STATUS_ACCESS_DENIED" || return 1
}

testit "symlink_traversal_SMB2" \
	test_symlink_traversal_SMB2 ||
	failed=$((failed + 1))

#
# Cleanup.
do_cleanup

testok "$0" "$failed"
