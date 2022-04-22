#!/bin/sh
#
# Check smbclient can (or cannot) delete a directory containing dangling symlinks.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14879
#

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: $0 SERVER SERVER_IP USERNAME PASSWORD SHAREPATH SMBCLIENT
EOF
	exit 1
fi

SERVER=${1}
SERVER_IP=${2}
USERNAME=${3}
PASSWORD=${4}
SHAREPATH=${5}
SMBCLIENT=${6}
shift 6
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$@"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

rmdir_path="$SHAREPATH/dir"

#
# Using the share "[delete_veto_files_only]" we CAN delete
# a directory containing only a dangling symlink.
#
test_dangle_symlink_delete_veto_rmdir()
{
	local dangle_symlink_path="$rmdir_path/bad_link"
	local tmpfile=$PREFIX/smbclient.in.$$

	# Create rmdir directory.
	mkdir -p "$rmdir_path"
	# Create dangling symlink underneath.
	ln -s "nowhere-foo" "$dangle_symlink_path"

	cat >"$tmpfile" <<EOF
cd dir
ls
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/delete_veto_files_only -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share delete_veto_files_only - $ret"
		echo "$out"
		return 1
	fi

	# We should NOT see the dangling symlink file.
	echo "$out" | grep bad_link
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Saw dangling symlink bad_link in share delete_veto_files_only"
		echo "$out"
		return 1
	fi

	# Try and remove the directory, should succeed.
	cat >"$tmpfile" <<EOF
rd dir
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/delete_veto_files_only -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share delete_veto_files_only - $ret"
		echo "$out"
		return 1
	fi

	# We should get no NT_STATUS_ errors.
	echo "$out" | grep NT_STATUS_
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Got error NT_STATUS_ in share delete_veto_files_only"
		echo "$out"
		return 1
	fi

	return 0
}

#
# Using the share "[veto_files_nodelete]" we CANNOT delete
# a directory containing only a dangling symlink.
#
test_dangle_symlink_veto_files_nodelete()
{
	local dangle_symlink_path="$rmdir_path/bad_link"
	local tmpfile=$PREFIX/smbclient.in.$$

	# Create rmdir directory.
	mkdir -p "$rmdir_path"
	# Create dangling symlink underneath.
	ln -s "nowhere-foo" "$dangle_symlink_path"

	cat >"$tmpfile" <<EOF
cd dir
ls
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/veto_files_nodelete -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share veto_files_nodelete - $ret"
		echo "$out"
		return 1
	fi

	# We should NOT see the dangling symlink file.
	echo "$out" | grep bad_link
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Saw dangling symlink bad_link in share veto_files_nodelete"
		echo "$out"
		return 1
	fi

	# Try and remove the directory, should fail with DIRECTORY_NOT_EMPTY.
	cat >"$tmpfile" <<EOF
rd dir
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/veto_files_nodelete -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share veto_files_nodelete - $ret"
		echo "$out"
		return 1
	fi

	# We should get NT_STATUS_DIRECTORY_NOT_EMPTY errors.
	echo "$out" | grep NT_STATUS_DIRECTORY_NOT_EMPTY
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Should get NT_STATUS_DIRECTORY_NOT_EMPTY in share veto_files_nodelete"
		echo "$out"
		return 1
	fi

	return 0
}

testit "rmdir can delete directory containing dangling symlink" \
	test_dangle_symlink_delete_veto_rmdir || failed=$(expr "$failed" + 1)

rm -rf "$rmdir_path"

testit "rmdir cannot delete directory delete_veto_files_no containing dangling symlink" \
	test_dangle_symlink_veto_files_nodelete || failed=$(expr "$failed" + 1)

rm -rf "$rmdir_path"
exit "$failed"
