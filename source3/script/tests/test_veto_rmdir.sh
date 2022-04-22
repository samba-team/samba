#!/bin/sh
#
# Check smbclient can (or cannot) delete a directory containing veto files.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=14878
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
. "$incdir"/subunit.sh

failed=0

rmdir_path="$SHAREPATH/dir"

test_veto_nodelete_rmdir()
{
	local veto_path="$rmdir_path/veto_name1"
	local msdfs_link_path="$rmdir_path/dfs_link"
	local tmpfile=$PREFIX/smbclient.in.$$

	# Create rmdir directory.
	mkdir -p "$rmdir_path"
	# Create veto file underneath.
	touch "$veto_path"
	# Create msdfs link underneath.
	ln -s "msdfs:$SERVER_IP\\ro-tmp" "$msdfs_link_path"

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

	# We should only see the dfs_link file.
	echo "$out" | grep dfs_link
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to see dfs_link in share veto_files_nodelete"
		echo "$out"
		return 1
	fi

	# Now remove the dfs_link file.
	rm -rf "$msdfs_link_path"

	# Try and remove the directory, should fail with NT_STATUS_DIRECTORY_NOT_EMPTY.
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

	# We should get NT_STATUS_DIRECTORY_NOT_EMPTY.
	echo "$out" | grep NT_STATUS_DIRECTORY_NOT_EMPTY
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to get error NT_STATUS_DIRECTORY_NOT_EMPTY in share veto_files_nodelete"
		echo "$out"
		return 1
	fi

	# remove the veto file - directory should now be empty.
	rm -rf "$veto_path"

	# Try and remove the directory, should now succeed.
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

	# We should get no NT_STATUS_ errors.
	echo "$out" | grep NT_STATUS_
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Got error NT_STATUS_ in share veto_files_nodelete"
		echo "$out"
		return 1
	fi

	return 0
}

test_veto_delete_rmdir()
{
	local veto_path="$rmdir_path/veto_name1"
	local msdfs_link_path="$rmdir_path/dfs_link"
	local tmpfile=$PREFIX/smbclient.in.$$

	# Create rmdir directory.
	mkdir -p "$rmdir_path"
	# Create veto file underneath.
	touch "$veto_path"
	# Create msdfs link underneath.
	ln -s "msdfs:$SERVER_IP\\ro-tmp" "$msdfs_link_path"

	cat >"$tmpfile" <<EOF
cd dir
ls
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/veto_files_delete -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share veto_files_delete - $ret"
		echo "$out"
		return 1
	fi

	# We should only see the dfs_link file.
	echo "$out" | grep dfs_link
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to see dfs_link in share veto_files_delete"
		echo "$out"
		return 1
	fi

	# Now remove the dfs_link file.
	rm -rf "$msdfs_link_path"

	# Try and remove the directory, should now succeed.
	cat >"$tmpfile" <<EOF
rd dir
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/veto_files_delete -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	if [ $ret != 0 ]; then
		echo "Failed accessing share veto_files_delete - $ret"
		echo "$out"
		return 1
	fi

	# We should get no NT_STATUS_ errors.
	echo "$out" | grep NT_STATUS_
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Got error NT_STATUS_ in share veto_files_delete"
		echo "$out"
		return 1
	fi

	return 0
}

testit "rmdir cannot delete directory containing a veto file" \
	test_veto_nodelete_rmdir || failed=$(expr "$failed" + 1)

rm -rf "$rmdir_path"

testit "rmdir can delete directory containing a veto file" \
	test_veto_delete_rmdir || failed=$(expr "$failed" + 1)

rm -rf "$rmdir_path"

exit "$failed"
