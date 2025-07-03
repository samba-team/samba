#!/bin/sh
#
# Check smbclient cannot get a file that matches a veto files
# parameter, or inside a directory that matches a veto files
# parameter.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15143
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
# Used by test_smbclient()
# shellcheck disable=2034
smbclient="$VALGRIND ${SMBCLIENT}"
ADDARGS="$@"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh
. "${incdir}/common_test_fns.inc"

failed=0

TMPDIR=${PREFIX}/$(basename "${0}")
mkdir -p "${TMPDIR}" || exit 1
cd "${TMPDIR}" || exit 1

#
# Cleanup function.
#
do_cleanup()
{
	(
		#subshell.
		rm -rf "$SHAREPATH/dir1"
		rm -rf "$SHAREPATH/veto_name_dir"
		rm -rf "$SHAREPATH/veto_name_dir\"mangle"
		rm -f "$SHAREPATH/veto_name_file"
		rm -f "$SHAREPATH/veto_name_file\"mangle"
		rm -f "${SHAREPATH}/regular_file"
		rm -f "${SHAREPATH}/.hidden_file"
	)
}

#
# smbclient function given path and expected error.
#
smbclient_get_expect_error()
{
	filename1="$1"
	expected_error="$2"
	tmpfile=${TMPDIR}/smbclient_interactive_prompt_commands
	cat >"$tmpfile" <<EOF
get $filename1 got_file
quit
EOF
	rm -f got_file

	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/veto_files -I$SERVER_IP < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"
	rm -f got_file

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed accessing veto_files share with error %s\n" "$ret"
		return 1
	fi

	if [ "$expected_error" = "NT_STATUS_OK" ]; then
		printf "%s" "$out" | grep "NT_STATUS_" | wc -l | grep '^0$'
	else
		printf "%s" "$out" | grep "$expected_error"
	fi
	ret=$?
	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed - should get %s doing \"get %s got_file\"\n" "$expected_error" "$filename1"
		return 1
	fi
}

smbclient_create_expect_error()
{
	filename="$1.$$"
	expected_error="$2"
	tmpfile=${TMPDIR}/smbclient_interactive_prompt_commands
	cat >"$tmpfile" <<EOF
put $tmpfile $filename
quit
EOF

	cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/veto_files -I$SERVER_IP < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	rm -f "$tmpfile"
	rm -f "$SHAREPATH/$filename"

	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed accessing veto_files share with error %s\n" "$ret"
		return 1
	fi

	if [ "$expected_error" = "NT_STATUS_OK" ]; then
		printf "%s" "$out" | grep -c "NT_STATUS_" && false
	else
		printf "%s" "$out" | grep "$expected_error"
	fi
	ret=$?
	if [ $ret != 0 ]; then
		printf "%s\n" "$out"
		printf "failed - should get %s doing \"put %s\"\n" "$expected_error" "$filename"
		return 1
	fi
}

#
# Using the share "[veto_files]" ensure we
# cannot fetch a veto'd file or file in a veto'd directory.
#
test_get_veto_file()
{
	# toplevel
	smbclient_get_expect_error "veto_name_file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "veto_name_dir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "veto_name_dir/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# toplevel mangle names
	smbclient_get_expect_error "VHXE5P~M" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "VF5SKC~B/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "VF5SKC~B/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# depth1
	smbclient_get_expect_error "dir1/veto_name_file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/veto_name_dir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/veto_name_dir/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# depth1 mangle names
	smbclient_get_expect_error "dir1/VHXE5P~M" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/VF5SKC~B/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/VF5SKC~B/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# depth2
	smbclient_get_expect_error "dir1/dir2/veto_name_file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/veto_name_dir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/veto_name_dir/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# depth2 mangle names
	smbclient_get_expect_error "dir1/dir2/VHXE5P~M" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/VF5SKC~B/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/VF5SKC~B/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# depth3
	smbclient_get_expect_error "dir1/dir2/dir3/veto_name_file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/dir3/veto_name_dir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/dir3/veto_name_dir/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	# depth3 mangle names
	smbclient_get_expect_error "dir1/dir2/dir3/VHXE5P~M" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/dir3/VF5SKC~B/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/dir2/dir3/VF5SKC~B/testdir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1

	return 0
}

test_create_veto_file()
{
	# Test creating files
	smbclient_create_expect_error "veto_name_file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_create_expect_error "veto_name_dir/file_inside_dir" "NT_STATUS_OBJECT_PATH_NOT_FOUND" || return 1
	smbclient_create_expect_error "dir1/veto_name_file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1

	return 0
}

test_per_user()
{
	USERNAME=user1
	smbclient_get_expect_error "dir1/user1file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/user2file" "NT_STATUS_OK" || return 1
	smbclient_get_expect_error "dir1/group1file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/group2file" "NT_STATUS_OK" || return 1

	USERNAME=user2
	smbclient_get_expect_error "dir1/user1file" "NT_STATUS_OK" || return 1
	smbclient_get_expect_error "dir1/user2file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1
	smbclient_get_expect_error "dir1/group1file" "NT_STATUS_OK" || return 1
	smbclient_get_expect_error "dir1/group2file" "NT_STATUS_OBJECT_NAME_NOT_FOUND" || return 1

	return 0
}

do_cleanup

echo "regular_file" > "${SHAREPATH}/regular_file"
echo "hidden_file" > "${SHAREPATH}/.hidden_file"

test_smbclient "download regular file" \
	"get regular_file" "//${SERVER}/veto_files_nohidden" \
	-U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
rm -f regular_file
test_smbclient_expect_failure "hidden file can't be downloaded" \
	"get .hidden_file" "//${SERVER}/veto_files_nohidden" \
	-U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))
test_smbclient "list files" \
	"ls" "//${SERVER}/veto_files_nohidden" \
	-U"${USERNAME}%${PASSWORD}" ||
	failed=$((failed + 1))

do_cleanup

# Using hash2, veto_name_file\"mangle == VHXE5P~M
# Using hash2, veto_name_dir\"mangle == VF5SKC~B

# I think a depth of 3 should be enough.
# toplevel
touch "$SHAREPATH/veto_name_file"
mkdir "$SHAREPATH/veto_name_dir"
touch "$SHAREPATH/veto_name_dir/file_inside_dir"
mkdir "$SHAREPATH/veto_name_dir/testdir"
touch "$SHAREPATH/veto_name_dir/testdir/file_inside_dir"
# toplevel mangle names.
touch "$SHAREPATH/veto_name_file\"mangle"
mkdir "$SHAREPATH/veto_name_dir\"mangle"
touch "$SHAREPATH/veto_name_dir\"mangle/file_inside_dir"
mkdir "$SHAREPATH/veto_name_dir\"mangle/testdir"
touch "$SHAREPATH/veto_name_dir\"mangle/testdir/file_inside_dir"

#depth1
mkdir "$SHAREPATH/dir1"
touch "$SHAREPATH/dir1/veto_name_file"
mkdir "$SHAREPATH/dir1/veto_name_dir"
touch "$SHAREPATH/dir1/veto_name_dir/file_inside_dir"
mkdir "$SHAREPATH/dir1/veto_name_dir/testdir"
touch "$SHAREPATH/dir1/veto_name_dir/testdir/file_inside_dir"
# depth1 mangle names.
touch "$SHAREPATH/dir1/veto_name_file\"mangle"
mkdir "$SHAREPATH/dir1/veto_name_dir\"mangle"
touch "$SHAREPATH/dir1/veto_name_dir\"mangle/file_inside_dir"
mkdir "$SHAREPATH/dir1/veto_name_dir\"mangle/testdir"
touch "$SHAREPATH/dir1/veto_name_dir\"mangle/testdir/file_inside_dir"

#depth2
mkdir "$SHAREPATH/dir1/dir2"
touch "$SHAREPATH/dir1/dir2/veto_name_file"
mkdir "$SHAREPATH/dir1/dir2/veto_name_dir"
touch "$SHAREPATH/dir1/dir2/veto_name_dir/file_inside_dir"
mkdir "$SHAREPATH/dir1/dir2/veto_name_dir/testdir"
touch "$SHAREPATH/dir1/dir2/veto_name_dir/testdir/file_inside_dir"
# depth2 mangle names.
touch "$SHAREPATH/dir1/dir2/veto_name_file\"mangle"
mkdir "$SHAREPATH/dir1/dir2/veto_name_dir\"mangle"
touch "$SHAREPATH/dir1/dir2/veto_name_dir\"mangle/file_inside_dir"
mkdir "$SHAREPATH/dir1/dir2/veto_name_dir\"mangle/testdir"
touch "$SHAREPATH/dir1/dir2/veto_name_dir\"mangle/testdir/file_inside_dir"

#depth3
mkdir "$SHAREPATH/dir1/dir2/dir3"
touch "$SHAREPATH/dir1/dir2/dir3/veto_name_file"
mkdir "$SHAREPATH/dir1/dir2/dir3/veto_name_dir"
touch "$SHAREPATH/dir1/dir2/dir3/veto_name_dir/file_inside_dir"
mkdir "$SHAREPATH/dir1/dir2/dir3/veto_name_dir/testdir"
touch "$SHAREPATH/dir1/dir2/dir3/veto_name_dir/testdir/file_inside_dir"
# depth3 mangle names.
touch "$SHAREPATH/dir1/dir2/dir3/veto_name_file\"mangle"
mkdir "$SHAREPATH/dir1/dir2/dir3/veto_name_dir\"mangle"
touch "$SHAREPATH/dir1/dir2/dir3/veto_name_dir\"mangle/file_inside_dir"
mkdir "$SHAREPATH/dir1/dir2/dir3/veto_name_dir\"mangle/testdir"
touch "$SHAREPATH/dir1/dir2/dir3/veto_name_dir\"mangle/testdir/file_inside_dir"

# testfiles for per-user feature
touch "$SHAREPATH/dir1/user1file"
touch "$SHAREPATH/dir1/user2file"
touch "$SHAREPATH/dir1/group1file"
touch "$SHAREPATH/dir1/group2file"

testit "create_veto_file" test_create_veto_file || failed=$((failed + 1))
testit "get_veto_file" test_get_veto_file || failed=$(("$failed" + 1))
testit "per-user" test_per_user || failed=$(("$failed" + 1))

do_cleanup

cd "${PREFIX}" && rm -rf ${TMPDIR}

exit "$failed"
