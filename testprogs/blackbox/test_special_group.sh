#!/bin/sh

if [ $# -lt 1 ]; then
	cat <<EOF
Usage: $0 PREFIX
EOF
	exit 1
fi

PREFIX="$1"
shift 1

failed=0

. $(dirname $0)/subunit.sh
. $(dirname $0)/common_test_fns.inc

OLD_RELEASE="release-4-5-0-pre1"
old_release_dir="$SRCDIR_ABS/source4/selftest/provisions/$OLD_RELEASE"

samba_tdbrestore=$(system_or_builddir_binary tdbrestore "${BINDIR}")

samba_undump="$SRCDIR_ABS/source4/selftest/provisions/undump.sh"
if [ ! -x "${samba_undump}" ]; then
	subunit_start_test "special group"
	subunit_skip_test "special group" <<EOF
Skipping tests - undump.sh is not available in release tarballs
EOF
	exit 0
fi

cleanup_output_directories()
{
	remove_directory $PREFIX/$OLD_RELEASE
}

undump_old()
{
	$samba_undump $old_release_dir $PREFIX/$OLD_RELEASE $samba_tdbrestore
}

add_special_group()
{
	$PYTHON $BINDIR/samba-tool group add 'protected users' --special -H tdb://$PREFIX/$OLD_RELEASE/private/sam.ldb
}

# double-check we cleaned up from the last test run
cleanup_output_directories

testit $OLD_RELEASE undump_old || failed=$(expr $failed + 1)

testit "add_special_group" add_special_group || failed=$(expr $failed + 1)

testit_expect_failure_grep "add_duplicate_special_group" "Failed to add group.*already exists" add_special_group || failed=$(expr $failed + 1)

cleanup_output_directories

testok $0 $failed
