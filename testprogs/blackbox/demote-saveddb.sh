#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: demote.sh PREFIX RELEASE
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

failed=0

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

samba_tree_dir="$SRCDIR_ABS/source4/selftest/provisions/multi-dc-samba-master-c596ac6"

samba_tdbrestore="tdbrestore"
if [ -x $BINDIR/tdbrestore ]; then
    samba_tdbrestore="$BINDIR/tdbrestore"
fi

# The undump script and the provision data is not part of release tarballs,
# skip the tests in this case!
samba_undump="$SRCDIR_ABS/source4/selftest/provisions/undump.sh"
if [ ! -x $samba_undump ] || [ ! -d $samba_tree_dir ]; then
    subunit_start_test "undump"
    subunit_skip_test "undump" <<EOF
EOF

    subunit_start_test "undump"
    subunit_skip_test "undump" <<EOF
Skipping tests - no provision!
EOF

    subunit_start_test "demote-q-0-0"
    subunit_skip_test "demote-q-0-0" <<EOF
Skipping tests - no provision!
EOF
    subunit_start_test "demote-q-0-1"
    subunit_skip_test "demote-q-0-1" <<EOF
Skipping tests - no provision!
EOF
    subunit_start_test "demote-q-1-0"
    subunit_skip_test "demote-q-1-0" <<EOF
Skipping tests - no provision!
EOF
    subunit_start_test "demote-q-1-1"
    subunit_skip_test "demote-q-1-1" <<EOF
Skipping tests - no provision!
EOF

    exit 0
fi

undump() {
    $SRCDIR_ABS/source4/selftest/provisions/undump.sh $samba_tree_dir $PREFIX_ABS $samba_tdbrestore
}

demote() {
       $PYTHON $BINDIR/samba-tool domain demote -H tdb://$PREFIX_ABS/private/sam.ldb --remove-other-dead-server=$1
}

remove_directory $PREFIX_ABS

testit "undump" undump || failed=`expr $failed + 1`
testit "demote-q-0-0" demote "q-0-0" || failed=`expr $failed + 1`
# The database was copied of q-0-1 so this will fail
# as we can't remove our own name
testit_expect_failure "demote-q-0-1" demote "q-0-1" || failed=`expr $failed + 1`
testit "demote-q-1-0" demote "q-1-0" || failed=`expr $failed + 1`
testit "demote-q-1-1" demote "q-1-1" || failed=`expr $failed + 1`

remove_directory $PREFIX_ABS

exit $failed
