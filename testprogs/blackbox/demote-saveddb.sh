#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: demote.sh PREFIX RELEASE
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

. `dirname $0`/subunit.sh

tree_dir=`dirname $0`/../../source4/selftest/provisions/multi-dc-samba-master-c596ac6

undump() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $tree_dir $PREFIX_ABS $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $tree_dir $PREFIX_ABS
       fi
}

demote() {
       $PYTHON $BINDIR/samba-tool domain demote -H tdb://$PREFIX_ABS/private/sam.ldb --remove-other-dead-server=$1
}


if [ -d $tree_dir ]; then
    testit "undump" undump
    testit "demote-q-0-0" demote "q-0-0"
    # The database was copied of q-0-1 so this will fail
    # as we can't remove our own name
    testit_expect_failure "demote-q-0-1" demote "q-0-1"
    testit "demote-q-1-0" demote "q-1-0"
    testit "demote-q-1-1" demote "q-1-1"
else
    subunit_start_test "undump"
    subunit_skip_test "undump" <<EOF
no test provision
EOF

    subunit_start_test "demote-q-0-0"
    subunit_skip_test "demote-q-0-0" <<EOF
no test provision
EOF
    subunit_start_test "demote-q-0-1"
    subunit_skip_test "demote-q-0-1" <<EOF
no test provision
EOF
    subunit_start_test "demote-q-1-1"
    subunit_skip_test "demote-q-0-1" <<EOF
no test provision
EOF
    subunit_start_test "demote-q-1-1"
    subunit_skip_test "demote-q-1-1" <<EOF
no test provision
EOF
fi

if [ -d $PREFIX_ABS ]; then
    rm -fr $PREFIX_ABS
fi

exit $failed
