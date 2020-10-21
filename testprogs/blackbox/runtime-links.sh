#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck-links.sh PREFIX RELEASE
EOF
exit 1;
fi

PREFIX_ABS="$1"
RELEASE="$2"
shift 2

failed=0

. `dirname $0`/subunit.sh

. `dirname $0`/common-links.sh

. `dirname $0`/common_test_fns.inc

if [ ! -x $samba_undump ] || [ ! -d $release_dir ]; then
    subunit_start_test $RELEASE
    subunit_skip_test $RELEASE <<EOF
no test provision
EOF

    subunit_start_test "tombstones_expunge"
    subunit_skip_test "tombstones_expunge" <<EOF
no test provision
EOF

    exit 0
fi

delete_member_of_deleted_group() {
    TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb 'CN=User1 UT. Tester,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    if [ "$?" != "0" ]; then
	return 1
    fi
}

delete_backlink_memberof_deleted_group() {
    TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb 'CN=User UT. Tester,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    if [ "$?" != "0" ]; then
	return 1
    fi
}

delete_dangling_backlink_memberof_group() {
    TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb 'CN=dangling-back,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    if [ "$?" != "0" ]; then
	return 1
    fi
}

remove_directory $PREFIX_ABS/${RELEASE}

testit $RELEASE undump || failed=`expr $failed + 1`
testit "add_dangling_link" add_dangling_link || failed=`expr $failed + 1`
testit "add_dangling_backlink" add_dangling_backlink || failed=`expr $failed + 1`
testit "add_deleted_dangling_backlink" add_deleted_dangling_backlink || failed=`expr $failed + 1`
testit "revive_links_on_deleted_group" revive_links_on_deleted_group || failed=`expr $failed + 1`
testit "revive_backlink_on_deleted_group" revive_backlink_on_deleted_group || failed=`expr $failed + 1`
testit "add_deleted_target_link" add_deleted_target_link || failed=`expr $failed + 1`
testit "add_deleted_target_backlink" add_deleted_target_backlink || failed=`expr $failed + 1`
testit "dangling_one_way_link" dangling_one_way_link || failed=`expr $failed + 1`
testit "dangling_one_way_dn" dangling_one_way_dn || failed=`expr $failed + 1`
testit "deleted_one_way_dn" deleted_one_way_dn || failed=`expr $failed + 1`
testit "add_dangling_multi_valued" add_dangling_multi_valued || failed=`expr $failed + 1`

#Now things are set up, work with the DB
testit "delete_member_of_deleted_group" delete_member_of_deleted_group || failed=`expr $failed + 1`
testit "delete_backlink_memberof_deleted_group" delete_backlink_memberof_deleted_group || failed=`expr $failed + 1`
testit "delete_dangling_backlink_memberof_group" delete_dangling_backlink_memberof_group || failed=`expr $failed + 1`

remove_directory $PREFIX_ABS/${RELEASE}

exit $failed
