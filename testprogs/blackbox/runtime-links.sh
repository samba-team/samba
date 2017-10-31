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

. `dirname $0`/subunit.sh

. `dirname $0`/common-links.sh

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


if [ -d $release_dir ]; then
    testit $RELEASE undump
    testit "add_dangling_link" add_dangling_link
    testit "add_dangling_backlink" add_dangling_backlink
    testit "add_deleted_dangling_backlink" add_deleted_dangling_backlink
    testit "revive_links_on_deleted_group" revive_links_on_deleted_group
    testit "revive_backlink_on_deleted_group" revive_backlink_on_deleted_group
    testit "add_deleted_target_link" add_deleted_target_link
    testit "add_deleted_target_backlink" add_deleted_target_backlink
    testit "dangling_one_way_link" dangling_one_way_link
    testit "dangling_one_way_dn" dangling_one_way_dn
    testit "deleted_one_way_dn" deleted_one_way_dn
    testit "add_dangling_multi_valued" add_dangling_multi_valued

#Now things are set up, work with the DB
    testit "delete_member_of_deleted_group" delete_member_of_deleted_group
    testit "delete_backlink_memberof_deleted_group" delete_backlink_memberof_deleted_group
    testit "delete_dangling_backlink_memberof_group" delete_dangling_backlink_memberof_group
else
    subunit_start_test $RELEASE
    subunit_skip_test $RELEASE <<EOF
no test provision
EOF

    subunit_start_test "tombstones_expunge"
    subunit_skip_test "tombstones_expunge" <<EOF
no test provision
EOF
fi

if [ -d $PREFIX_ABS/${RELEASE} ]; then
    rm -fr $PREFIX_ABS/${RELEASE}
fi

exit $failed
