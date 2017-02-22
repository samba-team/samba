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

release_dir=`dirname $0`/../../source4/selftest/provisions/$RELEASE

ldbadd="ldbadd"
if [ -x "$BINDIR/ldbadd" ]; then
    ldbadd="$BINDIR/ldbadd"
fi

ldbmodify="ldbmodify"
if [ -x "$BINDIR/ldbmodify" ]; then
    ldbmodify="$BINDIR/ldbmodify"
fi

ldbdel="ldbdel"
if [ -x "$BINDIR/ldbdel" ]; then
    ldbdel="$BINDIR/ldbdel"
fi

ldbsearch="ldbsearch"
if [ -x "$BINDIR/ldbsearch" ]; then
    ldbsearch="$BINDIR/ldbsearch"
fi

ldbrename="ldbrename"
if [ -x "$BINDIR/ldbrename" ]; then
    ldbrename="$BINDIR/ldbrename"
fi

undump() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE
       fi
}

dbcheck() {
    tmpfile=$PREFIX_ABS/$RELEASE/expected-dbcheck-link-output.txt.tmp
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-dbcheck-output2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --fix --yes > $tmpfile
    if [ "$?" != "1" ]; then
	return 1
    fi
    diff $tmpfile $release_dir/expected-dbcheck-link-output.txt
    if [ "$?" != "0" ]; then
	return 1
    fi

    tmpldif2=$PREFIX_ABS/$RELEASE/expected-dbcheck-output2.txt.tmp2
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif2

    diff $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_clean() {
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-dbcheck-output2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb
    if [ "$?" != "0" ]; then
	return 1
    fi
    tmpldif2=$PREFIX_ABS/$RELEASE/expected-dbcheck-output2.txt.tmp2
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif2

    diff $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_dangling_link() {
    ldif=$release_dir/add-dangling-forwardlink-user.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-initially-normal-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
    sleep 6

    ldif=$release_dir/delete-only-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_dangling_backlink() {
    ldif=$release_dir/add-dangling-backlink-user.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi

    ldif=$release_dir/add-dangling-backlink.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_two_more_users() {
    ldif=$release_dir/add-two-more-users.ldif
    TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_four_more_links() {
    ldif=$release_dir/add-four-more-links.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

remove_one_link() {
    ldif=$release_dir/remove-one-more-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

remove_one_user() {
    ldif=$release_dir/remove-one-more-user.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

move_one_user() {
    TZ=UTC $ldbrename -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb 'cn=user1,cn=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' 'cn=user1x,cn=users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-links-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-links-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_deleted_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-deleted-links-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-deleted-links-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_objects() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-objects-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(samaccountname=fred)(samaccountname=ddg)(samaccountname=usg)(samaccountname=user1)(samaccountname=user1x)(samaccountname=user2))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted samAccountName | grep sAMAccountName > $tmpldif
    diff $tmpldif $release_dir/expected-objects-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dangling_one_way() {
    ldif=$release_dir/dangling-one-way-link.ldif
    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif
    if [ "$?" != "0" ]; then
        return 1
    fi
}

if [ -d $release_dir ]; then
    testit $RELEASE undump
    testit "add_two_more_users" add_two_more_users
    testit "add_four_more_links" add_four_more_links
    testit "remove_one_link" remove_one_link
    testit "remove_one_user" remove_one_user
    testit "move_one_user" move_one_user
    testit "add_dangling_link" add_dangling_link
    testit "add_dangling_backlink" add_dangling_backlink
    testit "dbcheck" dbcheck
    testit "dbcheck_clean" dbcheck_clean
    testit "check_expected_after_deleted_links" check_expected_after_deleted_links
    testit "check_expected_after_links" check_expected_after_links
    testit "check_expected_after_objects" check_expected_after_objects
    testit "dangling_one_way" dangling_one_way
    testit "dbcheck_clean" dbcheck_clean
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
