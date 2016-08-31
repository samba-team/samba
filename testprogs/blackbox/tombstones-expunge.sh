#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: tombstones-expunge.sh PREFIX RELEASE
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

undump() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE
       fi
}

tombstones_expunge() {
    tmpfile=$PREFIX_ABS/$RELEASE/expected-expunge-output.txt
    $PYTHON $BINDIR/samba-tool domain tombstones expunge -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --current-time=2016-07-30 --tombstone-lifetime=4 > $tmpfile
    if [ "$?" != "0" ]; then
	return $?
    fi
    diff $tmpfile $release_dir/expected-expunge-output.txt
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

check_expected_after_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-links-after-expunge.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-links-after-expunge.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_deleted_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-deleted-links-after-expunge.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-deleted-links-after-expunge.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_objects() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-objects-after-expunge.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(samaccountname=fred)(samaccountname=ddg)(samaccountname=usg)(samaccountname=user1)(samaccountname=user2))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted samAccountName | grep sAMAccountName > $tmpldif
    diff $tmpldif $release_dir/expected-objects-after-expunge.ldif
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
    testit "tombstones_expunge" tombstones_expunge
    testit "check_expected_after_deleted_links" check_expected_after_deleted_links
    testit "check_expected_after_links" check_expected_after_links
    testit "check_expected_after_objects" check_expected_after_objects
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
