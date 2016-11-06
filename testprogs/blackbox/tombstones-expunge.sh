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
    tmpfile=$PREFIX_ABS/$RELEASE/expected-expunge-output.txt.tmp
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-expunge-output2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool domain tombstones expunge -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --current-time=2016-07-30 --tombstone-lifetime=4 > $tmpfile
    if [ "$?" != "0" ]; then
	return 1
    fi
    diff $tmpfile $release_dir/expected-expunge-output.txt
    if [ "$?" != "0" ]; then
	return 1
    fi

    tmpldif2=$PREFIX_ABS/$RELEASE/expected-expunge-output2.txt.tmp2
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif2

    diff $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

add_dangling_link() {
    ldif=$release_dir/add-dangling-link.ldif
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

check_match_rule_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-match-rule-links.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=131139216000000000)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-match-rule-links.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_match_rule_links_negative() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=-131139216000000000)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member
}

check_match_rule_links_overflow() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=18446744073709551617)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member
}

check_match_rule_links_null() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=18446744\073709551617)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member
}

check_match_rule_links_hex() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=abcd)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member
}

check_match_rule_links_hex2() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=0xabcd)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member
}

check_match_rule_links_decimal() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(member:1.3.6.1.4.1.7165.4.5.2:=131139216000000000.00)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member
}

check_match_rule_links_backlink() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(memberOf:1.3.6.1.4.1.7165.4.5.2:=131139216000000000)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted memberOf
}

check_match_rule_links_notlink() {
    $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samAccountName:1.3.6.1.4.1.7165.4.5.2:=131139216000000000)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted samAccountName
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
    testit "add_dangling_link" add_dangling_link
    testit "remove_one_link" remove_one_link
    testit "remove_one_user" remove_one_user
    testit "check_match_rule_links" check_match_rule_links
    testit_expect_failure "check_match_rule_links_negative" check_match_rule_links_negative
    testit_expect_failure "check_match_rule_links_overflow" check_match_rule_links_overflow
    testit_expect_failure "check_match_rule_links_null" check_match_rule_links_null
    testit_expect_failure "check_match_rule_links_hex" check_match_rule_links_hex
    testit_expect_failure "check_match_rule_links_hex2" check_match_rule_links_hex2
    testit_expect_failure "check_match_rule_links_decimal" check_match_rule_links_decimal
    testit_expect_failure "check_match_rule_links_backlink" check_match_rule_links_backlink
    testit_expect_failure "check_match_rule_links_notlink" check_match_rule_links_notlink
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
