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

dbcheck() {
    tmpfile=$PREFIX_ABS/$RELEASE/expected-dbcheck-link-output${1}.txt.tmp
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-dbcheck-output${1}2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $3 --fix --yes > $tmpfile
    if [ "$?" != "$2" ]; then
	return 1
    fi
    sort $tmpfile > $tmpfile.sorted
    sort $release_dir/expected-dbcheck-link-output${1}.txt > $tmpfile.expected
    diff -u $tmpfile.sorted $tmpfile.expected
    if [ "$?" != "0" ]; then
	return 1
    fi

    tmpldif2=$PREFIX_ABS/$RELEASE/expected-dbcheck-output${1}2.txt.tmp2
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif2

    diff -u $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_dangling() {
    dbcheck "" "1" ""
    return $?
}

dbcheck_one_way() {
    dbcheck "_one_way" "0" "CN=Configuration,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    return $?
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

duplicate_member() {
    # We use an exisiting group so we have a stable GUID in the
    # dbcheck output
    LDIF1=$(TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -b 'CN=Enterprise Admins,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' -s base --reveal --extended-dn member)
    DN=$(echo "${LDIF1}" | grep '^dn: ')
    MSG=$(echo "${LDIF1}" | grep -v '^dn: ' | grep -v '^#' | grep -v '^$')
    ldif=$PREFIX_ABS/${RELEASE}/duplicate-member-multi.ldif
    {
	echo "${DN}"
	echo "changetype: modify"
	echo "replace: member"
	echo "${MSG}"
	echo "${MSG}" | sed -e 's!RMD_LOCAL_USN=[1-9][0-9]*!RMD_LOCAL_USN=0!'
    } > $ldif

    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_duplicate_member() {
    dbcheck "_duplicate_member" "1" ""
    return $?
}

check_expected_after_duplicate_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-duplicates-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=administrator)(cn=enterprise admins))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted memberOf member > $tmpldif
    diff $tmpldif $release_dir/expected-duplicates-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_dangling_multi_valued() {

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --fix --yes
    if [ "$?" != "1" ]; then
	return 1
    fi
}

dangling_multi_valued_check_missing() {
    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi2)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`
    if [ $WORDS -ne 4 ]; then
        echo Got only $WORDS links for dangling-multi2
	return 1
    fi
    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi3)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`
    if [ $WORDS -ne 4 ]; then
        echo Got only $WORDS links for dangling-multi3
	return 1
    fi
}

dangling_multi_valued_check_equal_or_too_many() {
    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi1)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`
    if [ $WORDS -ne 4 ]; then
        echo Got $WORDS links for dangling-multi1
	return 1
    fi

    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi5)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`

    if [ $WORDS -ne 0 ]; then
        echo Got $WORDS links for dangling-multi5
	return 1
    fi

    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=Administrator)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`

    if [ $WORDS -ne 2 ]; then
        echo Got $WORDS links for Administrator
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
    testit "add_deleted_dangling_backlink" add_deleted_dangling_backlink
    testit "revive_links_on_deleted_group" revive_links_on_deleted_group
    testit "revive_backlink_on_deleted_group" revive_backlink_on_deleted_group
    testit "add_deleted_target_link" add_deleted_target_link
    testit "add_deleted_target_backlink" add_deleted_target_backlink
    testit "dbcheck_dangling" dbcheck_dangling
    testit "dbcheck_clean" dbcheck_clean
    testit "check_expected_after_deleted_links" check_expected_after_deleted_links
    testit "check_expected_after_links" check_expected_after_links
    testit "check_expected_after_objects" check_expected_after_objects
    testit "duplicate_member" duplicate_member
    testit "dbcheck_duplicate_member" dbcheck_duplicate_member
    testit "check_expected_after_duplicate_links" check_expected_after_duplicate_links
    testit "duplicate_clean" dbcheck_clean
    testit "dangling_one_way_link" dangling_one_way_link
    testit "dbcheck_one_way" dbcheck_one_way
    testit "dbcheck_clean2" dbcheck_clean
    testit "dangling_one_way_dn" dangling_one_way_dn
    testit "deleted_one_way_dn" deleted_one_way_dn
    testit "dbcheck_clean3" dbcheck_clean
    testit "add_dangling_multi_valued" add_dangling_multi_valued
    testit "dbcheck_dangling_multi_valued" dbcheck_dangling_multi_valued
    testit "dangling_multi_valued_check_missing" dangling_multi_valued_check_missing
    testit "dangling_multi_valued_check_equal_or_too_many" dangling_multi_valued_check_equal_or_too_many
    # Currently this cannot pass
    testit "dbcheck_dangling_multi_valued_clean" dbcheck_clean
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
