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
. `dirname $0`/common_test_fns.inc

failed=0

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

dbcheck() {
    tmpfile=$PREFIX_ABS/$RELEASE/expected-dbcheck-link-output${1}.txt.tmp
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-dbcheck-output${1}2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $3 --fix --yes > $tmpfile
    if [ "$?" != "$2" ]; then
	return 1
    fi
    sort $tmpfile | grep -v "^INFO:" > $tmpfile.sorted
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
    dbcheck "" "1" "--selftest-check-expired-tombstones"
    return $?
}

dbcheck_one_way() {
    dbcheck "_one_way" "0" "CN=Configuration,DC=release-4-5-0-pre1,DC=samba,DC=corp --selftest-check-expired-tombstones"
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

    diff -u $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-links-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted member > $tmpldif
    diff -u $tmpldif $release_dir/expected-links-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_deleted_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-deleted-links-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member > $tmpldif
    diff -u $tmpldif $release_dir/expected-deleted-links-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_objects() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-objects-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(samaccountname=fred)(samaccountname=ddg)(samaccountname=usg)(samaccountname=user1)(samaccountname=user1x)(samaccountname=user2))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted samAccountName | grep sAMAccountName > $tmpldif
    diff -u $tmpldif $release_dir/expected-objects-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

duplicate_member() {
    # We use an existing group so we have a stable GUID in the
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
    dbcheck "_duplicate_member" "1" "--selftest-check-expired-tombstones"
    return $?
}

check_expected_after_duplicate_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-duplicates-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=administrator)(cn=enterprise admins))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted memberOf member > $tmpldif
    diff -u $tmpldif $release_dir/expected-duplicates-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

missing_link_sid_corruption() {
    # Step1: add user "missingsidu1"
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption1.ldif
    cat > $ldif <<EOF
dn: CN=missingsidu1,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: user
samaccountname: missingsidu1
objectGUID: 0da8f25e-d110-11e8-80b7-3c970ec68461
objectSid: S-1-5-21-4177067393-1453636373-93818738-771
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    # Step2: add user "missingsidu2"
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption2.ldif
    cat > $ldif <<EOF
dn: CN=missingsidu2,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: user
samaccountname: missingsidu2
objectGUID: 66eb8f52-d110-11e8-ab9b-3c970ec68461
objectSid: S-1-5-21-4177067393-1453636373-93818738-772
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    # Step3: add group "missingsidg3" and add users as members
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption3.ldif
    cat > $ldif <<EOF
dn: CN=missingsidg3,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: group
samaccountname: missingsidg3
objectGUID: fd992424-d114-11e8-bb36-3c970ec68461
objectSid: S-1-5-21-4177067393-1453636373-93818738-773
member: CN=missingsidu1,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
member: CN=missingsidu2,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    # Step4: remove one user again, so that we have one deleted link
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption4.ldif
    cat > $ldif <<EOF
dn: CN=missingsidg3,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: modify
delete: member
member: CN=missingsidu1,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step5: remove the SIDS from the links
    #
    LDIF1=$(TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -b 'CN=missingsidg3,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' -s base --reveal --extended-dn --show-binary member)
    DN=$(echo "${LDIF1}" | grep '^dn: ')
    MSG=$(echo "${LDIF1}" | grep -v '^dn: ' | grep -v '^#' | grep -v '^$')
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption5.ldif
    {
	echo "${DN}"
	echo "changetype: modify"
	echo "replace: member"
	#echo "${MSG}"
	echo "${MSG}" | sed \
		-e 's!<SID=S-1-5-21-4177067393-1453636373-93818738-771>;!!g' \
		-e 's!<SID=S-1-5-21-4177067393-1453636373-93818738-772>;!!g' \
		-e 's!RMD_ADDTIME=[1-9][0-9]*!RMD_ADDTIME=123456789000000000!g' \
		-e 's!RMD_CHANGETIME=[1-9][0-9]*!RMD_CHANGETIME=123456789000000000!g' \
		| cat
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    return 0
}

dbcheck_missing_link_sid_corruption() {
    dbcheck "-missing-link-sid-corruption" "1" "--selftest-check-expired-tombstones"
    return $?
}

add_lost_deleted_user1() {
    ldif=$PREFIX_ABS/${RELEASE}/add_lost_deleted_user1.ldif
    cat > $ldif <<EOF
dn: CN=fred\0ADEL:2301a64c-1234-5678-851e-12d4a711cfb4,OU=removed,DC=release-4-5-0-pre1,DC=samba,DC=corp
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
instanceType: 4
whenCreated: 20160629043638.0Z
uSNCreated: 3740
objectGUID: 2301a64c-1234-5678-851e-12d4a711cfb4
objectSid: S-1-5-21-4177067393-1453636373-93818738-1011
sAMAccountName: fred
userAccountControl: 512
isDeleted: TRUE
lastKnownParent: <GUID=f28216e9-1234-5678-8b2d-6bb229563b62>;OU=removed,DC=rel
 ease-4-5-0-pre1,DC=samba,DC=corp
isRecycled: TRUE
cn:: ZnJlZApERUw6MjMwMWE2NGMtMTIzNC01Njc4LTg1MWUtMTJkNGE3MTFjZmI0
name:: ZnJlZApERUw6MjMwMWE2NGMtMTIzNC01Njc4LTg1MWUtMTJkNGE3MTFjZmI0
replPropertyMetaData:: AQAAAAAAAAAXAAAAAAAAAAAAAAABAAAAVuGDDQMAAACjlkROuH+XT4o
 z0jjbi14tnA4AAAAAAACcDgAAAAAAAAMAAAACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4A
 AAAAAACiDgAAAAAAAAEAAgABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAA
 AAAAAIAAgABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAADAAAgABAA
 AAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAABkBAgABAAAAVuGDDQMAAAC
 jlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAAEACQACAAAAV+GDDQMAAACjlkROuH+XT4oz
 0jjbi14tog4AAAAAAACiDgAAAAAAAAgACQADAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tng4AA
 AAAAACeDgAAAAAAABAACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAA
 AAABkACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAFoACQABAAA
 AVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAAAAF4ACQABAAAAVuGDDQMAAACj
 lkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAAAAGAACQADAAAAV+GDDQMAAACjlkROuH+XT4oz0
 jjbi14tog4AAAAAAACiDgAAAAAAAGIACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAA
 AAAACiDgAAAAAAAH0ACQABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAA
 AAJIACQABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAJ8ACQACAAAA
 V+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAN0ACQABAAAAVuGDDQMAAACjl
 kROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAC4BCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0j
 jbi14tog4AAAAAAACiDgAAAAAAAJACCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAA
 AAACiDgAAAAAAAA0DCQABAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAA
 AA4DCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAAoICQABAAAAV
 +GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAA==
whenChanged: 20160629043639.0Z
uSNChanged: 3746
nTSecurityDescriptor:: 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
 GAC9AQ8AAQIAAAAAAAUgAAAAIAIAAA==
EOF

    out=$(TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbadd returned:\n$out"
	return 1
    fi

    return 0
}

dbcheck_lost_deleted_user1() {
    dbcheck "-lost-deleted-user1" "1" "--selftest-check-expired-tombstones"
    return $?
}

remove_lost_deleted_user1() {
    out=$(TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb "<GUID=2301a64c-1234-5678-851e-12d4a711cfb4>" --show-recycled --relax)
    if [ "$?" != "0" ]; then
	echo "ldbdel returned:\n$out"
	return 1
    fi

    return 0
}

add_lost_deleted_user2() {
    ldif=$PREFIX_ABS/${RELEASE}/add_lost_deleted_user2.ldif
    cat > $ldif <<EOF
dn: CN=fred\0ADEL:2301a64c-8765-4321-851e-12d4a711cfb4,CN=LostAndFound,DC=release-4-5-0-pre1,DC=samba,DC=corp
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
instanceType: 4
whenCreated: 20160629043638.0Z
uSNCreated: 3740
objectGUID: 2301a64c-8765-4321-851e-12d4a711cfb4
objectSid: S-1-5-21-4177067393-1453636373-93818738-1001
sAMAccountName: fred
userAccountControl: 512
isDeleted: TRUE
lastKnownParent: OU=removed,DC=release-4-5-0-pre1,DC=samba,DC=corp
isRecycled: TRUE
cn:: ZnJlZApERUw6MjMwMWE2NGMtODc2NS00MzIxLTg1MWUtMTJkNGE3MTFjZmI0
name:: ZnJlZApERUw6MjMwMWE2NGMtODc2NS00MzIxLTg1MWUtMTJkNGE3MTFjZmI0
replPropertyMetaData:: AQAAAAAAAAAXAAAAAAAAAAAAAAABAAAAVuGDDQMAAACjlkROuH+XT4o
 z0jjbi14tnA4AAAAAAACcDgAAAAAAAAMAAAACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4A
 AAAAAACiDgAAAAAAAAEAAgABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAA
 AAAAAIAAgABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAADAAAgABAA
 AAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAABkBAgABAAAAVuGDDQMAAAC
 jlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAAEACQAEAAAAePOWEgMAAACjlkROuH+XT4oz
 0jjbi14tvA4AAAAAAAC8DgAAAAAAAAgACQADAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tng4AA
 AAAAACeDgAAAAAAABAACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAA
 AAABkACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAFoACQABAAA
 AVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAAAAF4ACQABAAAAVuGDDQMAAACj
 lkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAAAAGAACQADAAAAV+GDDQMAAACjlkROuH+XT4oz0
 jjbi14tog4AAAAAAACiDgAAAAAAAGIACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAA
 AAAACiDgAAAAAAAH0ACQABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAA
 AAJIACQABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAJ8ACQACAAAA
 V+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAN0ACQABAAAAVuGDDQMAAACjl
 kROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAC4BCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0j
 jbi14tog4AAAAAAACiDgAAAAAAAJACCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAA
 AAACiDgAAAAAAAA0DCQADAAAAePOWEgMAAACjlkROuH+XT4oz0jjbi14tvQ4AAAAAAAC9DgAAAAAA
 AA4DCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAAoICQABAAAAV
 +GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAA==
whenChanged: 20160629043639.0Z
uSNChanged: 3746
nTSecurityDescriptor:: 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
 GAC9AQ8AAQIAAAAAAAUgAAAAIAIAAA==
EOF

    out=$(TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbadd returned:\n$out"
	return 1
    fi

    return 0
}

dbcheck_lost_deleted_user2() {
    dbcheck "-lost-deleted-user2" "1" "--selftest-check-expired-tombstones"
    return $?
}

add_lost_deleted_user3() {
    ldif=$PREFIX_ABS/${RELEASE}/add_lost_deleted_user3.ldif
    cat > $ldif <<EOF
dn: CN=fred\0ADEL:2301a64c-1122-5566-851e-12d4a711cfb4,OU=removed,DC=release-4-5-0-pre1,DC=samba,DC=corp
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
instanceType: 4
whenCreated: 20160629043638.0Z
uSNCreated: 3740
objectGUID: 2301a64c-1122-5566-851e-12d4a711cfb4
objectSid: S-1-5-21-4177067393-1453636373-93818738-1010
sAMAccountName: fred
userAccountControl: 512
isDeleted: TRUE
lastKnownParent: <GUID=f28216e9-1234-5678-8b2d-6bb229563b62>;OU=removed,DC=rel
 ease-4-5-0-pre1,DC=samba,DC=corp
isRecycled: TRUE
cn:: ZnJlZApERUw6MjMwMWE2NGMtMTEyMi01NTY2LTg1MWUtMTJkNGE3MTFjZmI0
name:: ZnJlZApERUw6MjMwMWE2NGMtMTEyMi01NTY2LTg1MWUtMTJkNGE3MTFjZmI0
replPropertyMetaData:: AQAAAAAAAAAXAAAAAAAAAAAAAAABAAAAVuGDDQMAAACjlkROuH+XT4o
 z0jjbi14tnA4AAAAAAACcDgAAAAAAAAMAAAACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4A
 AAAAAACiDgAAAAAAAAEAAgABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAA
 AAAAAIAAgABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAADAAAgABAA
 AAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAABkBAgABAAAAVuGDDQMAAAC
 jlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAAEACQACAAAAV+GDDQMAAACjlkROuH+XT4oz
 0jjbi14tog4AAAAAAACiDgAAAAAAAAgACQADAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tng4AA
 AAAAACeDgAAAAAAABAACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAA
 AAABkACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAFoACQABAAA
 AVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAAAAF4ACQABAAAAVuGDDQMAAACj
 lkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAAAAGAACQADAAAAV+GDDQMAAACjlkROuH+XT4oz0
 jjbi14tog4AAAAAAACiDgAAAAAAAGIACQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAA
 AAAACiDgAAAAAAAH0ACQABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnQ4AAAAAAACdDgAAAAA
 AAJIACQABAAAAVuGDDQMAAACjlkROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAJ8ACQACAAAA
 V+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAN0ACQABAAAAVuGDDQMAAACjl
 kROuH+XT4oz0jjbi14tnA4AAAAAAACcDgAAAAAAAC4BCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0j
 jbi14tog4AAAAAAACiDgAAAAAAAJACCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAA
 AAACiDgAAAAAAAA0DCQABAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAA
 AA4DCQACAAAAV+GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAAoICQABAAAAV
 +GDDQMAAACjlkROuH+XT4oz0jjbi14tog4AAAAAAACiDgAAAAAAAA==
whenChanged: 20160629043639.0Z
uSNChanged: 3746
nTSecurityDescriptor:: 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
 GAC9AQ8AAQIAAAAAAAUgAAAAIAIAAA==
EOF

    out=$(TZ=UTC $ldbadd -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbadd returned:\n$out"
	return 1
    fi

    return 0
}

dbcheck_lost_deleted_user3() {
    # here we don't pass --selftest-check-expired-tombstones
    # as we want to test the default
    dbcheck "-lost-deleted-user3" "0" ""
    return $?
}

remove_lost_deleted_user3() {
    out=$(TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb "<GUID=2301a64c-1122-5566-851e-12d4a711cfb4>" --show-recycled --relax)
    if [ "$?" != "0" ]; then
	echo "ldbdel returned:\n$out"
	return 1
    fi

    return 0
}

forward_link_corruption() {
    #
    # Step1: add a duplicate forward link from
    # "CN=Enterprise Admins" to "CN=Administrator"
    #
    LDIF1=$(TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -b 'CN=Enterprise Admins,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' -s base --reveal --extended-dn member)
    DN=$(echo "${LDIF1}" | grep '^dn: ')
    MSG=$(echo "${LDIF1}" | grep -v '^dn: ' | grep -v '^#' | grep -v '^$')
    ldif=$PREFIX_ABS/${RELEASE}/forward_link_corruption1.ldif
    {
	echo "${DN}"
	echo "changetype: modify"
	echo "replace: member"
	echo "${MSG}"
	echo "${MSG}" | sed -e 's!RMD_LOCAL_USN=[1-9][0-9]*!RMD_LOCAL_USN=0!'
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add user "dangling"
    #
    ldif=$PREFIX_ABS/${RELEASE}/forward_link_corruption2.ldif
    cat > $ldif <<EOF
dn: CN=dangling,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: user
samaccountname: dangling
objectGUID: fd8a04ac-cea0-4921-b1a6-c173e1155c22
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step3: add a dangling backlink from
    # "CN=dangling" to "CN=Enterprise Admins"
    #
    ldif=$PREFIX_ABS/${RELEASE}/forward_link_corruption3.ldif
    {
	echo "dn: CN=dangling,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
	echo "changetype: modify"
	echo "add: memberOf"
	echo "memberOf: <GUID=304ad703-468b-465e-9787-470b3dfd7d75>;<SID=S-1-5-21-4177067393-1453636373-93818738-519>;CN=Enterprise Admins,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi
}

dbcheck_forward_link_corruption() {
    dbcheck "-forward-link-corruption" "1" "--selftest-check-expired-tombstones"
    return $?
}

check_expected_after_dbcheck_forward_link_corruption() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-after-dbcheck-forward-link-corruption.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=dangling)(cn=enterprise admins))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted memberOf member > $tmpldif
    diff -u $tmpldif $release_dir/expected-after-dbcheck-forward-link-corruption.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

oneway_link_corruption() {
    #
    # Step1: add  OU "dangling-ou"
    #
    ldif=$PREFIX_ABS/${RELEASE}/oneway_link_corruption.ldif
    cat > $ldif <<EOF
dn: OU=dangling-ou,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: organizationalUnit
objectGUID: 20600e7c-92bb-492e-9552-f3ed7f8a2cad
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add  msExchConfigurationContainer "dangling-msexch"
    #
    ldif=$PREFIX_ABS/${RELEASE}/oneway_link_corruption2.ldif
    cat > $ldif <<EOF
dn: OU=dangling-from,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: organizationalUnit
seeAlso: OU=dangling-ou,DC=release-4-5-0-pre1,DC=samba,DC=corp
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step3: rename dangling-ou to dangling-ou2
    #
    # Because this is a one-way link we don't fix it at runtime
    #
    out=$(TZ=UTC $ldbrename -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb OU=dangling-ou,DC=release-4-5-0-pre1,DC=samba,DC=corp OU=dangling-ou2,DC=release-4-5-0-pre1,DC=samba,DC=corp)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi
}

dbcheck_oneway_link_corruption() {
    dbcheck "-oneway-link-corruption" "0" "--selftest-check-expired-tombstones"
    return $?
}

check_expected_after_dbcheck_oneway_link_corruption() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-after-dbcheck-oneway-link-corruption.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(ou=dangling-ou)(ou=dangling-ou2)(ou=dangling-from))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted seeAlso > $tmpldif
    diff -u $tmpldif $release_dir/expected-after-dbcheck-oneway-link-corruption.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_dangling_multi_valued() {

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --selftest-check-expired-tombstones --fix --yes
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

dangling_link_does_not_prevent_delete() {

    #
    # Step1: add user "dangling"
    #
    ldif=$PREFIX_ABS/${RELEASE}/backlink_can_be_vanished1.ldif
    dn='CN=dangling-for-vanish,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    cat > $ldif <<EOF
dn: $dn
changetype: add
objectclass: user
samaccountname: dangling-v
objectGUID: fd8a04ac-cea0-4921-b1a6-c173e1155c23
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add a dangling backlink from
    # "CN=dangling-for-vanish" to "CN=Enterprise Admins"
    #
    ldif=$PREFIX_ABS/${RELEASE}/backlink_can_be_vanished2.ldif
    {
	echo "dn: $dn"
	echo "changetype: modify"
	echo "add: memberOf"
	echo "memberOf: <GUID=304ad703-468b-465e-9787-470b3dfd7d75>;<SID=S-1-5-21-4177067393-1453636373-93818738-519>;CN=Enterprise Admins,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    out=$(TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb "$dn")
    if [ "$?" != "0" ]; then
	echo "ldbdel returned:\n$out"
	return 1
    fi
}
    
dangling_link_to_unknown_does_not_prevent_delete() {

    #
    # Step1: add user "dangling"
    #
    ldif=$PREFIX_ABS/${RELEASE}/backlink_can_be_vanished1.ldif
    dn='CN=dangling-for-vanish,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    cat > $ldif <<EOF
dn: $dn
changetype: add
objectclass: user
samaccountname: dangling-v
objectGUID: a4090081-ac2a-410c-8924-b255375160e8
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add a dangling backlink from
    # "CN=dangling-for-vanish" to "CN=NOT Enterprise Admins"
    #
    ldif=$PREFIX_ABS/${RELEASE}/backlink_can_be_vanished2.ldif
    {
	echo "dn: $dn"
	echo "changetype: modify"
	echo "add: memberOf"
	echo "memberOf: <GUID=09a47bff-0227-44e1-a8e4-63f9e726515d>;<SID=S-1-5-21-4177067393-1453636373-93818738-588>;CN=NOT Enterprise Admins,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    out=$(TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb "$dn")
    if [ "$?" != "0" ]; then
	echo "ldbdel returned:\n$out"
	return 1
    fi
}

dangling_link_to_known_and_unknown_does_not_prevent_delete() {

    #
    # Step1: add user "dangling"
    #
    ldif=$PREFIX_ABS/${RELEASE}/backlink_can_be_vanished1.ldif
    dn='CN=dangling-for-vanish,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp'
    cat > $ldif <<EOF
dn: $dn
changetype: add
objectclass: user
samaccountname: dangling-v
objectGUID: 2882ffb1-31c3-485e-a7fc-184dfafc32d4
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add a dangling backlink from
    # "CN=dangling-for-vanish" to "CN=Enterprise Admins",
    # "CN=dangling-for-vanish" to "CN=NOT Enterprise Admins" and
    # back to ourselves
    #
    ldif=$PREFIX_ABS/${RELEASE}/backlink_can_be_vanished2.ldif
    {
	echo "dn: $dn"
	echo "changetype: modify"
	echo "add: memberOf"
	echo "memberOf: <GUID=304ad703-468b-465e-9787-470b3dfd7d75>;<SID=S-1-5-21-4177067393-1453636373-93818738-519>;CN=Enterprise Admins,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
	echo "memberOf: <GUID=09a47bff-0227-44e1-a8e4-63f9e726515d>;<SID=S-1-5-21-4177067393-1453636373-93818738-588>;CN=NOT Enterprise Admins,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
	echo "memberOf: <GUID=2882ffb1-31c3-485e-a7fc-184dfafc32d4>;CN=dangling-for-vanish,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    out=$(TZ=UTC $ldbdel -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb "$dn")
    if [ "$?" != "0" ]; then
	echo "ldbdel returned:\n$out"
	return 1
    fi
}

remove_directory $PREFIX_ABS/${RELEASE}

testit $RELEASE undump || failed=`expr $failed + 1`
testit "add_two_more_users" add_two_more_users || failed=`expr $failed + 1`
testit "add_four_more_links" add_four_more_links || failed=`expr $failed + 1`
testit "remove_one_link" remove_one_link || failed=`expr $failed + 1`
testit "remove_one_user" remove_one_user || failed=`expr $failed + 1`
testit "move_one_user" move_one_user || failed=`expr $failed + 1`
testit "add_dangling_link" add_dangling_link || failed=`expr $failed + 1`
testit "add_dangling_backlink" add_dangling_backlink || failed=`expr $failed + 1`
testit "add_deleted_dangling_backlink" add_deleted_dangling_backlink || failed=`expr $failed + 1`
testit "revive_links_on_deleted_group" revive_links_on_deleted_group || failed=`expr $failed + 1`
testit "revive_backlink_on_deleted_group" revive_backlink_on_deleted_group || failed=`expr $failed + 1`
testit "add_deleted_target_link" add_deleted_target_link || failed=`expr $failed + 1`
testit "add_deleted_target_backlink" add_deleted_target_backlink || failed=`expr $failed + 1`
testit "dbcheck_dangling" dbcheck_dangling || failed=`expr $failed + 1`
testit "dbcheck_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "check_expected_after_deleted_links" check_expected_after_deleted_links || failed=`expr $failed + 1`
testit "check_expected_after_links" check_expected_after_links || failed=`expr $failed + 1`
testit "check_expected_after_objects" check_expected_after_objects || failed=`expr $failed + 1`
testit "duplicate_member" duplicate_member || failed=`expr $failed + 1`
testit "dbcheck_duplicate_member" dbcheck_duplicate_member || failed=`expr $failed + 1`
testit "check_expected_after_duplicate_links" check_expected_after_duplicate_links || failed=`expr $failed + 1`
testit "duplicate_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "forward_link_corruption" forward_link_corruption || failed=`expr $failed + 1`
testit "dbcheck_forward_link_corruption" dbcheck_forward_link_corruption || failed=`expr $failed + 1`
testit "check_expected_after_dbcheck_forward_link_corruption" check_expected_after_dbcheck_forward_link_corruption || failed=`expr $failed + 1`
testit "forward_link_corruption_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "oneway_link_corruption" oneway_link_corruption || failed=`expr $failed + 1`
testit "dbcheck_oneway_link_corruption" dbcheck_oneway_link_corruption || failed=`expr $failed + 1`
testit "check_expected_after_dbcheck_oneway_link_corruption" check_expected_after_dbcheck_oneway_link_corruption || failed=`expr $failed + 1`
testit "oneway_link_corruption_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "dangling_one_way_link" dangling_one_way_link || failed=`expr $failed + 1`
testit "dbcheck_one_way" dbcheck_one_way || failed=`expr $failed + 1`
testit "dbcheck_clean2" dbcheck_clean || failed=`expr $failed + 1`
testit "missing_link_sid_corruption" missing_link_sid_corruption || failed=`expr $failed + 1`
testit "dbcheck_missing_link_sid_corruption" dbcheck_missing_link_sid_corruption || failed=`expr $failed + 1`
testit "missing_link_sid_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "add_lost_deleted_user1" add_lost_deleted_user1 || failed=`expr $failed + 1`
testit "dbcheck_lost_deleted_user1" dbcheck_lost_deleted_user1 || failed=`expr $failed + 1`
testit "lost_deleted_user1_clean_A" dbcheck_clean || failed=`expr $failed + 1`
testit "remove_lost_deleted_user1" remove_lost_deleted_user1 || failed=`expr $failed + 1`
testit "lost_deleted_user1_clean_B" dbcheck_clean || failed=`expr $failed + 1`
testit "add_lost_deleted_user2" add_lost_deleted_user2 || failed=`expr $failed + 1`
testit "dbcheck_lost_deleted_user2" dbcheck_lost_deleted_user2 || failed=`expr $failed + 1`
testit "lost_deleted_user2_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "add_lost_deleted_user3" add_lost_deleted_user3 || failed=`expr $failed + 1`
testit "dbcheck_lost_deleted_user3" dbcheck_lost_deleted_user3 || failed=`expr $failed + 1`
testit "lost_deleted_user3_clean_A" dbcheck_clean || failed=`expr $failed + 1`
testit "remove_lost_deleted_user3" remove_lost_deleted_user3 || failed=`expr $failed + 1`
testit "lost_deleted_user3_clean_B" dbcheck_clean || failed=`expr $failed + 1`
testit "dangling_one_way_dn" dangling_one_way_dn || failed=`expr $failed + 1`
testit "deleted_one_way_dn" deleted_one_way_dn || failed=`expr $failed + 1`
testit "dbcheck_clean3" dbcheck_clean || failed=`expr $failed + 1`
testit "add_dangling_multi_valued" add_dangling_multi_valued || failed=`expr $failed + 1`
testit "dbcheck_dangling_multi_valued" dbcheck_dangling_multi_valued || failed=`expr $failed + 1`
testit "dangling_multi_valued_check_missing" dangling_multi_valued_check_missing || failed=`expr $failed + 1`
testit "dangling_multi_valued_check_equal_or_too_many" dangling_multi_valued_check_equal_or_too_many || failed=`expr $failed + 1`
# Currently this cannot pass
testit "dbcheck_dangling_multi_valued_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "dangling_link_does_not_prevent_delete" dangling_link_does_not_prevent_delete || failed=`expr $failed + 1`
testit "dangling_link_to_unknown_does_not_prevent_delete" dangling_link_to_unknown_does_not_prevent_delete || failed=`expr $failed + 1`
testit "dangling_link_to_known_and_unknown_does_not_prevent_delete" dangling_link_to_known_and_unknown_does_not_prevent_delete || failed=`expr $failed + 1`

remove_directory $PREFIX_ABS/${RELEASE}

exit $failed
