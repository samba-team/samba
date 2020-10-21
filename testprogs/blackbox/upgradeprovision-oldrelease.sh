#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck.sh PREFIX RELEASE
EOF
exit 1;
fi

PREFIX_ABS="$1"
RELEASE="$2"
shift 2

failed=0

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

release_dir="$SRCDIR_ABS/source4/selftest/provisions/${RELEASE}"

LDBDEL_BIN=ldbdel
if [ -x "$BINDIR/ldbdel" ]; then
	LDBDEL_BIN=$BINDIR/ldbdel
fi

samba_tdbrestore="tdbrestore"
if [ -x "$BINDIR/tdbrestore" ]; then
    samba_tdbrestore="$BINDIR/tdbrestore"
fi

samba_undump="$SRCDIR_ABS/source4/selftest/provisions/undump.sh"
if [ ! -x $samba_undump ] || [ ! -d $release_dir ]; then
    subunit_start_test "${RELEASE}"
    subunit_skip_test "${RELEASE}" <<EOF
no test provision
EOF

    subunit_start_test "remove_dns_user"
    subunit_skip_test "remove_dns_user" <<EOF
no test provision
EOF

    subunit_start_test "upgradeprovision"
    subunit_skip_test "upgradeprovision" <<EOF
no test provision
EOF
    subunit_start_test "upgradeprovision_full"
    subunit_skip_test "upgradeprovision_full" <<EOF
no test provision
EOF
    subunit_start_test "reindex"
    subunit_skip_test "reindex" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck"
    subunit_skip_test "dbcheck" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_clean"
    subunit_skip_test "dbcheck_clean" <<EOF
no test provision
EOF
    # So far, only releases before 4.0.0rc6 need a dbcheck if upgradeprovision has already been run
    if [ x$RELEASE != x"release-4-0-0" ]; then
	subunit_start_test "dbcheck_full"
	subunit_skip_test "dbcheck_full" <<EOF
no test provision
EOF
    fi
    subunit_start_test "dbcheck_full_clean"
    subunit_skip_test "dbcheck_full_clean" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_full_clean_well_known_acls"
    subunit_skip_test "dbcheck_full_clean_well_known_acls" <<EOF
no test provision
EOF
    subunit_start_test "samba_dnsupgrade"
    subunit_skip_test "samba_dnsupgrade" <<EOF
no test provision
EOF
    subunit_start_test "referenceprovision"
    subunit_skip_test "referenceprovision" <<EOF
no test provision
EOF
    subunit_start_test "ldapcmp"
    subunit_skip_test "ldapcmp" <<EOF
no test provision
EOF
    subunit_start_test "ldapcmp_full"
    subunit_skip_test "ldapcmp_full" <<EOF
no test provision
EOF
    subunit_start_test "ldapcmp_sd"
    subunit_skip_test "ldapcmp_sd" <<EOF
no test provision
EOF
    subunit_start_test "ldapcmp_full_sd"
    subunit_skip_test "ldapcmp_full_sd" <<EOF
no test provision
EOF

    exit 0
fi

undump() {
    $samba_undump $release_dir $PREFIX_ABS/${RELEASE}_upgrade $samba_tdbrestore
    $samba_undump $release_dir $PREFIX_ABS/${RELEASE}_upgrade_full $samba_tdbrestore

    cp -a $release_dir/private/*.keytab $PREFIX_ABS/${RELEASE}_upgrade/private/
    cp -a $release_dir/sysvol $PREFIX_ABS/${RELEASE}_upgrade/
    mkdir $PREFIX_ABS/${RELEASE}_upgrade/etc/
    sed -e "s|@@PREFIX@@|$PREFIX_ABS/${RELEASE}_upgrade|g" $release_dir/etc/smb.conf.template \
     >  $PREFIX_ABS/${RELEASE}_upgrade/etc/smb.conf

    cp -a $release_dir/private/*.keytab $PREFIX_ABS/${RELEASE}_upgrade_full/private/
    cp -a $release_dir/sysvol $PREFIX_ABS/${RELEASE}_upgrade_full/
    mkdir $PREFIX_ABS/${RELEASE}_upgrade_full/etc/
    sed -e "s|@@PREFIX@@|$PREFIX_ABS/${RELEASE}_upgrade_full|g" $release_dir/etc/smb.conf.template \
     >  $PREFIX_ABS/${RELEASE}_upgrade_full/etc/smb.conf
}

remove_dns_user() {
    if [ x$RELEASE != x"release-4-0-0" ]; then
       # This is done, because otherwise the upgrdeprovision will not run without --full
       ${LDBDEL_BIN} -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb cn=dns,cn=users,dc=${RELEASE},dc=samba,dc=corp
    fi
}

reindex() {
       $PYTHON $BINDIR/samba-tool dbcheck --reindex -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb $@
}

dbcheck_clean() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck_full() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb $@
}

dbcheck_full_clean() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb $@
}

# This checks that after the upgrade, the well known ACLs are correct, so this reset should not want to do anything
dbcheck_full_clean_well_known_acls() {
       $PYTHON $BINDIR/samba-tool dbcheck --reset-well-known-acls --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb $@
}

upgradeprovision() {
	# bring the really old Samba schema in line with a more recent 2008R2 schema
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX_ABS/${RELEASE}_upgrade/etc/smb.conf" --debugchange

	# on top of this, also apply 2008R2 changes we accidentally missed in the past
	$PYTHON $BINDIR/samba-tool domain schemaupgrade -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb --ldf-file=samba-4.7-missing-for-schema45.ldif,fix-forest-rev.ldf

	# add missing domain prep for 2008R2
	$PYTHON $BINDIR/samba-tool domain functionalprep -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb --domain --function-level 2008_R2
}

upgradeprovision_full() {
	# add missing domain prep for 2008R2
	$PYTHON $BINDIR/samba-tool domain functionalprep -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb --domain --function-level 2008_R2

	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX_ABS/${RELEASE}_upgrade_full/etc/smb.conf" --full --debugchange
}

samba_upgradedns() {
        $PYTHON $BINDIR/samba_upgradedns --dns-backend=SAMBA_INTERNAL -s "$PREFIX_ABS/${RELEASE}_upgrade_full/etc/smb.conf"
}

referenceprovision() {
        $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=SAMBA --host-name=ares --realm=${RELEASE}.samba.corp --targetdir=$PREFIX_ABS/${RELEASE}_upgrade_reference --use-ntvfs --host-ip=127.0.0.1 --host-ip6=::1 --function-level=2003 --base-schema=2008_R2_old
}

ldapcmp() {
    if [ x$RELEASE != x"alpha13" ]; then
         $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_upgrade_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb --two --skip-missing-dn --filter=dnsRecord,displayName,msDS-SupportedEncryptionTypes
    fi
}

ldapcmp_full() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_upgrade_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb --two --filter=dNSProperty,dnsRecord,cn,displayName,versionNumber,systemFlags,msDS-HasInstantiatedNCs --skip-missing-dn
}

ldapcmp_sd() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_upgrade_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb --two --sd --skip-missing-dn
}

ldapcmp_full_sd() {
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_upgrade_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb --two --sd --skip-missing-dn
}

remove_directory $PREFIX_ABS/${RELEASE}_upgrade
remove_directory $PREFIX_ABS/${RELEASE}_upgrade_full
remove_directory $PREFIX_ABS/${RELEASE}_upgrade_reference

testit $RELEASE undump || failed=`expr $failed + 1`
testit "remove_dns_user" remove_dns_user || failed=`expr $failed + 1`
testit "upgradeprovision" upgradeprovision || failed=`expr $failed + 1`
testit "upgradeprovision_full" upgradeprovision_full || failed=`expr $failed + 1`
testit "reindex" reindex || failed=`expr $failed + 1`
testit_expect_failure "dbcheck" dbcheck || failed=`expr $failed + 1`
testit_expect_failure "dbcheck_full" dbcheck_full || failed=`expr $failed + 1`
testit "dbcheck_clean" dbcheck_clean || failed=`expr $failed + 1`
testit "dbcheck_full_clean" dbcheck_full_clean || failed=`expr $failed + 1`
testit "dbcheck_full_clean_well_known_acls" dbcheck_full_clean_well_known_acls || failed=`expr $failed + 1`
testit "referenceprovision" referenceprovision || failed=`expr $failed + 1`
testit "samba_upgradedns" samba_upgradedns || failed=`expr $failed + 1`
testit "ldapcmp" ldapcmp || failed=`expr $failed + 1`
testit "ldapcmp_sd" ldapcmp_sd || failed=`expr $failed + 1`
testit "ldapcmp_full_sd" ldapcmp_full_sd || failed=`expr $failed + 1`

remove_directory $PREFIX_ABS/${RELEASE}_upgrade
remove_directory $PREFIX_ABS/${RELEASE}_upgrade_full
remove_directory $PREFIX_ABS/${RELEASE}_upgrade_reference

exit $failed
