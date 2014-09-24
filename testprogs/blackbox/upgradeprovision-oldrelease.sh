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

. `dirname $0`/subunit.sh

release_dir=`dirname $0`/../../source4/selftest/provisions/${RELEASE}

LDBDEL_BIN=ldbdel
if [ -x "$BINDIR/ldbdel" ]; then
	LDBDEL_BIN=$BINDIR/ldbdel
fi

undump() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/${RELEASE}_upgrade $BINDIR/tdbrestore
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/${RELEASE}_upgrade_full $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/${RELEASE}_upgrade
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/${RELEASE}_upgrade_full
       fi
       cp -a $release_dir/private/*.keytab $PREFIX_ABS/${RELEASE}_upgrade/private/
       cp -a $release_dir/sysvol $PREFIX_ABS/${RELEASE}_upgrade/
       mkdir $PREFIX_ABS/${RELEASE}_upgrade/etc/
       cat $release_dir/etc/smb.conf.template | \
              sed "s|@@PREFIX@@|$PREFIX_ABS/${RELEASE}_upgrade|g" \
        >  $PREFIX_ABS/${RELEASE}_upgrade/etc/smb.conf

       cp -a $release_dir/private/*.keytab $PREFIX_ABS/${RELEASE}_upgrade_full/private/
       cp -a $release_dir/sysvol $PREFIX_ABS/${RELEASE}_upgrade_full/
       mkdir $PREFIX_ABS/${RELEASE}_upgrade_full/etc/
       cat $release_dir/etc/smb.conf.template | \
              sed "s|@@PREFIX@@|$PREFIX_ABS/${RELEASE}_upgrade_full|g" \
        >  $PREFIX_ABS/${RELEASE}_upgrade_full/etc/smb.conf
}

remove_dns_user() {
    if [ x$RELEASE != x"release-4-0-0" ]; then
       # This is done, because otherwise the upgrdeprovision will not run without --full
       ${LDBDEL_BIN} -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb cn=dns,cn=users,dc=${RELEASE},dc=samba,dc=corp
    fi
}

reindex() {
       $BINDIR/samba-tool dbcheck --reindex -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck() {
       $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb $@
}

dbcheck_clean() {
       $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck_full() {
       $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb $@
}

dbcheck_full_clean() {
       $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb $@
}

# This checks that after the upgrade, the well known ACLs are correct, so this reset should not want to do anything
dbcheck_full_clean_well_known_acls() {
       $BINDIR/samba-tool dbcheck --reset-well-known-acls --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}_upgrade_full/private/sam.ldb $@
}

upgradeprovision() {
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX_ABS/${RELEASE}_upgrade/etc/smb.conf" --debugchange
}

upgradeprovision_full() {
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX_ABS/${RELEASE}_upgrade_full/etc/smb.conf" --full --debugchange
}

samba_upgradedns() {
        $PYTHON $BINDIR/samba_upgradedns --dns-backend=SAMBA_INTERNAL -s "$PREFIX_ABS/${RELEASE}_upgrade_full/etc/smb.conf"
}

referenceprovision() {
        $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=SAMBA --host-name=ares --realm=${RELEASE}.samba.corp --targetdir=$PREFIX_ABS/${RELEASE}_upgrade_reference --use-ntvfs --host-ip=127.0.0.1 --host-ip6=::1 --function-level=2003
}

ldapcmp() {
    if [ x$RELEASE != x"alpha13" ]; then
         $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_upgrade_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}_upgrade/private/sam.ldb --two --skip-missing-dn --filter=dnsRecord
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

if [ -d $PREFIX_ABS/${RELEASE}_upgrade ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_upgrade
fi

if [ -d $PREFIX_ABS/${RELEASE}_upgrade_full ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_upgrade_full
fi

if [ -d $PREFIX_ABS/${RELEASE}_upgrade_reference ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_upgrade_reference
fi

if [ -d $release_dir ]; then
    testit $RELEASE undump
    testit "remove_dns_user" remove_dns_user
    testit "upgradeprovision" upgradeprovision
    testit "upgradeprovision_full" upgradeprovision_full
    testit "reindex" reindex
    testit_expect_failure "dbcheck" dbcheck
    testit_expect_failure "dbcheck_full" dbcheck_full
    testit "dbcheck_clean" dbcheck_clean
    testit "dbcheck_full_clean" dbcheck_full_clean
    testit "dbcheck_full_clean_well_known_acls" dbcheck_full_clean_well_known_acls
    testit "referenceprovision" referenceprovision
    testit "samba_upgradedns" samba_upgradedns
    testit "ldapcmp" ldapcmp
    testit "ldapcmp_sd" ldapcmp_sd
    testit "ldapcmp_full_sd" ldapcmp_full_sd
else
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
fi

if [ -d $PREFIX_ABS/${RELEASE}_upgrade ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_upgrade
fi

if [ -d $PREFIX_ABS/${RELEASE}_upgrade_full ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_upgrade_full
fi

if [ -d $PREFIX_ABS/${RELEASE}_upgrade_reference ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_upgrade_reference
fi

exit $failed
