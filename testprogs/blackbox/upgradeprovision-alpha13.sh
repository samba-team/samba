#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck.sh PREFIX
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

. `dirname $0`/subunit.sh

alpha13_dir=`dirname $0`/../../source4/selftest/provisions/alpha13

alpha13() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $alpha13_dir $PREFIX_ABS/alpha13_upgrade $BINDIR/tdbrestore
	`dirname $0`/../../source4/selftest/provisions/undump.sh $alpha13_dir $PREFIX_ABS/alpha13_upgrade_full $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $alpha13_dir $PREFIX_ABS/alpha13_upgrade
	`dirname $0`/../../source4/selftest/provisions/undump.sh $alpha13_dir $PREFIX_ABS/alpha13_upgrade_full
       fi
       cp -a $alpha13_dir/private/*.keytab $PREFIX_ABS/alpha13_upgrade/private/
       cp -a $alpha13_dir/sysvol $PREFIX_ABS/alpha13_upgrade/
       mkdir $PREFIX_ABS/alpha13_upgrade/etc/
       cat $alpha13_dir/etc/smb.conf.template | \
              sed "s|@@PREFIX@@|$PREFIX_ABS/alpha13_upgrade|g" \
        >  $PREFIX_ABS/alpha13_upgrade/etc/smb.conf

       cp -a $alpha13_dir/private/*.keytab $PREFIX_ABS/alpha13_upgrade_full/private/
       cp -a $alpha13_dir/sysvol $PREFIX_ABS/alpha13_upgrade_full/
       mkdir $PREFIX_ABS/alpha13_upgrade_full/etc/
       cat $alpha13_dir/etc/smb.conf.template | \
              sed "s|@@PREFIX@@|$PREFIX_ABS/alpha13_upgrade_full|g" \
        >  $PREFIX_ABS/alpha13_upgrade_full/etc/smb.conf
}

remove_dns_user() {
       # This is done, because otherwise the upgrdeprovision will not run without --full
       $BINDIR/ldbdel -H tdb://$PREFIX_ABS/alpha13_upgrade/private/sam.ldb cn=dns,cn=users,dc=alpha13,dc=samba,dc=corp
}

reindex() {
       $BINDIR/samba-tool dbcheck --reindex -H tdb://$PREFIX_ABS/alpha13_upgrade/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck() {
       $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/alpha13_upgrade/private/sam.ldb $@
}

dbcheck_clean() {
       $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/alpha13_upgrade/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck_full() {
       $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/alpha13_upgrade_full/private/sam.ldb $@
}

dbcheck_full_clean() {
       $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/alpha13_upgrade_full/private/sam.ldb $@
}

upgradeprovision() {
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX_ABS/alpha13_upgrade/etc/smb.conf" --debugchange
}

upgradeprovision_full() {
	$PYTHON $BINDIR/samba_upgradeprovision -s "$PREFIX_ABS/alpha13_upgrade_full/etc/smb.conf" --full --debugchange
}

if [ -d $PREFIX_ABS/alpha13_upgrade ]; then
  rm -fr $PREFIX_ABS/alpha13_upgrade
fi

if [ -d $PREFIX_ABS/alpha13_upgrade_full ]; then
  rm -fr $PREFIX_ABS/alpha13_upgrade_full
fi

if [ -d $alpha13_dir ]; then
    testit "alpha13" alpha13
    testit "remove_dns_user" remove_dns_user
    testit "upgradeprovision" upgradeprovision
    testit "upgradeprovision_full" upgradeprovision_full
    testit "reindex" reindex
    testit_expect_failure "dbcheck" dbcheck
    testit "dbcheck_clean" dbcheck_clean
    testit_expect_failure "dbcheck_full" dbcheck_full
    testit "dbcheck_full_clean" dbcheck_full_clean
else
    subunit_start_test "alpha13"
    subunit_skip_test "alpha13" <<EOF
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
    subunit_start_test "dbcheck_full"
    subunit_skip_test "dbcheck_full" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_full_clean"
    subunit_skip_test "dbcheck_full_clean" <<EOF
no test provision
EOF
fi

exit $failed
