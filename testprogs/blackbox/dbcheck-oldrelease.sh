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

release_dir=`dirname $0`/../../source4/selftest/provisions/$RELEASE

undump() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE $BINDIR/tdbrestore
       else
	`dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE
       fi
}

reindex() {
       $PYTHON $BINDIR/samba-tool dbcheck --reindex -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}
# But having fixed it all up, this should pass
dbcheck_clean() {
       $PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck_acl_reset() {
       $PYTHON $BINDIR/samba-tool dbcheck --reset-well-known-acls --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}
# But having fixed it all up, this should pass
dbcheck_acl_reset_clean() {
       $PYTHON $BINDIR/samba-tool dbcheck --reset-well-known-acls --cross-ncs -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $@
}

referenceprovision() {
        $PYTHON $BINDIR/samba-tool domain provision --server-role="dc" --domain=SAMBA --host-name=ares --realm=${RELEASE}.samba.corp --targetdir=$PREFIX_ABS/${RELEASE}_reference --use-ntvfs --host-ip=127.0.0.1 --host-ip6=::1
}

ldapcmp() {
    if [ x$RELEASE != x"alpha13" ]; then
         $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --two --skip-missing-dn --filter=dnsRecord
    fi
}

ldapcmp_sd() {
    if [ x$RELEASE != x"alpha13" ]; then
        $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/${RELEASE}_reference/private/sam.ldb tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --two --sd --skip-missing-dn
    fi
}

if [ -d $release_dir ]; then
    testit $RELEASE undump
    testit "reindex" reindex
    testit_expect_failure "dbcheck" dbcheck
    testit "dbcheck_clean" dbcheck_clean
    testit_expect_failure "dbcheck_acl_reset" dbcheck_acl_reset
    testit "dbcheck_acl_reset_clean" dbcheck_acl_reset_clean
    testit "referenceprovision" referenceprovision
    testit "ldapcmp" ldapcmp
    testit "ldapcmp_sd" ldapcmp_sd
else
    subunit_start_test $RELEASE
    subunit_skip_test $RELEASE <<EOF
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
    subunit_start_test "dbcheck_acl_reset"
    subunit_skip_test "dbcheck_acl_reset" <<EOF
no test provision
EOF
    subunit_start_test "dbcheck_clean_acl_reset"
    subunit_skip_test "dbcheck_clean_acl_reset" <<EOF
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
    subunit_start_test "ldapcmp_sd"
    subunit_skip_test "ldapcmp_sd" <<EOF
no test provision
EOF
fi

if [ -d $PREFIX_ABS/${RELEASE} ]; then
  rm -fr $PREFIX_ABS/${RELEASE}
fi

if [ -d $PREFIX_ABS/${RELEASE}_reference ]; then
  rm -fr $PREFIX_ABS/${RELEASE}_reference
fi

exit $failed
