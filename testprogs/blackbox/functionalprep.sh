#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: $0 PREFIX
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

failed=0

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

RELEASE="release-4-8-0-pre1"
release_dir="$SRCDIR_ABS/source4/selftest/provisions/$RELEASE"

OLD_RELEASE="release-4-1-0rc3"
old_release_dir="$SRCDIR_ABS/source4/selftest/provisions/$OLD_RELEASE"

samba_tdbrestore="tdbrestore"
if [ -x "$BINDIR/tdbrestore" ]; then
    samba_tdbrestore="$BINDIR/tdbrestore"
fi

samba_undump="$SRCDIR_ABS/source4/selftest/provisions/undump.sh"

if [ ! -x $samba_undump ] || [ ! -d $release_dir ] || [ ! -d $old_release_dir ]; then
    subunit_start_test $RELEASE
    subunit_skip_test $RELEASE <<EOF
no test provision
EOF

    subunit_start_test "functional_prep"
    subunit_skip_test "functional_prep" <<EOF
no test provision
EOF

    subunit_start_test "functional_prep_old"
    subunit_skip_test "functional_prep_old" <<EOF
no test provision
EOF

    exit 0
fi

cleanup_output_directories()
{
    remove_directory $PREFIX_ABS/2012R2_schema
    remove_directory $PREFIX_ABS/$RELEASE
    remove_directory $PREFIX_ABS/$OLD_RELEASE
}

undump() {
    $samba_undump $release_dir $PREFIX_ABS/$RELEASE $samba_tdbrestore
}

undump_old() {
    $samba_undump $old_release_dir $PREFIX_ABS/$OLD_RELEASE $samba_tdbrestore
}


PROVISION_OPTS="--use-ntvfs --host-ip6=::1 --host-ip=127.0.0.1"

provision_2012r2() {
    $PYTHON $BINDIR/samba-tool domain provision $PROVISION_OPTS --domain=REALM --realm=REALM.COM --targetdir=$PREFIX_ABS/2012R2_schema --base-schema=2012_R2 --host-name=FLPREP
}

ldapcmp_ignore() {
    # At some point we will need to ignore, but right now, it should be perfect
    IGNORE_ATTRS=$1
    $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/$2/private/sam.ldb tdb://$PREFIX_ABS/$3/private/sam.ldb --two --skip-missing-dn --filter msDS-SupportedEncryptionTypes,servicePrincipalName
}

ldapcmp() {
    # Our functional prep doesn't set these values as they were not provided
    # These are XML schema based enumerations which are used for claims
    ldapcmp_ignore "msDS-ClaimPossibleValues" "$RELEASE"  "2012R2_schema"
}

functional_prep() {
    $PYTHON $BINDIR/samba-tool domain functionalprep -H tdb://$PREFIX_ABS/2012R2_schema/private/sam.ldb --function-level=2012_R2
}

functional_prep_old() {
    $PYTHON $BINDIR/samba-tool domain functionalprep -H tdb://$PREFIX_ABS/$OLD_RELEASE/private/sam.ldb --function-level=2012_R2
}

steal_roles() {
    # Must steal schema master and infrastructure roles first
    $PYTHON $BINDIR/samba-tool fsmo seize --role=schema -H tdb://$PREFIX_ABS/$OLD_RELEASE/private/sam.ldb --force
    $PYTHON $BINDIR/samba-tool fsmo seize --role=infrastructure -H tdb://$PREFIX_ABS/$OLD_RELEASE/private/sam.ldb --force
}

schema_upgrade() {
    $PYTHON $BINDIR/samba-tool domain schemaupgrade -H tdb://$PREFIX_ABS/$OLD_RELEASE/private/sam.ldb --schema=2012_R2
}

# double-check we cleaned up from the last test run
cleanup_output_directories

testit $RELEASE undump || failed=`expr $failed + 1`

# Provision a DC based on 2012R2 schema
testit "provision_2012R2_schema" provision_2012r2 || failed=`expr $failed + 1`

# Perform functional prep up to 2012 R2 level
testit "functional_prep" functional_prep || failed=`expr $failed + 1`

# check that the databases are now the same
testit "check_databases_same" ldapcmp || failed=`expr $failed + 1`

testit $OLD_RELEASE undump_old || failed=`expr $failed + 1`

testit "steal_roles" steal_roles || failed=`expr $failed + 1`

testit "schema_upgrade" schema_upgrade || failed=`expr $failed + 1`

testit "functional_prep_old" functional_prep_old || failed=`expr $failed + 1`

cleanup_output_directories

exit $failed
