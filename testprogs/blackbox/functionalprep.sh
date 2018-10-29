#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: $0 PREFIX
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

. `dirname $0`/subunit.sh

RELEASE="release-4-8-0-pre1"
release_dir=`dirname $0`/../../source4/selftest/provisions/$RELEASE

OLD_RELEASE="release-4-1-0rc3"
old_release_dir=`dirname $0`/../../source4/selftest/provisions/$OLD_RELEASE

cleanup_output_directories()
{
    if [ -d $PREFIX_ABS/2012R2_schema ]; then
        rm -fr $PREFIX_ABS/2012R2_schema
    fi

    if [ -d $PREFIX_ABS/$RELEASE ]; then
        rm -fr $PREFIX_ABS/$RELEASE
    fi

    if [ -d $PREFIX_ABS/$OLD_RELEASE ]; then
        rm -fr $PREFIX_ABS/$OLD_RELEASE
    fi
}

undump() {
   if test -x $BINDIR/tdbrestore;
   then
       `dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE $BINDIR/tdbrestore
   else
       `dirname $0`/../../source4/selftest/provisions/undump.sh $release_dir $PREFIX_ABS/$RELEASE
   fi
}

undump_old() {
   if test -x $BINDIR/tdbrestore;
   then
       `dirname $0`/../../source4/selftest/provisions/undump.sh $old_release_dir $PREFIX_ABS/$OLD_RELEASE $BINDIR/tdbrestore
   else
       `dirname $0`/../../source4/selftest/provisions/undump.sh $old_release_dir $PREFIX_ABS/$OLD_RELEASE
   fi
}


PROVISION_OPTS="--use-ntvfs --host-ip6=::1 --host-ip=127.0.0.1"

provision_2012r2() {
    $PYTHON $BINDIR/samba-tool domain provision $PROVISION_OPTS --domain=REALM --realm=REALM.COM --targetdir=$PREFIX_ABS/2012R2_schema --base-schema=2012_R2 --host-name=FLPREP
}

ldapcmp_ignore() {
    # At some point we will need to ignore, but right now, it should be perfect
    IGNORE_ATTRS=$1
    $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/$2/private/sam.ldb tdb://$PREFIX_ABS/$3/private/sam.ldb --two --skip-missing-dn
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

testit $RELEASE undump

# Provision a DC based on 2012R2 schema
testit "provision_2012R2_schema" provision_2012r2

# Perform functional prep up to 2012 R2 level
testit "functional_prep" functional_prep

# check that the databases are now the same
testit "check_databases_same" ldapcmp

testit $OLD_RELEASE undump_old

testit "steal_roles" steal_roles

testit "schema_upgrade" schema_upgrade

testit "functional_prep_old" functional_prep_old

cleanup_output_directories

exit $failed
