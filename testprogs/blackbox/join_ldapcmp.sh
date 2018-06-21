#!/bin/sh
# Does a join against the testenv's DC and then runs ldapcmp on the resulting DB

. `dirname $0`/subunit.sh

TARGET_DIR="$PREFIX_ABS/join_$SERVER"

cleanup_output_dir()
{
    if [ -d $TARGET_DIR ]; then
        rm -fr $TARGET_DIR
    fi
}

SAMBA_TOOL="$PYTHON $BINDIR/samba-tool"

join_dc() {
    JOIN_ARGS="--targetdir=$TARGET_DIR --server=$SERVER -U$USERNAME%$PASSWORD"
    $SAMBA_TOOL domain join $REALM dc $JOIN_ARGS --option="netbios name = TESTJOINDC"
}

ldapcmp_result() {
    DB1_PATH="tdb://$PREFIX_ABS/$SERVER/private/sam.ldb"
    DB2_PATH="tdb://$TARGET_DIR/private/sam.ldb"

    # interSiteTopologyGenerator gets periodically updated. With the restored
    # testenvs, it can sometimes point to the old/deleted DC object still
    $SAMBA_TOOL ldapcmp $DB1_PATH $DB2_PATH --filter=interSiteTopologyGenerator
}

cleanup_output_dir

# check that we can join this DC
testit "check_dc_join" join_dc

# check resulting DB matches server DC
testit "new_db_matches" ldapcmp_result

cleanup_output_dir

exit $failed
