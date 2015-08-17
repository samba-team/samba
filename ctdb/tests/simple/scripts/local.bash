# onnode needs CTDB_BASE to be set when run in-tree
if [ -z "$CTDB_BASE" ] ; then
    export CTDB_BASE="$TEST_SUBDIR"
fi

if [ -n "$TEST_LOCAL_DAEMONS" ] ; then
    . "${TEST_SUBDIR}/scripts/local_daemons.bash"
fi
