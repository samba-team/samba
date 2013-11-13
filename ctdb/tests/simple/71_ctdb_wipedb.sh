#!/bin/bash

test_info()
{
    cat <<EOF
The command 'ctdb wipedb' is used to clear a database across the whole
cluster.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. create a persistent test database
3, add some records to node #0 and node #1
4, perform wipedb on node #0 and verify the database is empty on both node 0 and 1

Expected results:

* that 4 will result in empty database

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

# create a temporary persistent database to test with
echo create persistent test database persistent_test.tdb
try_command_on_node 0 $CTDB attach persistent_test.tdb persistent


# 3,
# add one record to node 0   key==ABC  data==ABC
TDB=`try_command_on_node -v 0 $CTDB getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(ABC) data(ABC) on node 0"
try_command_on_node 0 $CTDB tstore $TDB 0x414243 0x070000000000000000000000000000000000000000000000414243
#
# add one record to node 1   key==DEF  data==DEF
TDB=`try_command_on_node -v 1 $CTDB getdbmap | grep persistent_test.tdb | sed -e "s/.*path://" -e "s/ .*//"`
echo "store key(DEF) data(DEF) on node 1"
try_command_on_node 1 $CTDB tstore $TDB 0x444546 0x070000000000000000000000000000000000000000000000444546


# 4,
echo wipe the persistent test database
try_command_on_node 0 $CTDB wipedb persistent_test.tdb
echo force a recovery
try_command_on_node 0 $CTDB recover

# check that the database is wiped
num_records=$(try_command_on_node -v 1 $CTDB cattdb persistent_test.tdb | grep key | wc -l)
[ $num_records != "0" ] && {
    echo "BAD: we did not end up with an empty database"
    exit 1
}
echo "OK. database was wiped"

