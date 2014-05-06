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
2. Create a persistent test database
3. Add some records to node #0 and node #1
4. Perform wipedb on node #0 and verify the database is empty on both node 0 and 1

Expected results:

* An empty database will result

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)

# 2.
test_db="persistent_test.tdb"
echo "Create persistent test database \"$test_db\""
try_command_on_node 0 $CTDB attach "$test_db" persistent

# 3.
# add one record to node 0   key==ABC  data==ABC
echo "Store key(ABC) data(ABC) on node 0"
db_ctdb_tstore 0 "$test_db" "ABC" "ABC"

# add one record to node 1   key==DEF  data==DEF
echo "Store key(DEF) data(DEF) on node 1"
db_ctdb_tstore 1 "$test_db" "DEF" "DEF"

# 4.
echo "Wipe database"
try_command_on_node 0 $CTDB wipedb "$test_db"

# check that the database is wiped
num_records=$(db_ctdb_cattdb_count_records 1 "$test_db")
if [ $num_records = "0" ] ; then
    echo "OK: Database was wiped"
else
    echo "BAD: We did not end up with an empty database"
    exit 1
fi

echo "Force a recovery"
try_command_on_node 0 $CTDB recover

# check that the database is wiped
num_records=$(db_ctdb_cattdb_count_records 1 "$test_db")
if [ $num_records = "0" ] ; then
    echo "OK: Database was wiped"
else
    echo "BAD: We did not end up with an empty database"
    exit 1
fi
