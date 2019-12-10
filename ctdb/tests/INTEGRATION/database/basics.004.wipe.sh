#!/usr/bin/env bash

# Verify that 'ctdb wipedb' can clear a persistent database:
# 1. Verify that the status on all of the ctdb nodes is 'OK'.
# 2. Create a persistent test database
# 3. Add some records to node 0 and node 1
# 4. Run wipedb on node 0
# 5. verify the database is empty on both node 0 and 1

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

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
