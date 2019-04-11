#!/bin/bash

test_info()
{
    cat <<EOF
The command 'ctdb restoredb' is used to restore a database across the
whole cluster.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Create a persistent test database
3. Add some records to test database
4. Backup database
5. Wipe database and verify the database is empty on all nodes
6. Restore database and make sure all the records are restored
7. Make sure no recovery has been triggered

Expected results:

* Database operations should not cause a recovery

EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

try_command_on_node 0 $CTDB status
generation=$(sed -n -e 's/^Generation:\([0-9]*\)/\1/p' "$outfile")

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

# 2.
test_db="restoredb_test.tdb"
test_dump=$(mktemp)
echo $test_dump
echo "Create persistent test database \"$test_db\""
try_command_on_node 0 $CTDB attach "$test_db" persistent
try_command_on_node 0 $CTDB wipedb "$test_db"

# 3.
# add 10,000 records to database
echo "Adding 10000 records to database"
(
for i in $(seq 1 10000) ; do
	echo "\"key$i\" \"value$i\""
done
) | try_command_on_node -i 0 $CTDB ptrans "$test_db"

num_records=$(db_ctdb_cattdb_count_records 1 "$test_db")
if [ $num_records = "10000" ] ; then
    echo "OK: Records added"
else
    echo "BAD: We did not end up with 10000 records"
    echo "num records = $num_records"
    exit 1
fi

ctdb_test_exit_hook_add "rm -f $test_dump"

# 4.
echo "Backup database"
try_command_on_node 0 $CTDB backupdb "$test_db" "$test_dump"

# 5.
echo "Wipe database"
try_command_on_node 0 $CTDB wipedb "$test_db"

# check that the database is restored
num_records=$(db_ctdb_cattdb_count_records 1 "$test_db")
if [ $num_records = "0" ] ; then
    echo "OK: Database was wiped"
else
    echo "BAD: We did not end up with an empty database"
    echo "num records = $num_records"
    exit 1
fi

# 6.
echo "Restore database"
try_command_on_node 0 $CTDB restoredb "$test_dump" "$test_db"

# check that the database is restored
num_records=$(db_ctdb_cattdb_count_records 1 "$test_db")
if [ $num_records = "10000" ] ; then
    echo "OK: Database was restored"
else
    echo "BAD: We did not end up with 10000 records"
    echo "num records = $num_records"
    exit 1
fi

# 7.
wait_until_ready

try_command_on_node 0 $CTDB status
new_generation=$(sed -n -e 's/^Generation:\([0-9]*\)/\1/p' "$outfile")

echo "Old generation = $generation"
echo "New generation = $new_generation"

if [ "$generation" = "$new_generation" ]; then
    echo "OK: Database recovery not triggered."
else
    echo "BAD: Database recovery triggered."
    exit 1
fi
