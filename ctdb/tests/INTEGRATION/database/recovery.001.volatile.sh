#!/usr/bin/env bash

# Test that recovery correctly handles RSNs

# Recovery can under certain circumstances lead to old record copies
# resurrecting: Recovery selects the newest record copy purely by RSN. At
# the end of the recovery, the leader is the dmaster for all
# records in all (non-persistent) databases. And the other nodes locally
# hold the complete copy of the databases. The bug is that the recovery
# process does not increment the RSN on the leader at the end of
# the recovery. Now clients acting directly on the leader will
# directly change a record's content on the leader without migration
# and hence without RSN bump.  So a subsequent recovery can not tell that
# the leader's copy is newer than the copies on the other nodes, since
# their RSN is the same. Hence, if the leader is not node 0 (or more
# precisely not the active node with the lowest node number), the recovery
# will choose copies from nodes with lower number and stick to these.

# 1. Create a test database
# 2. Add a record with value value1 on leader
# 3. Force a recovery
# 4. Update the record with value value2 on leader
# 5. Force a recovery
# 6. Confirm that the value is value2

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

#
# Main test
#
TESTDB="rec_test.tdb"

status=0

# Make sure node 0 is not the leader
echo "find out which node is leader"
ctdb_onnode 0 leader
leader="$out"
if [ "$leader" = "0" ]; then
    echo "node 0 is leader, disable leader role on node 0"
    #
    # Note:
    # It should be sufficient to run "ctdb setleaderrole off"
    # on node 0 and wait for election and recovery to finish.
    # But there were problems related to this in this automatic
    # test, so for now use "ctdb stop" and "ctdb continue".
    #
    echo "stop node 0"
    try_command_on_node 0 $CTDB stop
    wait_until_node_has_status 0 stopped
    echo "continue node 0"
    try_command_on_node 0 $CTDB continue
    wait_until_node_has_status 0 notstopped

    ctdb_onnode 0 leader
    leader="$out"
    if [ "$leader" = "0" ]; then
	echo "failed to move leader to different node"
	exit 1
    fi
fi

echo "Leader:${leader}"

# Create a temporary non-persistent database to test with
echo "create test database $TESTDB"
ctdb_onnode "$leader" attach "$TESTDB"

# Wipe Test database
echo "wipe test database"
ctdb_onnode "$leader" wipedb "$TESTDB"

# Add a record   key=test1 data=value1
echo "store key(test1) data(value1)"
ctdb_onnode "$leader" writekey "$TESTDB" test1 value1

# Fetch a record   key=test1
echo "read key(test1)"
ctdb_onnode "$leader" readkey "$TESTDB" test1
cat "$outfile"

# Do a recovery
echo "force recovery"
ctdb_onnode "$leader" recover

wait_until_node_has_status "$leader" recovered

# Add a record   key=test1 data=value2
echo "store key(test1) data(value2)"
ctdb_onnode "$leader" writekey "$TESTDB" test1 value2

# Fetch a record   key=test1
echo "read key(test1)"
ctdb_onnode "$leader" readkey "$TESTDB" test1
cat "$outfile"

# Do a recovery
echo "force recovery"
ctdb_onnode "$leader" recover

wait_until_node_has_status "$leader" recovered

# Verify record   key=test1
echo "read key(test1)"
ctdb_onnode "$leader" readkey "$TESTDB" test1
cat "$outfile"
if [ "$out" = "Data: size:6 ptr:[value2]" ]; then
	echo "GOOD: Recovery did not corrupt database"
else
	echo "BAD: Recovery corrupted database"
	status=1
fi

exit $status
