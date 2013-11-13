#!/bin/bash

test_info()
{
    cat <<EOF
Readonly records can be activated at runtime using a ctdb command.
If readonly records are not activated, then any attempt to fetch a readonly
copy should be automatically upgraded to a read-write fetch_lock().

If readonly delegations are present, then any attempt to aquire a read-write
fetch_lock will trigger all delegations to be revoked before the fetch lock
completes.


Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. create a test database and some records
3. try to fetch readonly records, this should not result in any delegations
4. activate readonly support
5. try to fetch readonly records, this should result in delegations
6. do a fetchlock  and the delegations should be revoked
7. try to fetch readonly records, this should result in delegations
8. do a recovery  and the delegations should be revoked

Expected results:

3. No delegations created when db is not in readonly mode
4. It is possible to activate readonly support for a database
5. Delegations should be created
6. Delegations should be revoked
8. Delegations should be revoked


EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

try_command_on_node 0 "$CTDB listnodes"
num_nodes=$(echo "$out" | wc -l)


# create a temporary database to test with
echo create test database test.tdb
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb attach test.tdb


# create some records
try_command_on_node -q all $CTDB_TEST_WRAPPER ctdb_update_record

#
# 3
# try readonly requests
echo Try some readonly fetches, these should all be upgraded to full fetchlocks
try_command_on_node -q 0,1,2 $CTDB_TEST_WRAPPER "ctdb_fetch_readonly_once </dev/null"

# no delegations should have been created
numreadonly=`try_command_on_node -v all $CTDB_TEST_WRAPPER ctdb cattdb test.tdb | grep READONLY | wc -l`
[ "$numreadonly" != "0" ] && {
    echo "BAD: readonly delegations were created, but the feature is not activated on the database"
    exit 1
}


#
# 4
#

echo Activating ReadOnly record support for test.tdb ...
# activate readonly support
try_command_on_node -q all $CTDB_TEST_WRAPPER ctdb setdbreadonly test.tdb
numreadonly=`try_command_on_node -v 0 $CTDB_TEST_WRAPPER ctdb getdbmap | grep READONLY | wc -l`
[ "$numreadonly" != "1" ] && {
    echo BAD: could not activate readonly support for the test database
    exit 1
}



#
# 5
#

echo Create some readonly delegations ...
# fetch record to node 0 and make it dmaster
try_command_on_node -q 1 $CTDB_TEST_WRAPPER ctdb_update_record

# fetch readonly to node 1
try_command_on_node -v 0 $CTDB_TEST_WRAPPER "ctdb_fetch_readonly_once </dev/null"

numreadonly=`try_command_on_node -v all $CTDB_TEST_WRAPPER ctdb cattdb test.tdb | grep RO_HAVE | wc -l`
[ "$numreadonly" != "2" ] && {
    echo BAD: could not create readonly delegation
    exit 1
}




#
# 6
#

echo verify that a fetchlock will revoke the delegations ...
# fetch record to node 0 and make it dmaster
try_command_on_node -q 1 $CTDB_TEST_WRAPPER ctdb_update_record

numreadonly=`try_command_on_node -v all $CTDB_TEST_WRAPPER ctdb cattdb test.tdb | grep RO_HAVE | wc -l`
[ "$numreadonly" != "0" ] && {
    echo BAD: fetchlock did not revoke delegations
    exit 1
}


#
# 7
#

echo Create some readonly delegations ...
# fetch record to node 0 and make it dmaster
try_command_on_node -q 1 $CTDB_TEST_WRAPPER ctdb_update_record

# fetch readonly to node 1
try_command_on_node -v 0 $CTDB_TEST_WRAPPER "ctdb_fetch_readonly_once </dev/null"

numreadonly=`try_command_on_node -v all $CTDB_TEST_WRAPPER ctdb cattdb test.tdb | grep RO_HAVE | wc -l`
[ "$numreadonly" != "2" ] && {
    echo BAD: could not create readonly delegation
    exit 1
}




#
# 8
#

echo verify that a recovery will revoke the delegations ...
try_command_on_node -q 0 $CTDB_TEST_WRAPPER ctdb recover

numreadonly=`try_command_on_node -v all $CTDB_TEST_WRAPPER ctdb cattdb test.tdb | grep RO_HAVE | wc -l`
[ "$numreadonly" != "0" ] && {
    echo BAD: recovery did not revoke delegations
    exit 1
}

echo OK. test completed successfully
exit 0
