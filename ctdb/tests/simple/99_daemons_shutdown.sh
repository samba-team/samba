#!/bin/bash

test_info()
{
    cat <<EOF
If we running local daemons and TEST_CLEANUP is true then shutdown the daemons.

No error if ctdbd is not already running on the cluster.

Prerequisites:

* Nodes must be accessible via 'onnode'.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

# Do not call ctdb_test_init() here.  It will setup ctdb_test_exit()
# to run and that will find the daemons missing and restart them!

# We only want to consider stopping CTDB if we're running local
# daemons.  This function will do the right thing.
maybe_stop_ctdb
