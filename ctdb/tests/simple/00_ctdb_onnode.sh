#!/bin/bash

test_info()
{
    cat <<EOF
Use 'onnode' to confirm connectivity between all cluster nodes.

Steps:

1. Do a recursive "onnode all" to make sure all the nodes can connect
   to each other.  On a cluster this ensures that SSH keys are known
   between all hosts, which will stop output being corrupted with
   messages about nodes being added to the list of known hosts.

Expected results:

* 'onnode' works between all nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"


# 

echo "Checking connectivity between nodes..."
onnode all onnode -p all hostname
