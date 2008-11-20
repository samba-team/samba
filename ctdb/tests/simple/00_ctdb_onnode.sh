#!/bin/bash

# Do a recursive "onnode all" to make sure all the nodes can connect
# to each other.  On a cluster this ensures that SSH keys are known
# between all hosts, which will stop output being corrupted with
# messages about nodes being added to the list of known hosts.

. ctdb_test_functions.bash

echo "Checking connectivity between nodes..."
onnode all onnode all true
