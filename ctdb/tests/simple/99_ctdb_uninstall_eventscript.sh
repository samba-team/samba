#!/bin/bash

test_info()
{
    cat <<EOF
Uninstall the event script used for testing..

Prerequisites:

* Nodes must be accessible via 'onnode'.

Steps:

1. 

Expected results:

* The script is successfully uninstalled from all nodes.
EOF
}

. ctdb_test_functions.bash

uninstall_eventscript "00.ctdb_test_trigger"
