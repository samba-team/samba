#!/bin/bash

test_info()
{
    cat <<EOF
Verify the output of the 'ctdb version' command.

This test assumes an RPM-based installation and needs to be skipped on
non-RPM systems.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run the 'ctdb version' command on one of the cluster nodes.
3. Compare the version displayed with that listed by the rpm command
   for the ctdb package.

Expected results:

* The 'ctdb version' command displays the ctdb version number.
EOF
}

. ctdb_test_functions.bash

ctdb_test_init "$@"

set -e

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

if ! try_command_on_node -v 0 "rpm -q ctdb" ; then
    echo "No useful output from rpm, SKIPPING rest of test".
    exit 0
fi
rpm_ver="${out#ctdb-}"

try_command_on_node -v 0 "$CTDB version"
ctdb_ver="${out#CTDB version: }"

if [ "$ctdb_ver" = "$rpm_ver" ] ; then
    echo "OK: CTDB version = RPM version"
else
    echo "BAD: CTDB version != RPM version"
    testfailures=1
fi

ctdb_test_exit
