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

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

if ! try_command_on_node -v 0 "rpm -qf $0" ; then
    echo "No useful output from rpm, SKIPPING rest of test".
    exit 0
fi
rpm_ver="${out#ctdb-tests-}"
# Some version of RPM append the architecture to the version.
# And also remove the release suffix.
arch=$(uname -m)
rpm_ver="${rpm_ver%-*.${arch}}"

try_command_on_node -v 0 "$CTDB version"
ctdb_ver="${out#CTDB version: }"

if [ "$ctdb_ver" = "$rpm_ver" ] ; then
    echo "OK: CTDB version = RPM version"
else
    echo "BAD: CTDB version != RPM version"
    testfailures=1
fi
