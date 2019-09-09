#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb dumpmemory' shows expected output.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb dumpmemory' and verify that it shows expected output

Expected results:

* 'ctdb dumpmemory' sows valid output.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

pat='^([[:space:]].+[[:space:]]+contains[[:space:]]+[[:digit:]]+ bytes in[[:space:]]+[[:digit:]]+ blocks \(ref [[:digit:]]+\)[[:space:]]+0x[[:xdigit:]]+|[[:space:]]+reference to: .+|full talloc report on .+ \(total[[:space:]]+[[:digit:]]+ bytes in [[:digit:]]+ blocks\))$'

try_command_on_node -v 0 "$CTDB dumpmemory"
sanity_check_output 10 "$pat"

echo
try_command_on_node -v 0 "$CTDB rddumpmemory"
sanity_check_output 10 "$pat"
