#!/usr/bin/env bash

# Verify that 'ctdb dumpmemory' shows expected output

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

pat='^([[:space:]].+[[:space:]]+contains[[:space:]]+[[:digit:]]+ bytes in[[:space:]]+[[:digit:]]+ blocks \(ref [[:digit:]]+\)[[:space:]]+0x[[:xdigit:]]+|[[:space:]]+reference to: .+|full talloc report on .+ \(total[[:space:]]+[[:digit:]]+ bytes in [[:digit:]]+ blocks\))$'

try_command_on_node -v 0 "$CTDB dumpmemory"
sanity_check_output 10 "$pat"

echo
try_command_on_node -v 0 "$CTDB rddumpmemory"
sanity_check_output 10 "$pat"
