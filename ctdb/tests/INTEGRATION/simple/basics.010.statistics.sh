#!/usr/bin/env bash

# Verify that 'ctdb statistics' works as expected

# This is pretty superficial and could do more validation.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

pattern='^(CTDB version 1|Current time of statistics[[:space:]]*:.*|Statistics collected since[[:space:]]*:.*|Gathered statistics for [[:digit:]]+ nodes|[[:space:]]+[[:alpha:]_]+[[:space:]]+[[:digit:]]+|[[:space:]]+(node|client|timeouts|locks)|[[:space:]]+([[:alpha:]_]+_latency|max_reclock_[[:alpha:]]+)[[:space:]]+[[:digit:]-]+\.[[:digit:]]+[[:space:]]sec|[[:space:]]*(locks_latency|reclock_ctdbd|reclock_recd|call_latency|lockwait_latency|childwrite_latency)[[:space:]]+MIN/AVG/MAX[[:space:]]+[-.[:digit:]]+/[-.[:digit:]]+/[-.[:digit:]]+ sec out of [[:digit:]]+|[[:space:]]+(hop_count_buckets|lock_buckets):[[:space:][:digit:]]+)$'

try_command_on_node -v 1 "$CTDB statistics"

sanity_check_output 40 "$pattern"
