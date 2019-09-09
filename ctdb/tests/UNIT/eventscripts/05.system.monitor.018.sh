#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check (custom, both), check throttling of warnings"

setup

setup_script_options <<EOF
CTDB_MONITOR_MEMORY_USAGE="70:80"
EOF

# Below threshold, nothing logged
set_mem_usage 67 67
ok_null
simple_test

set_mem_usage 71 71
ok "WARNING: System memory utilization 71% >= threshold 70%"
simple_test

# 2nd time at same level, nothing logged
set_mem_usage 71 71
ok_null
simple_test

set_mem_usage 73 73
ok "WARNING: System memory utilization 73% >= threshold 70%"
simple_test

# 2nd time at same level, nothing logged
set_mem_usage 73 73
ok_null
simple_test

set_mem_usage 79 79
ok "WARNING: System memory utilization 79% >= threshold 70%"
simple_test

set_mem_usage 80 80
required_result 1 <<EOF
ERROR: System memory utilization 80% >= threshold 80%
$FAKE_PROC_MEMINFO
$(ps foobar)
EOF
simple_test

# Fall back into warning at same level as last warning... should log
set_mem_usage 79 79
ok "WARNING: System memory utilization 79% >= threshold 70%"
simple_test

# Below threshold, notice
set_mem_usage 69 69
ok <<EOF
NOTICE: System memory utilization 69% < threshold 70%
EOF
simple_test

# Further reduction, nothing logged
set_mem_usage 68 68
ok_null
simple_test

# Back up into warning at same level as last warning... should log
set_mem_usage 79 79
ok "WARNING: System memory utilization 79% >= threshold 70%"
simple_test

# Back up above critical threshold... unhealthy
set_mem_usage 81 81
required_result 1 <<EOF
ERROR: System memory utilization 81% >= threshold 80%
$FAKE_PROC_MEMINFO
$(ps foobar)
EOF
simple_test

# Straight back down to a good level... notice
set_mem_usage 65 65
ok "NOTICE: System memory utilization 65% < threshold 70%"
simple_test
