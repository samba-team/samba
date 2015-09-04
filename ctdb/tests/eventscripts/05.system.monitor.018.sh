#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Check throttling of warnings"

CTDB_MONITOR_MEMORY_USAGE="70:80"
CTDB_MONITOR_SWAP_USAGE=""

# Below threshold, nothing logged
setup_memcheck 67 0
ok_null
simple_test

setup_memcheck 71 0
ok "WARNING: System memory utilization 71% >= threshold 70%"
simple_test

# 2nd time at same level, nothing logged
setup_memcheck 71 0
ok_null
simple_test

setup_memcheck 73 0
ok "WARNING: System memory utilization 73% >= threshold 70%"
simple_test

# 2nd time at same level, nothing logged
setup_memcheck 73 0
ok_null
simple_test

setup_memcheck 79 0
ok "WARNING: System memory utilization 79% >= threshold 70%"
simple_test

setup_memcheck 80 0
required_result 1 <<EOF
ERROR: System memory utilization 80% >= threshold 80%
MemTotal:        3940712 kB
MemFree:          225268 kB
Buffers:          146120 kB
Cached:          416754 kB
SwapCached:        56016 kB
Active:          2422104 kB
Inactive:        1019928 kB
Active(anon):    1917580 kB
Inactive(anon):   523080 kB
Active(file):     504524 kB
Inactive(file):   496848 kB
Unevictable:        4844 kB
Mlocked:            4844 kB
SwapTotal:       5857276 kB
SwapFree:        5857276 kB
...
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    Aug28   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    Aug28   0:43  \_ [ksoftirqd/0]
...
root         1  0.0  0.0   2976   624 ?        Ss   Aug28   0:07 init [2]
root       495  0.0  0.0   3888  1640 ?        Ss   Aug28   0:00 udevd --daemon
...
[MORE FAKE ps OUTPUT]
EOF
simple_test

# Fall back into warning at same level as last warning... should log
setup_memcheck 79 0
ok "WARNING: System memory utilization 79% >= threshold 70%"
simple_test

# Below threshold, notice
setup_memcheck 69 0
ok <<EOF
NOTICE: System memory utilization 69% < threshold 70%
EOF
simple_test

# Further reduction, nothing logged
setup_memcheck 68 0
ok_null
simple_test

# Back up into warning at same level as last warning... should log
setup_memcheck 79 0
ok "WARNING: System memory utilization 79% >= threshold 70%"
simple_test

# Back up above critical threshold... unhealthy
setup_memcheck 81 0
required_result 1 <<EOF
ERROR: System memory utilization 81% >= threshold 80%
MemTotal:        3940712 kB
MemFree:          225268 kB
Buffers:          146120 kB
Cached:          377347 kB
SwapCached:        56016 kB
Active:          2422104 kB
Inactive:        1019928 kB
Active(anon):    1917580 kB
Inactive(anon):   523080 kB
Active(file):     504524 kB
Inactive(file):   496848 kB
Unevictable:        4844 kB
Mlocked:            4844 kB
SwapTotal:       5857276 kB
SwapFree:        5857276 kB
...
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    Aug28   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    Aug28   0:43  \_ [ksoftirqd/0]
...
root         1  0.0  0.0   2976   624 ?        Ss   Aug28   0:07 init [2]
root       495  0.0  0.0   3888  1640 ?        Ss   Aug28   0:00 udevd --daemon
...
[MORE FAKE ps OUTPUT]
EOF
simple_test

# Straight back down to a good level... notice
setup_memcheck 65 0
ok "NOTICE: System memory utilization 65% < threshold 70%"
simple_test
