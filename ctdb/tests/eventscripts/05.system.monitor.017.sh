#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Memory check, bad situation, both custom memory checks, causes unhealthy"

setup_memcheck 87 0

CTDB_MONITOR_MEMORY_USAGE="70:80"
CTDB_MONITOR_SWAP_USAGE=""

required_result 1 <<EOF
ERROR: System memory utilization 87% >= threshold 80%
MemTotal:        3940712 kB
MemFree:          225268 kB
Buffers:          146120 kB
Cached:          140904 kB
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
