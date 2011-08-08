#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "port 139 down"

setup_samba
tcp_port_down 139

required_result 1 <<EOF
ERROR: samba tcp port 139 is not responding
netstat -l -t -n shows this output:
Active Internet connections (servers only)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN
EOF

simple_test
