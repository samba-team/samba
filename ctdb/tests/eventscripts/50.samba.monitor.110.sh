#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "port 139 down, ctdb checktcpport/nmap not implemented, debug"

ctdb_not_implemented "checktcpport"
export FAKE_NMAP_NOT_FOUND="yes"

export CTDB_SCRIPT_DEBUGLEVEL=4

setup_nmap_output_filter

setup_samba
tcp_port_down 139

required_result 1 <<EOF
DEBUG: ctdb_check_ports - checker ctdb not implemented
DEBUG: output from checker was:
DEBUG: ctdb checktcpport 445 (exited with 1) with output:
$ctdb_not_implemented
DEBUG: ctdb_check_ports - checker nmap not implemented
DEBUG: output from checker was:
DEBUG: sh: nmap: command not found
ERROR: samba tcp port 139 is not responding
DEBUG: netstat -l -t -n shows this output:
DEBUG: Active Internet connections (servers only)
DEBUG: Proto Recv-Q Send-Q Local Address           Foreign Address         State
DEBUG: tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN
EOF

simple_test
