#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "simple ping"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

result_filter ()
{
	_weekday="[A-Z][a-z][a-z]"
	_month="[A-Z][a-z][a-z]"
	_date="[0-9][0-9]*"
	_time="[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
	_year="[0-9][0-9]*"
	_date_time="${_weekday} ${_month}  *${_date} ${_time} ${_year}"
	_duration="(000 00:00:[0-9][0-9])"
	sed -e "s|${_date_time}\$|DATE/TIME|" \
	    -e "s|[.0-9]* seconds|SEC seconds|" \
	    -e "s|${_duration}|(DURATION)|"
}


ok <<EOF
Current time of node 0        :                DATE/TIME
Ctdbd start time              : (DURATION) DATE/TIME
Time of last recovery/failover: (DURATION) DATE/TIME
Duration of last recovery/failover: SEC seconds
EOF

simple_test
