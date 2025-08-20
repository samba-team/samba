#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "simple ping"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0
EOF

# Don't panic.  tests/scripts/common.sh sets LANG=C  :-)
result_filter()
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
Current time of node 0        :                Wed Aug 20 11:58:40 2025
Ctdbd start time              : (000 00:00:32) Wed Aug 20 11:58:08 2025
Time of last recovery/failover: (000 00:00:27) Wed Aug 20 11:58:13 2025
Duration of last recovery/failover: 0.033143 seconds
EOF

simple_test
