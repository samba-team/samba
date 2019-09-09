#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "logging check"

setup_eventd

ok_null
simple_test run 10 random verbose

ok <<EOF
ctdb-eventd[PID]: 02.enabled: Running event verbose
EOF
unit_test grep "02.enabled:" "$eventd_logfile"
