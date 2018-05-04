#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "new component"

setup_eventd

ok_null
mkdir  "${eventd_scriptdir}/foobar"

ok_null
cp "${eventd_scriptdir}/random/01.disabled.script" "${eventd_scriptdir}/foobar"

required_result 22 <<EOF
Event monitor has never run in foobar
EOF
simple_test status foobar monitor

ok_null
simple_test run 10 foobar monitor

ok <<EOF
01.disabled          DISABLED  
EOF
simple_test status foobar monitor

ok_null
simple_test script enable foobar 01.disabled

ok_null
simple_test run 10 foobar monitor

ok <<EOF
01.disabled          OK         DURATION DATETIME
EOF
simple_test status foobar monitor
