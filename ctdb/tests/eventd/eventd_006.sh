#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "timing out event script"

setup_eventd

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

sleep 10
exit 0
EOF
chmod +x "$eventd_scriptdir/01.test"

required_result 62 <<EOF
Event monitor timed out
EOF
simple_test run monitor 5

required_result 62 <<EOF
01.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status monitor lastrun

required_result 0 <<EOF
Event monitor has never passed
EOF
simple_test status monitor lastpass

required_result 62 <<EOF
01.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status monitor lastfail
