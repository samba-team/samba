#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "cancel running monitor event"

setup_eventd

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

sleep 5
EOF
chmod +x "$eventd_scriptdir/01.test"

required_result 125 <<EOF
Event monitor got cancelled
EOF
simple_test_background run monitor 30

required_result 0 <<EOF
EOF
simple_test run startup 30

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status startup lastrun

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status startup lastpass

required_result 0 <<EOF
Event startup has never failed
EOF
simple_test status startup lastfail

required_result 0 <<EOF
Event monitor has never run
EOF
simple_test status monitor lastrun

required_result 0 <<EOF
Event monitor has never passed
EOF
simple_test status monitor lastpass

required_result 0 <<EOF
Event monitor has never failed
EOF
simple_test status monitor lastfail
