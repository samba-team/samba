#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "queue events"

setup_eventd

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

sleep 5
EOF
chmod +x "$eventd_scriptdir/01.test"

required_result 0 <<EOF
EOF
simple_test_background run startup 30

required_result 0 <<EOF
EOF
simple_test run ipreallocated 30

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
01.test              OK         DURATION DATETIME
EOF
simple_test status ipreallocated lastrun

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status ipreallocated lastpass

required_result 0 <<EOF
Event ipreallocated has never failed
EOF
simple_test status ipreallocated lastfail
