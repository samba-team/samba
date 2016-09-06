#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple scripts"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

sleep 1
EOF

cp "$eventd_scriptdir/01.test" "$eventd_scriptdir/02.test"
cp "$eventd_scriptdir/01.test" "$eventd_scriptdir/03.test"

setup_eventd

required_result 0 <<EOF
01.test              DISABLED
02.test              DISABLED
03.test              DISABLED
EOF
simple_test script list

required_result 0 <<EOF
EOF
simple_test script enable 01.test

required_result 0 <<EOF
EOF
simple_test script enable 02.test

required_result 0 <<EOF
EOF
simple_test script enable 03.test

required_result 0 <<EOF
01.test             
02.test             
03.test             
EOF
simple_test script list

required_result 0 <<EOF
EOF
simple_test run monitor 30

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status monitor lastrun

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              OK         DURATION DATETIME
EOF
simple_test status monitor lastpass

required_result 0 <<EOF
Event monitor has never failed
EOF
simple_test status monitor lastfail
