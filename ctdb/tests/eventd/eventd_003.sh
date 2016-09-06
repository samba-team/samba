#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "disabled event script"

setup_eventd

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

exit 0
EOF

required_result 0 <<EOF
01.test              DISABLED
EOF
simple_test script list

required_result 0 <<EOF
EOF
simple_test script disable 01.test

required_result 0 <<EOF
EOF
simple_test script enable 01.test

required_result 0 <<EOF
01.test             
EOF
simple_test script list

required_result 0 <<EOF
EOF
simple_test script disable 01.test

required_result 0 <<EOF
EOF
simple_test run monitor 30

required_result 0 <<EOF
01.test              DISABLED  
EOF
simple_test status monitor lastrun

required_result 0 <<EOF
01.test              DISABLED  
EOF
simple_test status monitor lastpass

required_result 0 <<EOF
Event monitor has never failed
EOF
simple_test status monitor lastfail
