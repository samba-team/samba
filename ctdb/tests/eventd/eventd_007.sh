#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "capture event script output"

setup_eventd

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

echo "args: \$*"
exit 1
EOF
chmod +x "$eventd_scriptdir/01.test"

required_result 1 <<EOF
Failed to run event monitor, result=1
EOF
simple_test run monitor 30

required_result 1 <<EOF
01.test              ERROR      DURATION DATETIME
  OUTPUT: args: monitor
EOF
simple_test status monitor lastrun

required_result 0 <<EOF
Event monitor has never passed
EOF
simple_test status monitor lastpass

required_result 1 <<EOF
01.test              ERROR      DURATION DATETIME
  OUTPUT: args: monitor
EOF
simple_test status monitor lastfail
