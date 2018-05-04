#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "logging check"

cat > "$eventd_scriptdir/01.test.script" <<EOF
#!/bin/sh

echo "Running event \$1"
EOF
chmod +x "$eventd_scriptdir/01.test.script"

setup_eventd

required_result 0 <<EOF
EOF
simple_test run monitor 30

required_result 0 <<EOF
ctdb-eventd[PID]: 01.test: Running event monitor
EOF
unit_test grep "01.test:" "$eventd_logfile"
