#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "debug script"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

sleep 99
EOF
chmod +x "$eventd_scriptdir/01.test"

cat > "$eventd_scriptdir/debug.sh" <<EOF
#!/bin/sh

echo "args: \$*" > "$eventd_debug"
EOF
chmod +x "$eventd_scriptdir/debug.sh"

setup_eventd "$eventd_scriptdir/debug.sh"

result_filter ()
{
	_pid="[0-9][0-9]*"
	sed -e "s| ${_pid}| PID|"
}

required_result 62 <<EOF
Event startup timed out
EOF
simple_test run startup 5

# wait for debug hung script
sleep 5

required_result 0 <<EOF
args: PID startup
EOF
unit_test cat "$eventd_debug"
