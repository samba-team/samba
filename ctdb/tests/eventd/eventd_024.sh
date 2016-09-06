#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "process terminated after debug"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

echo "Sleeping for 99 seconds"
sleep 99
EOF
chmod +x "$eventd_scriptdir/01.test"

cat > "$eventd_scriptdir/debug.sh" <<EOF
#!/bin/sh

echo \$1 > "$eventd_debug"
EOF
chmod +x "$eventd_scriptdir/debug.sh"

setup_eventd "$eventd_scriptdir/debug.sh"

result_filter()
{
	_pid="[0-9][0-9]*"
	sed -e "s|${_pid}|PID|"
}

required_result 62 <<EOF
Event monitor timed out
EOF
simple_test run monitor 5

# wait for debug hung script
sleep 5

required_result 0 <<EOF
PID
EOF
unit_test cat "$eventd_debug"

pid=$(cat "$eventd_debug")

required_result 0 <<EOF
EOF
unit_test pstree -p -a "$pid"
