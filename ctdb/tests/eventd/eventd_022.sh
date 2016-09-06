#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "status output in debug script"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

echo "Sleeping for 99 seconds"
sleep 99
EOF
chmod +x "$eventd_scriptdir/01.test"

cat > "$eventd_scriptdir/debug.sh" <<EOF
#!/bin/sh

(
pstree -p -a \$1
ctdb_event "$eventd_socket" status monitor lastrun
) > "$eventd_debug"
EOF
chmod +x "$eventd_scriptdir/debug.sh"

setup_eventd "$eventd_scriptdir/debug.sh"

required_result 62 <<EOF
Event monitor timed out
EOF
simple_test run monitor 5

# wait for debug hung script
sleep 5

required_result 0 <<EOF
01.test,PID $eventd_scriptdir/01.test monitor
  \`-sleep,PID 99
01.test              TIMEDOUT   DATETIME
  OUTPUT: Sleeping for 99 seconds
EOF
unit_test cat "$eventd_debug"
