#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "multiple events"

setup_eventd

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

echo "args: \$*"

case "\$1" in
startup)
	exit 0
	;;
monitor)
	exit 1
	;;
esac
EOF
chmod +x "$eventd_scriptdir/01.test"

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
