#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "timeouts with multiple scripts"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

case "\$1" in
startup)
	sleep 10
	;;
monitor|ipreallocated)
	exit 0
	;;
esac

EOF
chmod +x "$eventd_scriptdir/01.test"

cat > "$eventd_scriptdir/02.test" <<EOF
#!/bin/sh

case "\$1" in
monitor)
	sleep 10
	;;
startup|ipreallocated)
	exit 0
	;;
esac

EOF
chmod +x "$eventd_scriptdir/02.test"

cat > "$eventd_scriptdir/03.test" <<EOF
#!/bin/sh

case "\$1" in
ipreallocated)
	sleep 10
	;;
startup|monitor)
	exit 0
	;;
esac

EOF
chmod +x "$eventd_scriptdir/03.test"

setup_eventd

required_result 62 <<EOF
Event startup timed out
EOF
simple_test run startup 5

required_result 62 <<EOF
01.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status startup lastrun

required_result 0 <<EOF
Event startup has never passed
EOF
simple_test status startup lastpass

required_result 62 <<EOF
01.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status startup lastfail

required_result 62 <<EOF
Event monitor timed out
EOF
simple_test run monitor 5

required_result 62 <<EOF
01.test              OK         DURATION DATETIME
02.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status monitor lastrun

required_result 0 <<EOF
Event monitor has never passed
EOF
simple_test status monitor lastpass

required_result 62 <<EOF
01.test              OK         DURATION DATETIME
02.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status monitor lastfail

required_result 62 <<EOF
Event ipreallocated timed out
EOF
simple_test run ipreallocated 5

required_result 62 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status ipreallocated lastrun

required_result 0 <<EOF
Event ipreallocated has never passed
EOF
simple_test status ipreallocated lastpass

required_result 62 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              TIMEDOUT   DATETIME
  OUTPUT: 
EOF
simple_test status ipreallocated lastfail
