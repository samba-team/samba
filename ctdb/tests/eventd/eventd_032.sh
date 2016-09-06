#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "failures with multiple scripts"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

case "\$1" in
startup)
	exit 1
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
	exit 2
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
	exit 3
	;;
startup|monitor)
	exit 0
	;;
esac

EOF
chmod +x "$eventd_scriptdir/03.test"

setup_eventd

required_result 1 <<EOF
Failed to run event startup, result=1
EOF
simple_test run startup 30

required_result 1 <<EOF
01.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status startup

required_result 0 <<EOF
Event startup has never passed
EOF
simple_test status startup lastpass

required_result 1 <<EOF
01.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status startup lastfail

required_result 2 <<EOF
Failed to run event monitor, result=2
EOF
simple_test run monitor 30

required_result 2 <<EOF
01.test              OK         DURATION DATETIME
02.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status monitor

required_result 0 <<EOF
Event monitor has never passed
EOF
simple_test status monitor lastpass

required_result 2 <<EOF
01.test              OK         DURATION DATETIME
02.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status monitor lastfail

required_result 3 <<EOF
Failed to run event ipreallocated, result=3
EOF
simple_test run ipreallocated 30

required_result 3 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status ipreallocated

required_result 0 <<EOF
Event ipreallocated has never passed
EOF
simple_test status ipreallocated lastpass

required_result 3 <<EOF
01.test              OK         DURATION DATETIME
02.test              OK         DURATION DATETIME
03.test              ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status ipreallocated lastfail
