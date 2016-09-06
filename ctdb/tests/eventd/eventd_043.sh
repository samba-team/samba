#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "updateip event"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

echo \$*
if [ \$# -ne 5 ] ; then
    echo "Wrong number of arguments"
    exit 2
fi
exit 0
EOF
chmod +x "$eventd_scriptdir/01.test"

setup_eventd

required_result 1 <<EOF
Insufficient arguments for event updateip
EOF
simple_test run updateip 30

required_result 0 <<EOF
Event updateip has never run
EOF
simple_test status updateip lastrun

required_result 0 <<EOF
EOF
simple_test run updateip 30 eth0 eth1 192.168.1.1 24

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status updateip lastrun

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status updateip lastpass

required_result 0 <<EOF
Event updateip has never failed
EOF
simple_test status updateip lastfail
