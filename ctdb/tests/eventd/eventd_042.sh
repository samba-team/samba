#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "releaseip event"

cat > "$eventd_scriptdir/01.test" <<EOF
#!/bin/sh

echo \$*
if [ \$# -ne 4 ] ; then
    echo "Wrong number of arguments"
    exit 2
fi
exit 0
EOF
chmod +x "$eventd_scriptdir/01.test"

setup_eventd

required_result 1 <<EOF
Insufficient arguments for event releaseip
EOF
simple_test run releaseip 30

required_result 0 <<EOF
Event releaseip has never run
EOF
simple_test status releaseip lastrun

required_result 0 <<EOF
EOF
simple_test run releaseip 30 eth0 192.168.1.1 24

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status releaseip lastrun

required_result 0 <<EOF
01.test              OK         DURATION DATETIME
EOF
simple_test status releaseip lastpass

required_result 0 <<EOF
Event releaseip has never failed
EOF
simple_test status releaseip lastfail
