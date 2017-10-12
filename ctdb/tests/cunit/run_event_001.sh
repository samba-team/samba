#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

# Invalid path
required_result 1 <<EOF
run_event_init() failed, ret=2
EOF
unit_test run_event_test /a/b/c list

scriptdir=$(mktemp -d --tmpdir="$TEST_VAR_DIR")

# Empty directory
ok <<EOF
No event scripts found
EOF
unit_test run_event_test "$scriptdir" list

cat > "$scriptdir/prog" <<EOF
#!/bin/sh

echo hello
EOF

# Invalid script
ok <<EOF
No event scripts found
EOF
unit_test run_event_test "$scriptdir" list

ok <<EOF
Script enable prog completed with result=22
EOF
unit_test run_event_test "$scriptdir" enable prog

required_result 1 <<EOF
EOF
unit_test test -x "${scriptdir}/prog"

cat > "$scriptdir/10.test.rpmnew" <<EOF
#!/bin/sh

echo hello
EOF
chmod +x "$scriptdir/10.test.rpmnew"

# Invalid script with multiple '.'s
ok <<EOF
No event scripts found
EOF
unit_test run_event_test "$scriptdir" list

ok <<EOF
Script disable 10.test.rpmnew completed with result=22
EOF
unit_test run_event_test "$scriptdir" disable 10.test.rpmnew

ok_null
unit_test test -x "${scriptdir}/10.test.rpmnew"

cat > "$scriptdir/11.foo" <<EOF
#!/bin/sh

echo hello
EOF

# Valid script
ok <<EOF
11.foo
EOF
unit_test run_event_test "$scriptdir" list

ok <<EOF
Script enable 11.foo completed with result=0
EOF
unit_test run_event_test "$scriptdir" enable 11.foo

ok <<EOF
EOF
unit_test test -x "${scriptdir}/11.foo"

ok <<EOF
11.foo: hello
Event monitor completed with result=0
11.foo result=0
EOF
unit_test run_event_test "$scriptdir" run 10 monitor

cat > "$scriptdir/22.bar" <<EOF
#!/bin/sh

exit 1
EOF

# Multiple scripts
ok <<EOF
11.foo
22.bar
EOF
unit_test run_event_test "$scriptdir" list

ok <<EOF
Script enable 22.bar completed with result=0
EOF
unit_test run_event_test "$scriptdir" enable 22.bar

ok <<EOF
11.foo: hello
Event monitor completed with result=1
11.foo result=0
22.bar result=1
EOF
unit_test run_event_test "$scriptdir" run 10 monitor

# Disable script
ok <<EOF
Script disable 22.bar completed with result=0
EOF
unit_test run_event_test "$scriptdir" disable 22.bar

required_result 1 <<EOF
EOF
unit_test test -x "${scriptdir}/22.bar"

ok <<EOF
11.foo: hello
Event monitor completed with result=0
11.foo result=0
22.bar result=-8
EOF
unit_test run_event_test "$scriptdir" run 10 monitor

cat > "$scriptdir/22.bar" <<EOF
#!/bin/sh

sleep 10
EOF

# Timed out script
ok <<EOF
Script enable 22.bar completed with result=0
EOF
unit_test run_event_test "$scriptdir" enable 22.bar

ok <<EOF
11.foo: hello
Event monitor completed with result=-62
11.foo result=0
22.bar result=-62
EOF
unit_test run_event_test "$scriptdir" run 5 monitor

rm -rf "$scriptdir"
exit 0

