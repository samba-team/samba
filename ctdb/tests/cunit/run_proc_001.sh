#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

# Invalid path
ok <<EOF
Process exited with error 2
EOF
unit_test run_proc_test 0 /a/b/c

# Non-executable path
prog=$(mktemp --tmpdir="$TEST_VAR_DIR")
cat > "$prog" <<EOF
echo hello
EOF

ok <<EOF
Process exited with error 13
EOF
unit_test run_proc_test 0 "$prog"

# Executable path
chmod +x "$prog"

ok <<EOF
Process exited with error 8
EOF
unit_test run_proc_test 0 "$prog"

# Capture output
cat > "$prog" <<EOF
#!/bin/sh
echo hello
EOF

ok <<EOF
Process exited with status 0
Output = (hello
)
EOF
unit_test run_proc_test 0 "$prog"

# Specify timeout
ok <<EOF
Process exited with status 0
Output = (hello
)
EOF
unit_test run_proc_test 5 "$prog"

# Redirected output
output=$(mktemp --tmpdir="$TEST_VAR_DIR")
cat > "$prog" <<EOF
#!/bin/sh
exec >"$output" 2>&1
echo hello
EOF

ok <<EOF
Process exited with status 0
EOF
unit_test run_proc_test 0 "$prog"

ok <<EOF
hello
EOF
unit_test cat "$output"

# Exit with error
cat > "$prog" <<EOF
#!/bin/sh
exit 1
EOF

ok <<EOF
Process exited with status 1
EOF
unit_test run_proc_test 0 "$prog"

# Exit with signal
cat > "$prog" <<EOF
#!/bin/sh
kill \$$
EOF

ok <<EOF
Process exited with signal 15
EOF
unit_test run_proc_test 0 "$prog"

# Exit with timeout
cat > "$prog" <<EOF
#!/bin/sh
echo "Sleeping for 5 seconds"
sleep 5
EOF

result_filter ()
{
	_pid="[0-9][0-9]*"
	sed -e "s|= ${_pid}|= PID|"
}

ok <<EOF
Process exited with error 62
Child = PID
Output = (Sleeping for 5 seconds
)
EOF
unit_test run_proc_test 1 "$prog"

# No zombie processes
pidfile=$(mktemp --tmpdir="$TEST_VAR_DIR")

cat > "$prog" <<EOF
#!/bin/sh
echo \$$ > "$pidfile"
sleep 10
EOF

ok <<EOF
Process exited with error 62
Child = PID
EOF
unit_test run_proc_test 1 "$prog"

result_filter ()
{
	_header="  *PID  *TTY  *TIME  *CMD"
	sed -e "s|^${_header}|HEADER|"
}

pid=$(cat "$pidfile")
required_result 1 <<EOF
HEADER
EOF
unit_test ps -p "$pid"

rm -f "$pidfile"
rm -f "$prog"
