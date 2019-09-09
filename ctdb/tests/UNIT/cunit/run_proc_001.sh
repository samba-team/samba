#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

# Invalid path
ok <<EOF
Process exited with error $(errcode ENOENT)
EOF
unit_test run_proc_test 0 -1 /a/b/c

# Non-executable path
prog=$(TMPDIR="$CTDB_TEST_TMP_DIR" mktemp)
cat > "$prog" <<EOF
echo hello
EOF

ok <<EOF
Process exited with error $(errcode EACCES)
EOF
unit_test run_proc_test 0 -1 "$prog"

# Executable path
chmod +x "$prog"

ok <<EOF
Process exited with error $(errcode ENOEXEC)
EOF
unit_test run_proc_test 0 -1 "$prog"

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
unit_test run_proc_test 0 -1 "$prog"

# Specify timeout
ok <<EOF
Process exited with status 0
Output = (hello
)
EOF
unit_test run_proc_test 5 -1 "$prog"

# Redirected output
output=$(TMPDIR="$CTDB_TEST_TMP_DIR" mktemp)
cat > "$prog" <<EOF
#!/bin/sh
exec >"$output" 2>&1
echo hello
EOF

ok <<EOF
Process exited with status 0
EOF
unit_test run_proc_test 0 -1 "$prog"

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
unit_test run_proc_test 0 -1 "$prog"

# Exit with signal
cat > "$prog" <<EOF
#!/bin/sh
kill \$$
EOF

ok <<EOF
Process exited with signal 15
EOF
unit_test run_proc_test 0 -1 "$prog"

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
Process exited with error $(errcode ETIMEDOUT)
Child = PID
Output = (Sleeping for 5 seconds
)
EOF
unit_test run_proc_test 1 -1 "$prog"

# No zombie processes
pidfile=$(TMPDIR="$CTDB_TEST_TMP_DIR" mktemp)

cat > "$prog" <<EOF
#!/bin/sh
echo \$$ > "$pidfile"
sleep 10
EOF

ok <<EOF
Process exited with error $(errcode ETIMEDOUT)
Child = PID
EOF
unit_test run_proc_test 1 -1 "$prog"

result_filter ()
{
	_header="  *PID  *TTY  *TIME  *CMD"
	_header2=" *PID  *TT  *STAT  *TIME  *COMMAND"
	sed -e "s|^${_header}|HEADER|" -e "s|^${_header2}|HEADER|"
}

pid=$(cat "$pidfile")
required_result 1 <<EOF
HEADER
EOF
unit_test ps -p "$pid"

# Redirect stdin
cat > "$prog" <<EOF
#!/bin/sh
cat -
EOF

cat > "$output" <<EOF
this is sample input
EOF

ok <<EOF
Process exited with status 0
Output = (this is sample input
)
EOF
(unit_test run_proc_test 0 4 "$prog") 4<"$output"

rm -f "$pidfile"
rm -f "$output"
rm -f "$prog"
