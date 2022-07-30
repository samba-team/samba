#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

epipe=$(errcode EPIPE)
etimedout=$(errcode ETIMEDOUT)
edom=$(errcode EDOM)

test_cases()
{
	test_case "no packets, sender exits, 3s timeout"
	ok <<EOF
WRITER OK
READER ERR=$epipe
EOF
	unit_test tmon_test "" false 3 false

	test_case "no packets, sender exits, 3s timeout, close ok"
	ok <<EOF
WRITER OK
READER OK
EOF
	unit_test tmon_test "" true 3 false

	test_case "Exit packet @ 1s, no timeout"
	ok <<EOF
READER OK
WRITER OK
EOF
	unit_test tmon_test "0" false 0 false

	test_case "errno 7 packet @ 1s, no timeout"
	ok <<EOF
READER ERR=7
WRITER OK
EOF
	unit_test tmon_test "7" false 0 false

	test_case "errno 110 packet @ 1s, no timeout"
	ok <<EOF
READER ERR=110
WRITER OK
EOF
	unit_test tmon_test "#110" false 0 false

	test_case "errno 0 error causes EDOM @ 1s, no timeout"
	ok <<EOF
WRITER ERR=$edom
READER ERR=$epipe
EOF
	unit_test tmon_test "#0;" false 0 false

	test_case "errno -1 error causes EDOM @ 1s, no timeout"
	ok <<EOF
WRITER ERR=$edom
READER ERR=$epipe
EOF
	unit_test tmon_test "#-1;" false 0 false

	test_case "errno 70000 error causes EDOM @ 1s, no timeout"
	ok <<EOF
WRITER ERR=$edom
READER ERR=$epipe
EOF
	unit_test tmon_test "#70000;!0" false 0 false

	test_case "Exit packet @ 3s, no timeout"
	ok <<EOF
READER OK
WRITER OK
EOF
	unit_test tmon_test "..0" false 0 false

	test_case "errno 7 packet @ 3s, no timeout"
	ok <<EOF
READER ERR=7
WRITER OK
EOF
	unit_test tmon_test "..7" false 0 false

	test_case "no packets for 5s, 3s timeout"
	ok <<EOF
READER ERR=$etimedout
WRITER OK
EOF
	unit_test tmon_test "....." false 3 false

	test_case "no packets for 5s, 3s timeout, timeout ok"
	ok <<EOF
READER OK
WRITER OK
EOF
	unit_test tmon_test "....." false 3 true

	test_case "4 pings then exit, 3s timeout"
	ok <<EOF
PING
PING
PING
PING
READER OK
WRITER OK
EOF
	unit_test tmon_test "!!!!0" false 3 false

	test_case "ASCII Hello, errno 7, 3s timeout"
	ok <<EOF
ASCII H
ASCII e
ASCII l
ASCII l
ASCII o
READER ERR=7
WRITER OK
EOF
	unit_test tmon_test "Hello7" false 3 false

	test_case "Hi there! 3s timeout"
	ok <<EOF
ASCII H
ASCII i
CUSTOM 0x20
ASCII t
ASCII h
ASCII e
ASCII r
ASCII e
PING
WRITER OK
READER ERR=$epipe
EOF
	unit_test tmon_test "Hi there!" false 3 false
}

echo "PASS #1: Run test cases in default mode"
test_cases

echo
echo "=================================================="

echo "PASS #2: Run test cases in write-skip mode"
CTDB_TEST_TMON_WRITE_SKIP_MODE=1 test_cases
