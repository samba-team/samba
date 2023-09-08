#!/bin/sh
# Blackbox wrapper for bug 15464
# Copyright (C) 2023 Stefan Metzmacher

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: b15464-testcase.sh B15464_TESTCASE LIBNSS_WINBIND
EOF
	exit 1
fi

b15464_testcase=$1
libnss_winbind=$2
shift 2
failed=0

. $(dirname $0)/subunit.sh

testit "run b15464-testcase" $VALGRIND $b15464_testcase $libnss_winbind || failed=$(expr $failed + 1)

testok $0 $failed
