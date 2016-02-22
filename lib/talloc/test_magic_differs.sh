#!/bin/sh
# This test ensures that two different talloc processes do not use the same
# magic value to lessen the opportunity for transferrable attacks.

echo "test: magic differs"

helper=$1
m1=$($helper)
m2=$($helper)

if [ $m1 -eq $m2 ]; then
	echo "failure: magic remained the same between executions ($m1 vs $m2)"
	exit 1
fi

echo "success: magic differs"
