#!/bin/sh
# This test ensures that two different talloc processes do not use the same
# magic value to lessen the opportunity for transferrable attacks.

echo "test: magic differs"

if [
	"`./talloc_test_magic_differs_helper`" != "`./talloc_test_magic_differs_helper`"
]; then
	echo "failure: magic remained the same between executions"
	exit 1
fi

echo "success: magic differs"
