#!/bin/sh

tests/scripts/run_tests -s tests/simple/*.sh || exit 1

echo "All OK"
exit 0
