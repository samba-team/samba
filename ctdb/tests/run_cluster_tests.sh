#!/bin/sh

if [ -n "$*" ]; then
    tests/scripts/run_tests -s $* || exit 1
else
    tests/scripts/run_tests -s tests/simple/*.sh tests/complex/*.sh || exit 1
fi

echo "All OK"
exit 0
