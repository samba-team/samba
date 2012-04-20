#!/bin/sh

test_dir=$(dirname "$0")

if [ -n "$1" ] ; then
    "${test_dir}/scripts/run_tests" -l -s "$@" || exit 1
else
    cd "$test_dir"

    # By default, run all unit tests and the tests against local
    # daemons
    dirs="onnode takeover tool eventscripts simple"

    ./scripts/run_tests -l -s $dirs || exit 1
fi

echo "All OK"
exit 0
