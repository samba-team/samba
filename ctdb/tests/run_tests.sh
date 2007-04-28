#!/bin/sh

tests/fetch.sh || exit 1
tests/bench.sh || exit 1
tests/test.sh || exit 1

echo "All OK"
exit 0
