#!/bin/sh

tests/fetch.sh 4 || exit 1
tests/bench.sh 4 || exit 1
tests/ctdbd.sh || exit 1

echo "All OK"
exit 0
