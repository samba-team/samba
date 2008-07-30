#!/bin/sh

trap 'echo "Killing test"; killall -9 -q ctdbd; exit 1' INT TERM

tests/fetch.sh 4 || exit 1
tests/bench.sh 4 || exit 1
tests/ctdbd.sh || exit 1

echo "All OK"
exit 0
