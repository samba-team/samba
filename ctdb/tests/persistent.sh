#!/bin/sh

NUMNODES=4
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

killall -9 -q ctdb_persistent ctdbd

rm -rf test.db/persistent

echo "Starting $NUMNODES daemons for SAFE persistent writes"
tests/start_daemons.sh $NUMNODES || exit 1

trap 'echo "Killing test"; killall -9 -q ctdbd ctdb_persistent; exit 1' INT TERM


for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_persistent --timelimit 30 --socket sock.$i $* &
  $VALGRIND bin/ctdb_persistent --timelimit 30 --socket sock.$i $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
killall -9 ctdbd



echo "Starting $NUMNODES daemons for UNSAFE persistent writes"
tests/start_daemons.sh $NUMNODES || exit 1

killall -9 -q ctdb_persistent

for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_persistent --unsafe-writes --timelimit 30 --socket sock.$i $* &
  $VALGRIND bin/ctdb_persistent --unsafe-writes --timelimit 30 --socket sock.$i $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
killall -9 ctdbd



exit 0
