#!/bin/sh

NUMNODES=4
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

killall -9 -q ctdb_transaction ctdbd

rm -rf test.db/transaction

echo "Starting $NUMNODES daemons for transaction writes"
tests/start_daemons.sh $NUMNODES || exit 1

trap 'echo "Killing test"; killall -9 -q ctdbd ctdb_transaction; exit 1' INT TERM

VALGRIND="valgrind -q"
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_transaction --timelimit 30 --socket sock.$i $* &
  $VALGRIND bin/ctdb_transaction --timelimit 30 --socket sock.$i $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
killall -9 ctdbd

exit 0
