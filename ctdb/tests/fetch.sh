#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

trap 'echo "Killing test"; killall -9 -q ctdbd ctdb_fetch; exit 1' INT TERM

tests/start_daemons.sh $NUMNODES || exit 1


killall -9 -q ctdb_fetch
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_fetch --socket sock.$i -n $NUMNODES $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
exit 0
