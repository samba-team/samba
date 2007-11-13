#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

tests/start_daemons.sh $NUMNODES || exit 1


killall -9 -q ctdb_persistent
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_persistent --socket sock.$i $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
exit 0
