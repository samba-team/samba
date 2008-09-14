#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

rm -f nodes.txt
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i >> nodes.txt
done

tests/start_daemons.sh $NUMNODES nodes.txt || exit 1


killall -9 -q ctdb_fetch
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_fetch --socket sock.$i -n $NUMNODES $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
exit 0
