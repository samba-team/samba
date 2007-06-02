#!/bin/sh

killall -q ctdb_bench ctdbd

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

rm -f nodes.txt
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i >> nodes.txt
done

echo "Trying $NUMNODES nodes"
for i in `seq 1 $NUMNODES`; do
    $VALGRIND bin/ctdbd --reclock=rec.lock --nlist nodes.txt --event-script=tests/events --logfile=- --socket=sock.$i
done

killall -9 ctdb_bench
echo "Trying $NUMNODES nodes"
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_bench --nlist nodes.txt --socket sock.$i $* &
done

wait
ctdb shutdown --socket sock.1 -n all
