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

tests/start_daemons.sh $NUMNODES nodes.txt || exit 1

killall -9 ctdb_bench
echo "Trying $NUMNODES nodes"
for i in `seq 1 $NUMNODES`; do
  valgrind -q $VALGRIND bin/ctdb_bench --socket sock.$i -n $NUMNODES $*  &
done

wait
bin/ctdb shutdown --socket sock.1 -n all
