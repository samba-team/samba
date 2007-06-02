#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

rm -f nodes.txt
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i >> nodes.txt
done

killall -q ctdbd
echo "Trying $NUMNODES nodes"
for i in `seq 1 $NUMNODES`; do
    $VALGRIND bin/ctdbd --reclock=rec.lock --nlist nodes.txt --event-script=tests/events --logfile=- --socket=sock.$i
done

killall -9 -q ctdb_fetch
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_fetch --socket sock.$i $* &
done
wait

echo "Shutting down"
bin/ctdb shutdown -n all --socket=sock.1
