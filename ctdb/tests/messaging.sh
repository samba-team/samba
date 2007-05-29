#!/bin/sh

#!/bin/sh

killall -q ctdb_messaging

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi

rm -f nodes.txt
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i >> nodes.txt
done

killall -9 ctdb_messaging
echo "Trying $NUMNODES nodes"
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_messaging --nlist nodes.txt --socket /tmp/ctdb.127.0.0.$i $* &
done

wait
