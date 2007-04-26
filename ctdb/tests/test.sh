#!/bin/sh

#!/bin/sh

killall -q ctdb_test

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
    shift
fi

rm -f nodes.txt
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i:9001 >> nodes.txt
done

killall -9 ctdb_test
echo "Trying $NUMNODES nodes"
for i in `seq 1 $NUMNODES`; do
  $VALGRIND bin/ctdb_test --nlist nodes.txt --listen 127.0.0.$i:9001 --socket /tmp/ctdb.127.0.0.$i $* &
done

wait
