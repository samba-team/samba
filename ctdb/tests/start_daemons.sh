#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi
NODES="nodes.txt"
shift
shift

rm -f nodes.txt
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i >> nodes.txt
done

killall -q ctdbd

CTDB_OPTIONS="--reclock=rec.lock --nlist $NODES --event-script-dir=tests/events.d --logfile=-  --dbdir=test.db --dbdir-persistent=test.db/persistent $*"
if [ `id -u` -eq 0 ]; then
    CTDB_OPTIONS="$CTDB_OPTIONS --public-addresses=tests/public_addresses --public-interface=lo"
fi

echo "Starting $NUMNODES ctdb daemons"
for i in `seq 1 $NUMNODES`; do
    $VALGRIND bin/ctdbd --socket=sock.$i $CTDB_OPTIONS || exit 1
done
ln -sf $PWD/sock.1 /tmp/ctdb.socket || exit 1

while bin/ctdb status | grep RECOVERY > /dev/null; do
    echo "`date` Waiting for recovery"
    sleep 1;
done

echo "$NUMNODES daemons started"

exit 0
