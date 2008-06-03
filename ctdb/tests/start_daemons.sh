#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi
NODES="./tests/nodes.txt"
shift

rm -f $NODES
for i in `seq 1 $NUMNODES`; do
  echo 127.0.0.$i >> $NODES
done

killall -q ctdbd
rm -rf test.db/persistent/*
 
CTDB_OPTIONS="--reclock=rec.lock --nlist $NODES --event-script-dir=tests/events.d --logfile=- -d 0 --dbdir=test.db --dbdir-persistent=test.db/persistent $*"

echo "Starting $NUMNODES ctdb daemons"
for i in `seq 1 $NUMNODES`; do
    if [ `id -u` -eq 0 ]; then
        CTDB_OPTIONS="$CTDB_OPTIONS --public-interface=lo"
    fi

    $VALGRIND bin/ctdbd --socket=sock.$i $CTDB_OPTIONS || exit 1
done
ln -sf $PWD/sock.1 /tmp/ctdb.socket || exit 1

while bin/ctdb status | egrep "DISCONNECTED|UNHEALTHY" > /dev/null; do
    echo "`date` Waiting for recovery"
    sleep 1;
done

echo "$NUMNODES daemons started"

exit 0
