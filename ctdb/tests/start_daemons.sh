#!/bin/sh

NUMNODES=2
if [ $# -gt 0 ]; then
    NUMNODES=$1
fi
shift

NODES="./tests/nodes.txt"
PUBLIC_ADDRESSES=./tests/public_addresses.txt
rm -f $NODES $PUBLIC_ADDRESSES
for i in `seq 1 $NUMNODES`; do
  if [ "${CTDB_USE_IPV6}x" != "x" ]; then
    echo ::$i >> $NODES
    ip addr add ::$i/128 dev lo
  else
    echo 127.0.0.$i >> $NODES
    # 2 public addresses per node, just to make things interesting.
    echo "192.0.2.$i/24 lo" >> $PUBLIC_ADDRESSES
    echo "192.0.2.$(($i + $NUMNODES))/24 lo" >> $PUBLIC_ADDRESSES
  fi
done

killall -q $PWD/bin/ctdbd
rm -rf test.db/persistent/*
 
CTDB_OPTIONS="--reclock=rec.lock --nlist $NODES --public-addresses $PUBLIC_ADDRESSES --nopublicipcheck --event-script-dir=tests/events.d --logfile=- -d 0 --dbdir=test.db --dbdir-persistent=test.db/persistent $*"

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
