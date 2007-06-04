#!/bin/sh

NUMNODES="$1"
NODES=$2

pkill -f ctdbd

echo "Starting $NUMNODES ctdb daemons"
for i in `seq 1 $NUMNODES`; do
    $VALGRIND bin/ctdbd --reclock=rec.lock --nlist $NODES --event-script=tests/events --logfile=- --socket=sock.$i --dbdir=test.db || exit 1
done
ln -sf sock.1 /tmp/ctdb.socket || exit 1

while bin/ctdb status | grep RECOVERY > /dev/null; do
    echo "`date` Waiting for recovery"
    sleep 1;
done

exit 0
