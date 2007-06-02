#!/bin/sh

killall -q ctdbd

echo "Starting 2 ctdb daemons"
$VALGRIND bin/ctdbd --reclock=rec.lock --nlist direct/nodes.txt --event-script=tests/events --logfile=-
$VALGRIND bin/ctdbd --reclock=rec.lock --nlist direct/nodes.txt --event-script=tests/events --logfile=- --socket=sock.2

while bin/ctdb status | grep RECOVERY > /dev/null; do
    echo "`date` Waiting for recovery"
    sleep 1;
done

echo "Testing ping"
$VALGRIND bin/ctdb ping || exit 1

echo "Testing status"
$VALGRIND bin/ctdb status || exit 1

echo "Testing statistics"
$VALGRIND bin/ctdb -n all statistics || exit 1

echo "Testing statisticsreset"
$VALGRIND bin/ctdb -n all statisticsreset || exit 1

echo "Testing debug"
$VALGRIND bin/ctdb -n all setdebug 3 || exit 1
$VALGRIND bin/ctdb -n all getdebug || exit 1
$VALGRIND bin/ctdb -n all setdebug 0 || exit 1
$VALGRIND bin/ctdb -n all getdebug || exit 1

echo "Attaching to some databases"
$VALGRIND bin/ctdb attach test1.tdb || exit 1
$VALGRIND bin/ctdb attach test2.tdb || exit 1

echo "Testing getdbmap"
$VALGRIND bin/ctdb getdbmap || exit 1

echo "Testing status"
$VALGRIND bin/ctdb status || exit 1

sleep 1

echo "Testing shutdown"
$VALGRIND bin/ctdb shutdown -n all || exit 1

sleep 1

echo "All done"
killall -q ctdbd
exit 0
