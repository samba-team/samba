#!/bin/sh

killall -q ctdbd

echo "Starting 2 ctdb daemons"
$VALGRIND bin/ctdbd --nlist direct/nodes.txt
$VALGRIND bin/ctdbd --nlist direct/nodes.txt

echo "Testing ping"
$VALGRIND bin/ctdb_control ping || exit 1
exit 0

echo "Testing status"
$VALGRIND bin/ctdb_control status all || exit 1

echo "Testing statusreset"
$VALGRIND bin/ctdb_control statusreset all || exit 1

echo "Testing debug"
$VALGRIND bin/ctdb_control debug all 5 || exit 1
$VALGRIND bin/ctdb_control debuglevel || exit 1
$VALGRIND bin/ctdb_control debug all 0 || exit 1
$VALGRIND bin/ctdb_control debuglevel || exit 1

echo "Testing map calls"
$VALGRIND bin/ctdb_control getvnnmap 0 || exit 1

echo "Attaching to some databases"
$VALGRIND bin/ctdb_control attach test1.tdb || exit 1
$VALGRIND bin/ctdb_control attach test2.tdb || exit 1

echo "Testing getdbmap"
$VALGRIND bin/ctdb_control getdbmap 0 || exit 1

killall -q ctdbd
