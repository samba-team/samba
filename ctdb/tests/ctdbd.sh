#!/bin/sh

killall -q ctdbd

echo "Starting 2 ctdb daemons"
$VALGRIND bin/ctdbd --nlist direct/nodes.txt
$VALGRIND bin/ctdbd --nlist direct/nodes.txt

echo "Testing ping"
$VALGRIND bin/ctdb ping || exit 1

echo "Testing status"
$VALGRIND bin/ctdb status || exit 1

echo "Testing statistics"
$VALGRIND bin/ctdb -n all statistics || exit 1

echo "Testing statisticsreset"
$VALGRIND bin/ctdb -n all statisticsreset || exit 1

echo "Testing debug"
$VALGRIND bin/ctdb -n all setdebug 5 || exit 1
$VALGRIND bin/ctdb -n all getdebug || exit 1
$VALGRIND bin/ctdb -n all setdebug 0 || exit 1
$VALGRIND bin/ctdb -n all getdebug || exit 1

echo "Attaching to some databases"
$VALGRIND bin/ctdb attach test1.tdb || exit 1
$VALGRIND bin/ctdb attach test2.tdb || exit 1

echo "Testing getdbmap"
$VALGRIND bin/ctdb getdbmap || exit 1

echo "All done"

killall -q ctdbd
