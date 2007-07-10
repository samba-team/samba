#!/bin/sh

killall -q ctdbd

tests/start_daemons.sh 2 tests/nodes.txt || exit 1

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

echo "Testing variables"
$VALGRIND bin/ctdb listvars || exit 1
$VALGRIND bin/ctdb getvar TraverseTimeout || exit 1
$VALGRIND bin/ctdb setvar TraverseTimeout 10 || exit 1
$VALGRIND bin/ctdb getvar TraverseTimeout || exit 1

sleep 1

echo "Testing shutdown"
$VALGRIND bin/ctdb shutdown -n all || exit 1

sleep 1

echo "All done"
killall -q ctdbd
exit 0
