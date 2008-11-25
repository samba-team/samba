#!/bin/sh

killall -q ctdbd

tests/start_daemons.sh 2 || exit 1

echo "Testing ping"
$VALGRIND bin/ctdb ping || exit 1  # Done

echo "Testing status"
$VALGRIND bin/ctdb status || exit 1 # Done: implied

echo "Testing statistics"
$VALGRIND bin/ctdb -n all statistics || exit 1 # Done

echo "Testing statisticsreset"
$VALGRIND bin/ctdb -n all statisticsreset || exit 1  # Done

echo "Testing debug"
$VALGRIND bin/ctdb -n all setdebug 3 || exit 1 # Done
$VALGRIND bin/ctdb -n all getdebug || exit 1   # Done
$VALGRIND bin/ctdb -n all setdebug 0 || exit 1 # Done
$VALGRIND bin/ctdb -n all getdebug || exit 1   # Done

echo "Attaching to some databases"
$VALGRIND bin/ctdb attach test1.tdb || exit 1
$VALGRIND bin/ctdb attach test2.tdb || exit 1

echo "Testing getdbmap"
$VALGRIND bin/ctdb getdbmap || exit 1

echo "Testing status"
$VALGRIND bin/ctdb status || exit 1 # Done: implied

echo "Testing variables"
$VALGRIND bin/ctdb listvars || exit 1
$VALGRIND bin/ctdb getvar TraverseTimeout || exit 1  # Done
$VALGRIND bin/ctdb setvar TraverseTimeout 10 || exit 1 # Done
$VALGRIND bin/ctdb getvar TraverseTimeout || exit 1 # Done

sleep 1

echo "Testing shutdown"
$VALGRIND bin/ctdb shutdown -n all || exit 1 # Done: implied by 09_ctdb_ping.sh

sleep 1

echo "All done"
killall -q ctdbd
exit 0
