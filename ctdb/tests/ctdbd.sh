#!/bin/sh

killall -q ctdbd

echo "Starting 2 ctdb daemons"
bin/ctdbd --nlist direct/nodes.txt
bin/ctdbd --nlist direct/nodes.txt

echo "Testing ping"
bin/ctdb_control ping || exit 1

echo "Testing status"
bin/ctdb_control status all || exit 1

echo "Testing statusreset"
bin/ctdb_control statusreset all || exit 1

echo "Testing debug"
bin/ctdb_control debug all 5 || exit 1
bin/ctdb_control debuglevel || exit 1
bin/ctdb_control debug all 0 || exit 1
bin/ctdb_control debuglevel || exit 1

echo "Testing map calls"
bin/ctdb_control getvnnmap 0 || exit 1

echo "Attaching to some databases"
bin/ctdb_control attach test1.tdb || exit 1
bin/ctdb_control attach test2.tdb || exit 1

echo "Testing getdbmap"
bin/ctdb_control getdbmap 0 || exit 1

killall -q ctdbd
