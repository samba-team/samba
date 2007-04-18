#!/bin/sh

killall -q ctdb_test


echo "Trying 2 nodes ..."
$VALGRIND bin/ctdb_test --nlist tests/nodes.txt --listen 127.0.0.1:9001 &
$VALGRIND bin/ctdb_test --nlist tests/nodes.txt --listen 127.0.0.2:9001
wait

echo "Trying 4 nodes ..."
$VALGRIND bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.1:9001 &
$VALGRIND bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.2:9001 &
$VALGRIND bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.3:9001 &
$VALGRIND bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.4:9001
wait

