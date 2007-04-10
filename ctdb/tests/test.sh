#!/bin/sh

killall -q ctdb_test


echo "Trying 2 nodes"
bin/ctdb_test --nlist tests/nodes.txt --listen 127.0.0.1:9001 &
bin/ctdb_test --nlist tests/nodes.txt --listen 127.0.0.2:9001 &

sleep 3
killall ctdb_test

echo "Trying 4 nodes"
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.1:9001 &
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.2:9001 &
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.3:9001 &
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.4:9001 &
sleep 3

killall ctdb_test

echo "Trying 2 nodes in daemon mode"
bin/ctdb_test --nlist tests/nodes.txt --listen 127.0.0.1:9001 --daemon &
bin/ctdb_test --nlist tests/nodes.txt --listen 127.0.0.2:9001 --daemon &

sleep 3
killall ctdb_test

echo "Trying 4 nodes in daemon mode"
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.1:9001 --daemon &
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.2:9001 --daemon &
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.3:9001 --daemon &
bin/ctdb_test --nlist tests/4nodes.txt --listen 127.0.0.4:9001 --daemon &
sleep 3
killall ctdb_test
