#!/bin/sh

killall -q ctdb_messaging

echo "Trying 2 nodes"
bin/ctdb_messaging --nlist tests/nodes.txt --listen 127.0.0.2:9001 $* &
bin/ctdb_messaging --nlist tests/nodes.txt --listen 127.0.0.1:9001 $*
wait
