#!/bin/sh

killall -q ctdb_fetch

echo "Trying 2 nodes"
bin/ctdb_fetch --nlist tests/nodes.txt --listen 127.0.0.2:9001 $* &
bin/ctdb_fetch --nlist tests/nodes.txt --listen 127.0.0.1:9001 $* 

killall -q ctdb_fetch
