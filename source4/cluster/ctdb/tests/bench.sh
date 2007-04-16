#!/bin/sh

killall -q ctdb_bench

echo "Trying 2 nodes"
bin/ctdb_bench --nlist tests/nodes.txt --listen 127.0.0.2:9001 $* &
bin/ctdb_bench --nlist tests/nodes.txt --listen 127.0.0.1:9001 $*

killall -q ctdb_bench
