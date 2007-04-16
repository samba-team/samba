#!/bin/sh

killall -q ctdb_bench

echo "Trying 1 nodes"
bin/ctdb_bench --nlist tests/1node.txt --listen 127.0.0.2:9001 $*

killall -q ctdb_bench
