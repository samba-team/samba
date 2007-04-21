#!/bin/sh

killall -q ctdb_fetch1

echo "Trying node"
bin/ctdb_fetch1 --nlist tests/1node.txt --listen 127.0.0.1:9001 $* 
wait
