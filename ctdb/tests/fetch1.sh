#!/bin/sh

killall -q ctdb_fetch1

echo "Trying node"
bin/ctdb_fetch1 --nlist tests/1node.txt $* 
wait
