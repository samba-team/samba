#!/bin/sh

killall -q ctdb_test

bin/ctdb_test --nlist nodes.txt --listen 127.0.0.1:9001 &
bin/ctdb_test --nlist nodes.txt --listen 127.0.0.2:9001 &

sleep 3
killall ctdb_test
