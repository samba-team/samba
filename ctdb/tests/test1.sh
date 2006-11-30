#!/bin/sh

killall -q ctdb_test
bin/ctdb_test --nlist tests/1node.txt --listen 127.0.0.1:9001
killall ctdb_test
