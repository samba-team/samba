#!/bin/sh

echo "Testing daemon mode"
bin/ctdb_test --nlist tests/1node.txt --listen 127.0.0.1:9001
wait

echo "Testing self connect"
bin/ctdb_test --nlist tests/1node.txt --listen 127.0.0.1:9001 --self-connect
wait
