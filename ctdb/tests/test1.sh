#!/bin/sh

echo "Testing daemon mode"
bin/ctdb_test --nlist tests/1node.txt
wait

echo "Testing self connect"
bin/ctdb_test --nlist tests/1node.txt --self-connect
wait
