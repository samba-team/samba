#!/bin/sh

killall -q ctdbd

echo "Starting 2 ctdb daemons"
bin/ctdbd --nlist direct/nodes.txt --listen 127.0.0.2:9001 --daemon &
bin/ctdbd --nlist direct/nodes.txt --listen 127.0.0.1:9001 --daemon &

