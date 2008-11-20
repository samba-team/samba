#!/bin/bash

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

echo "Getting list of public IPs..."
try_command_on_node 1 ctdb ip -n all
ips=$(echo "$out" | sed -e '1d')
colons=$(echo "$ips" | sed -e 's@^@:@' -e 's@$@:@' -e 's@ @:@')

while read ip pnn ; do
    try_command_on_node $pnn "ip addr show"
    if [ "${out/inet ${ip}\/}" != "$out" ] ; then
	echo "GOOD: node $pnn appears to have $ip assigned"
    else
	echo "BAD:  node $pnn does not appear to have $ip assigned"
	testfailures=1
    fi
done <<<"$ips" # bashism to avoid problem setting variable in pipeline.

[ "$testfailures" != 1 ] && echo "Looks good!"

cmd="ctdb -Y ip -n all | sed -e '1d'"
echo "Checking that \"$cmd\" produces expected output..."

try_command_on_node 1 "$cmd"
if [ "$out" = "$colons" ] ; then
    echo "Yep, looks good!"
else
    echo "Nope, it looks like this:"
    echo "$out"
    testfailures=1
fi

ctdb_test_exit
