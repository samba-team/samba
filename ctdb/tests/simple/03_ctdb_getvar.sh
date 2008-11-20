#!/bin/bash

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

try_command_on_node 0 "ctdb listvars"

echo "Veryifying all variable values using \"ctdb getvar\"..."

echo "$out" |
while read var x val ; do
    try_command_on_node 0 "ctdb getvar $var"

    val2=$(echo $out | sed -e 's@.*[[:space:]]@@')

    if [ "$val" != "$val2" ] ; then
	echo "MISMATCH on $var: $val != $val2"
	exit 1
    fi
done

testfailures=$?

ctdb_test_exit
