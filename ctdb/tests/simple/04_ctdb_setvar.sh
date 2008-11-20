#!/bin/bash

# Doesn't strictly follow the procedure, since it doesn't pick a
# variable from the output of "ctdb listvars".

. ctdb_test_functions.bash

set -e

onnode 0 $TEST_WRAP cluster_is_healthy

var="RecoverTimeout"

cmd="ctdb getvar $var"
try_command_on_node 0 $cmd

val=$(echo "$out" | sed -e 's@.*[[:space:]]@@')

echo "$out"

echo "Going to try incrementing it..."

incr=$(($val + 1))

cmd="ctdb setvar $var $incr"
try_command_on_node 0 $cmd

echo "That seemed to work, let's check the value..."

cmd="ctdb getvar $var"
try_command_on_node 0 $cmd

newval=$(echo "$out" | sed -e 's@.*[[:space:]]@@')

echo "$out"

if [ "$incr" != "$newval" ] ; then
    echo "Nope, that didn't work..."
    exit 1
fi

echo "Look's good!  Now verifying with \"ctdb listvars\""
cmd="ctdb listvars"
try_command_on_node 0 $cmd

line=$(echo "$out" | grep "^$var")
echo "$line"

check=$(echo "$line" | sed -e 's@.*[[:space:]]@@')

if [ "$incr" != "$check" ] ; then
    echo "Nope, that didn't work..."
    exit 1
fi

echo "Look's good!  Putting the old value back..."
cmd="ctdb setvar $var $val"
try_command_on_node 0 $cmd

echo "All done..."

ctdb_test_exit
