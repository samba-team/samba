#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb getdebug' works as expected.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Get the current debug level on a node, using 'ctdb getdebug -n <node>'.
3. Verify that pipe-separated output is generated with the -X option.
4. Verify that the '-n all' option shows the debug level on all nodes.

Expected results:

* 'ctdb getdebug' shows the debug level on all the nodes.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

try_command_on_node -v 1 "onnode -q all $CTDB getdebug"
getdebug_onnode="$out"

sanity_check_output \
    $num_nodes \
    '^Node [[:digit:]]+ is at debug level [[:alpha:]]+ \([[:digit:]]+\)$' \
    "$out"

try_command_on_node -v 1 "$CTDB getdebug -n all"
getdebug_all="$out"

cmd=""
n=0
while [ $n -lt $num_nodes ] ; do
    cmd="${cmd}${cmd:+; }$CTDB getdebug -n $n"
    n=$(($n + 1))
done
try_command_on_node -v 1 "$cmd"
getdebug_n="$out"

if [ "$getdebug_onnode" = "$getdebug_all" -a \
    "$getdebug_all" = "$getdebug_n" ] ; then
    echo "They're the same... cool!"
else
    echo "Error: they differ."
    testfailures=1
fi

seps=""
nl="
"
while read line ; do
    t=$(echo "$line" | sed -r -e 's@Node [[:digit:]]+ is at debug level ([[:alpha:]]+) \((-?[[:digit:]]+)\)$@\|\1\|\2|@')
    seps="${seps}${seps:+${nl}}|Name|Level|${nl}${t}"
done <<<"$getdebug_onnode"

cmd="$CTDB -X getdebug -n all"
echo "Checking that \"$cmd\" produces expected output..."

try_command_on_node 1 "$cmd"
if [ "$out" = "$seps" ] ; then
    echo "Yep, looks good!"
else
    echo "Nope, it looks like this:"
    echo "$out"
    testfailures=1
fi
