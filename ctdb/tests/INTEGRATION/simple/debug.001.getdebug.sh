#!/usr/bin/env bash

# Verify that 'ctdb getdebug' works as expected

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"

try_command_on_node -v 1 "onnode -q all $CTDB getdebug"
getdebug_onnode="$out"

sanity_check_output \
    $num_nodes \
    '^(ERROR|WARNING|NOTICE|INFO|DEBUG)$'

cmd=""
n=0
while [ $n -lt $num_nodes ] ; do
    cmd="${cmd}${cmd:+; }$CTDB getdebug -n $n"
    n=$(($n + 1))
done
try_command_on_node -v 1 "$cmd"
getdebug_n="$out"

if [ "$getdebug_onnode" = "$getdebug_n" ] ; then
    echo "They're the same... cool!"
else
    die "Error: they differ."
fi

seps=""
nl="
"
while read line ; do
    t=$(echo "$line" | sed -r -e 's@Node [[:digit:]]+ is at debug level ([[:alpha:]]+) \((-?[[:digit:]]+)\)$@\|\1\|\2|@')
    seps="${seps}${seps:+${nl}}|Name|Level|${nl}${t}"
done <<<"$getdebug_onnode"
