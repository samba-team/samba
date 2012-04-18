#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb getvar' works correctly.

Expands on the steps below as it actually checks the values of all
variables listed by 'ctdb listvars'.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb getvars <varname>' with a valid variable name (possibly
   obtained via 'ctdb listvars'.
3. Verify that the command displays the correct value of the variable
   (corroborate with the value shown by 'ctdb listvars'.

Expected results:

* 'ctdb getvar' shows the correct value of the variable.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

try_command_on_node -v 0 "$CTDB listvars"

echo "Veryifying all variable values using \"ctdb getvar\"..."

echo "$out" |
while read var x val ; do
    try_command_on_node 0 "$CTDB getvar $var"

    val2="${out#*= }"

    if [ "$val" != "$val2" ] ; then
	echo "MISMATCH on $var: $val != $val2"
	exit 1
    fi
done
