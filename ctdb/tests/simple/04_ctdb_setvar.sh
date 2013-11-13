#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb setvar' works correctly.

Doesn't strictly follow the procedure outlines below, since it doesn't
pick a variable from the output of 'ctdb listvars'.  However, it
verifies the value with 'ctdb getvar' in addition to 'ctdb listvars'.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Get a list of all the ctdb tunable variables, using the 'ctdb
   listvars' command.
3. Set the value of one of the variables using the 'setvar' control on
   one of the nodes.  E.g. 'ctdb setvar DeterministicIPs 0'.
4. Verify that the 'listvars' control now shows the new value for the
   variable.

Expected results:

* After setting a value using 'ctdb setvar', 'ctdb listvars' shows the
  modified value of the variable.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

var="RecoverTimeout"

try_command_on_node -v 0 $CTDB getvar $var

val="${out#*= }"

echo "Going to try incrementing it..."

incr=$(($val + 1))

try_command_on_node 0 $CTDB setvar $var $incr

echo "That seemed to work, let's check the value..."

try_command_on_node -v 0 $CTDB getvar $var

newval="${out#*= }"

if [ "$incr" != "$newval" ] ; then
    echo "Nope, that didn't work..."
    exit 1
fi

echo "Look's good!  Now verifying with \"ctdb listvars\""
try_command_on_node -v 0 "$CTDB listvars | grep '^$var'"

check="${out#*= }"

if [ "$incr" != "$check" ] ; then
    echo "Nope, that didn't work..."
    exit 1
fi

echo "Look's good!  Putting the old value back..."
cmd="$CTDB setvar $var $val"
try_command_on_node 0 $cmd
