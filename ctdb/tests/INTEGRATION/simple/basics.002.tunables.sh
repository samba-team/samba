#!/bin/bash

test_info()
{
    cat <<EOF
Verify the operation of "ctdb listvars", "ctdb getvar", "ctdb setvar"
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init

set -e

cluster_is_healthy

try_command_on_node -v 0 "$CTDB listvars"

sanity_check_output \
    5 \
    '^[[:alpha:]][[:alnum:]]+[[:space:]]*=[[:space:]]*[[:digit:]]+$'

echo "Verifying all variable values using \"ctdb getvar\"..."

while read var x val ; do
    try_command_on_node 0 "$CTDB getvar $var"

    val2="${out#*= }"

    if [ "$val" != "$val2" ] ; then
	echo "MISMATCH on $var: $val != $val2"
	exit 1
    fi
done <"$outfile"

echo "GOOD: all tunables match"

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
