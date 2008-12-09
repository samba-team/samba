#!/bin/bash

test_info()
{
    cat <<EOF
Install an event script on all nodes that helps detect ctdb events.

We could install separate scripts for particular events later as
needed.  However, the script installed here will allow detection of
all events.  It also allows a file to be created to indicate that a
node should be marked as unhealthy.

Prerequisites:

* Nodes must be accessible via 'onnode'.

Steps:

1. Use the install_eventscript to install the eventscript.

Expected results:

* The script is successfully installed on all nodes.
EOF
}

. ctdb_test_functions.bash

script='#!/bin/sh
out=$(ctdb pnn)
pnn="${out#PNN:}"

# Allow creation of flag files that are removed to confirm that events
# are taking place.
rm -f "/tmp/ctdb-test-flag.${1}.${pnn}"

# Allow creation of a trigger file to make a monitor event fail and
# force a node to be marked as unhealthy.  This avoids having to look
# at log files to confirm that monitoring is working.  Note that
# ${pnn} is needed in the filename if we are testing using local
# daemons so we put in there regardless.
trigger="/tmp/ctdb-test-unhealthy-trigger.${pnn}"
detected="/tmp/ctdb-test-unhealthy-detected.${pnn}"
if [ "$1" = "monitor" ] ; then
    if [ -e "$trigger" ] ; then
        echo "${0}: Unhealthy because \"$trigger\" detected"
        touch "$detected"
        exit 1
    elif [ -e "$detected" -a ! -e "$trigger" ] ; then
        echo "${0}: Healthy again, \"$trigger\" no longer detected"
        rm "$detected"
    fi
fi

exit 0
'

install_eventscript "00.ctdb_test_trigger" "$script"
