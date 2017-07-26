#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

last_command=5

command_output=$(
    for i in $(seq 1 $last_command) ; do
	echo -n "$i.. "
    done
    echo
)

generate_output ()
{
    for i in $(seq 1 $last_command) ; do
	echo "$1 $i"
    done
}

output=$(
    echo "ctdb_event_header"
    generate_output "ctdb_event_request_data"
    echo "ctdb_event_reply_data"
    echo "$command_output"
    echo "ctdb_event_request"
    echo "$command_output"
    echo "ctdb_event_reply"
    echo "$command_output"
)

ok "$output"

for i in $(seq 1 100) ; do
    unit_test protocol_event_test $i
done
