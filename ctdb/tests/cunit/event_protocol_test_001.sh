#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

last_command=3

generate_output ()
{
    for i in $(seq 1 $last_command) ; do
	echo "$1 $i"
    done
}

output=$(
    generate_output "ctdb_event_request_data"
    generate_output "ctdb_event_reply_data"
    generate_output "ctdb_event_request"
    generate_output "ctdb_event_reply"
)

ok "$output"

for i in $(seq 1 100) ; do
    unit_test event_protocol_test $i
done
