#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

last_control=150

control_output=$(
    for i in $(seq 0 $last_control) ; do
	echo -n "$i.. "
    done
    echo
)

generate_control_output ()
{
    for i in $(seq 0 $last_control) ; do
	echo "$1 $i"
    done
}

output=$(
    echo "ctdb_req_header"
    echo "ctdb_req_call"
    echo "ctdb_reply_call"
    echo "ctdb_reply_error"
    echo "ctdb_req_dmaster"
    echo "ctdb_reply_dmaster"
    generate_control_output "ctdb_req_control_data"
    echo "ctdb_reply_control_data"
    echo "$control_output"
    echo "ctdb_req_control"
    echo "$control_output"
    echo "ctdb_reply_control"
    echo "$control_output"
    echo "ctdb_req_message"
)

ok "$output"

for i in $(seq 1 100) ; do
    unit_test protocol_ctdb_test $i
done
