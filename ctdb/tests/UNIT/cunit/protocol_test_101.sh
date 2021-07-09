#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

last_control=158

generate_control_output ()
{
    for i in $(seq 0 $last_control) ; do
	echo "$1 $i"
    done
}

srvid_list="\
    f002000000000000 \
    f100000000000000 \
    f200000000000000 \
    f300000000000000 \
    f301000000000000 \
    f400000000000000 \
    f500000000000000 \
    f700000000000000 \
    f701000000000000 \
    f800000000000000 \
    f801000000000000 \
    f802000000000000 \
    f900000000000000 \
    fa00000000000000 \
    fb00000000000000 \
    fb01000000000000 \
    fb03000000000000 \
    fb04000000000000 \
    fc00000000000000 \
"

generate_message_output ()
{
    for i in $srvid_list ; do
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
    generate_control_output "ctdb_reply_control_data"
    generate_control_output "ctdb_req_control"
    generate_control_output "ctdb_reply_control"
    generate_message_output "ctdb_message_data"
    generate_message_output "ctdb_req_message"
    echo "ctdb_req_message_data"
    echo "ctdb_req_keepalive"
    echo "ctdb_req_tunnel"
)

ok "$output"

for i in $(seq 1 100) ; do
    unit_test protocol_ctdb_test $i
done
