#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

socket="${CTDB_TEST_TMP_DIR}/test_sock.$$"
num_clients=10

remove_socket ()
{
    rm -f "$socket"
}

test_cleanup remove_socket

ok_null

unit_test comm_server_test "$socket" $num_clients &
pid=$!

for i in $(seq 1 $num_clients) ; do
    unit_test comm_client_test "$socket"
done

wait $pid
