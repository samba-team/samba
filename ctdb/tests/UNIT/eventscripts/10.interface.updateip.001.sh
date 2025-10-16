#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "error - update a non-existent ip"

setup

public_address=$(ctdb_get_1_public_address)
ip="${public_address% *}"
ip="${ip#* }"

ok "WARNING: Unable to determine interface for IP ${ip}"
# Want separate words from public_address: interface IP maskbits
# shellcheck disable=SC2086
simple_test "__none__" $public_address
