#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Check public IP dropping, all assigned"

setup

nl="
"
ctdb_get_my_public_addresses | {
    out=""
    while read dev ip bits ; do
	ip addr add "${ip}/${bits}" dev "$dev"

	msg="Removing public address ${ip}/${bits} from device ${dev}"
	out="${out}${out:+${nl}}${msg}"
    done

    ok "$out"

    simple_test
}
