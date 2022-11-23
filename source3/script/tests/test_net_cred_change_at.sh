#!/bin/bash

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_net_cred_change_at.sh CONFIGURATION
EOF
	exit 1
fi

incdir=$(dirname "$0")/../../../testprogs/blackbox
# shellcheck source=/dev/null
. "$incdir/subunit.sh"

test_change_machine_secret_at() {
    local DC_SERVER
    local REPL_TARGET

    out=$("$BINDIR/wbinfo" --dc-info SAMBADOMAIN) || return 1
    echo "$out"
    echo "$out" | grep localdc && DC_SERVER=localvampiredc && REPL_TARGET=localdc
    echo "$out" | grep localvampiredc && DC_SERVER=localdc && REPL_TARGET=localvampiredc
    if [ -z $DC_SERVER ] ; then return 1 ; fi

    $VALGRIND "$BINDIR/wbinfo" --change-secret-at=$DC_SERVER || return 1

    # Force replication
    $VALGRIND "$BINDIR/samba-tool" drs replicate -U Administrator%locDCpass1 $REPL_TARGET $DC_SERVER DC=samba,DC=example,DC=com
}

testit "change machine secret at" test_change_machine_secret_at || failed=$(("$failed" + 1))
testit "validate secret" $VALGRIND "$BINDIR/net rpc testjoin" "$@" || failed=$(("$failed" + 1))

testok "$0" "$failed"
