#!/bin/sh
#
# Copyright (c) 2022 Pavel Filipenský <pfilipen@redhat.com>
#
# Blackbox tests for the rpcclient DFS commands

if [ $# -lt 4 ]; then
	cat <<EOF
Usage: test_rpcclient_dfs.sh USERNAME PASSWORD SERVER RPCCLIENT
EOF
	exit 1
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
RPCCLIENT="$4"

RPCCLIENTCMD="${VALGRIND} ${RPCCLIENT} ${SERVER} -U${USERNAME}%${PASSWORD}"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "${incdir}"/subunit.sh

failed=0

${RPCCLIENTCMD} -c "dfsversion"
RC=$?
testit "dfsversion" test ${RC} -eq 0 || failed=$((failed + 1))

${RPCCLIENTCMD} -c "dfsenum 5"
RC=$?
testit "dfsenum" test ${RC} -eq 0 || failed=$((failed + 1))

# This test fails: _dfs_EnumEx() is not implemented on samba RPC server side
${RPCCLIENTCMD} -c "dfsenumex 5"
RC=$?
testit "dfsenumex" test ${RC} -eq 0 || failed=$((failed + 1))

# Every backslash is reduced twice, so we need to enter it 4 times.
# Rpc server then gets: '\\server\share\path'
${RPCCLIENTCMD} -c "dfsgetinfo \\\\\\\\${SERVER}\\\\msdfs-share\\\\msdfs-src1 ${SERVER} msdfs-src1"
RC=$?
testit "dfsgetinfo" test ${RC} -eq 0 || failed=$((failed + 1))

testok "$0" "${failed}"
