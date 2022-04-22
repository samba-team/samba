#!/bin/sh
#
# Copyright (c) 2022 Pavel Filipenský <pfilipen@redhat.com>
#
# Tests for "username map" smb.conf parameter for UNIX groups

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_usernamemap.sh SERVER SMBCLIENT
EOF
	exit 1
fi

SERVER="$1"
SMBCLIENT="$2"
SMBCLIENT="${VALGRIND} ${SMBCLIENT}"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "${incdir}"/subunit.sh

failed=0

# jackthemapper is mapped to jacknomapper, so we need jacknomapper password
testit "jackthemapper" "${SMBCLIENT}" //"${SERVER}"/tmp -U"${SERVER}/jackthemapper%nOmApsEcrEt" -c ls || failed=$((failed + 1))
# jacknomapper is not mapped, so we need jacknomapper password
testit "jacknomapper" "${SMBCLIENT}" //"${SERVER}"/tmp -U"${SERVER}/jacknomapper%nOmApsEcrEt" -c ls || failed=$((failed + 1))

testok "$0" "${failed}"
