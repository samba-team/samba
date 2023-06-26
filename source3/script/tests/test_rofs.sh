#!/usr/bin/env bash
# Test smbd handling EROFS when creating a file
# Copyright (C) 2023 Volker Lendecke

if [ $# -ne 4 ]; then
	echo Usage: $0 SERVERCONFFILE SMBCLIENT SERVER SHARE
	exit 1
fi

CONF=$1
shift 1
SMBCLIENT=$1
shift 1
SERVER=$1
shift 1
SHARE=$1
shift 1

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

error_inject_conf=$(dirname ${SERVERCONFFILE})/error_inject.conf
echo "error_inject:openat_create = EROFS" >${error_inject_conf}

failed=0

out=$(${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} -U${USER}%${PASSWORD} \
		   -c "put VERSION")
testit_grep "Expect MEDIA_WRITE_PROTECTED" NT_STATUS_MEDIA_WRITE_PROTECTED \
    echo "$out" || failed=$(expr $failed + 1)

>${error_inject_conf}

testok $0 $failed
