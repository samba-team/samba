#!/bin/sh

DIRNAME=$(dirname $0)

CTDB_BASE="${DIRNAME}/../config"
. "${CTDB_BASE}/functions"

SERVICE="test-service"

PORTS="$@"

if [ "x${PORTS}" = "x" ] ; then
	PORTS=139
fi

ctdb_check_tcp_ports ${SERVICE} ${PORTS}

echo "Test for service '${SERVICE}' on tcp ports ${PORTS} succeeded!"
