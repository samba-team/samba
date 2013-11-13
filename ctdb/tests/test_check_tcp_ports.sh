#!/bin/sh

DIRNAME=$(dirname $0)

. ${DIRNAME}/../config/functions

SERVICE="test-service"

PORTS="$@"

if [ "x${PORTS}" = "x" ] ; then
	PORTS=139
fi

ctdb_check_tcp_ports ${SERVICE} ${PORTS}

echo "Test for service '${SERVICE}' on tcp ports ${PORTS} succeeded!"
