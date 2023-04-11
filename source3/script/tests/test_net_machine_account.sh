#!/bin/sh
# Reproducer for https://bugzilla.samba.org/show_bug.cgi?id=14908

if [ $# -lt 2 ]; then
	echo "Usage: $0 NET CONFFILE SERVER_IP"
	exit 1
fi

NET="$1"
shift
CONFFILE="$1"
shift
SERVER_IP="$1"
shift

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

net_ads_user() {
	_out=$(UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		${VALGRIND} "${NET}" rpc user \
		--configfile="${CONFFILE}" -S "${SERVER_IP}" -P)
	_ret=$?

	echo "${_out}"

	return ${_ret}
}

testit "net_ads_user" net_ads_user || failed=$((failed + 1))

testok $0 $failed
