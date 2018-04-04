#!/bin/sh
#
# This script can be called from a cronjob to automatically drop/release
# all public ip addresses if CTDBD has crashed or stopped running.
#

[ -n "$CTDB_BASE" ] || \
    CTDB_BASE=$(d=$(dirname "$0") ; cd -P "$d" ; echo "$PWD")

. "${CTDB_BASE}/functions"

# If ctdb is running, just exit
if service ctdb status >/dev/null 2>&1 ; then
    exit 0
fi

load_script_options "failover" "11.natgw"

if [ ! -f "$CTDB_BASE/public_addresses" ] ; then
	die "No public addresses file found. Can't clean up."
fi

drop_all_public_ips 2>&1 | script_log "ctdb-crash-cleanup.sh"

if [ -n "$CTDB_NATGW_PUBLIC_IP" ] ; then
    drop_ip "$CTDB_NATGW_PUBLIC_IP" "ctdb-crash-cleanup.sh"
fi
