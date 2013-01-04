#!/bin/sh
#
# This script can be called from a cronjob to automatically drop/release
# all public ip addresses if CTDBD has crashed or stopped running.
#

# If ctdb is running, just exit
if ctdb ping >/dev/null 2>&1 ; then
    exit 0
fi

[ -n "$CTDB_BASE" ] || \
    export CTDB_BASE=$(cd -P $(dirname "$0") ; echo "$PWD")

. "$CTDB_BASE/functions"

loadconfig ctdb

[ -n "$CTDB_PUBLIC_ADDRESSES" ] || \
	CTDB_PUBLIC_ADDRESSES="$CTDB_BASE/public_addresses"

[ -f "$CTDB_PUBLIC_ADDRESSES" ] || \
    die "No public addresses file found. Can't clean up."

drop_all_public_ips "ctdb-crash-cleanup"

if [ -n "$CTDB_NATGW_PUBLIC_IP" ] ; then
    drop_ip "$CTDB_NATGW_PUBLIC_IP" "ctdb-crash-cleanup"
fi
