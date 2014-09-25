#!/bin/sh

# This script parses /proc/locks and finds the processes that are holding
# locks on CTDB databases.  For all those processes the script dumps a
# stack trace using gstack.
#
# This script can be used only if Samba is configured to use fcntl locks
# rather than mutex locks.

[ -n "$CTDB_BASE" ] || \
    export CTDB_BASE=$(cd -P $(dirname "$0") ; echo "$PWD")

. "$CTDB_BASE/functions"

# Default fallback location for database directories.
# These can be overwritten from CTDB configuration
CTDB_DBDIR="${CTDB_VARDIR}"
CTDB_DBDIR_PERSISTENT="${CTDB_VARDIR}/persistent"

loadconfig ctdb

(
    flock -n 9 || exit 1

    echo "===== Start of debug locks PID=$$ ====="

    # Create sed expression to convert inodes to names
    sed_cmd=$( ls -li "$CTDB_DBDIR"/*.tdb.* "$CTDB_DBDIR_PERSISTENT"/*.tdb.* |
	   sed -e "s#${CTDB_DBDIR}/\(.*\)#\1#" \
	       -e "s#${CTDB_DBDIR_PERSISTENT}/\(.*\)#\1#" |
	   awk '{printf "s#[0-9a-f]*:[0-9a-f]*:%s #%s #\n", $1, $10}' )

    # Parse /proc/locks and extract following information
    #    pid process_name tdb_name offsets [W]
    out=$( cat /proc/locks |
    grep -F "POSIX  ADVISORY  WRITE" |
    awk '{ if($2 == "->") { print $6, $7, $8, $9, "W" } else { print $5, $6, $7, $8 } }' |
    while read pid rest ; do
	pname=$(readlink /proc/$pid/exe)
	echo $pid $pname $rest
    done | sed -e "$sed_cmd" | grep "\.tdb" )

    if [ -n "$out" ]; then
	# Log information about locks
	echo "$out"

	# Find processes that are waiting for locks
	dbs=$(echo "$out" | grep "W$" | awk '{print $3}')
	all_pids=""
	for db in $dbs ; do
	    pids=$(echo "$out" | grep -v "W$" | grep "$db" | grep -v ctdbd | awk '{print $1}')
	    all_pids="$all_pids $pids"
	done
	pids=$(echo $all_pids | tr " " "\n" | sort -u)

	# For each process waiting, log stack trace
	for pid in $pids ; do
	    echo "----- Stack trace for PID=$pid -----"
	    gstack $pid
	    # gcore -o /var/log/core-deadlock-ctdb $pid
	done
    fi

    echo "===== End of debug locks PID=$$ ====="

) 9>"${CTDB_VARDIR}/debug_locks.lock" | script_log "ctdbd-lock"

exit 0
