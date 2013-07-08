#!/bin/sh

# This script parses /proc/locks and finds the processes that are holding
# locks on CTDB databases.  For all those processes the script dumps a
# stack trace using gstack.
#
# This script can be used only if Samba is configured to use fcntl locks
# rather than mutex locks.

# Create sed expression to convert inodes to names
sed_cmd=$( ls -li /var/ctdb/*.tdb.* /var/ctdb/persistent/*.tdb.* |
	   sed -e "s#/var/ctdb[/persistent]*/\(.*\)#\1#" |
	   awk '{printf "s#[0-9]*:[0-9]*:%s #%s #\n", $1, $10}' )

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
    echo "$out" | logger -t "ctdbd-lock"

    # Find processes that are waiting for locks
    dbs=$(echo "$out" | grep "W$" | awk '{print $3}')
    all_pids=""
    for db in $dbs ; do
	pids=$(echo "$out" | grep -v "W$" | grep "$db" | grep -v ctdbd | awk '{print $1}')
	all_pids="$all_pids $pids"
    done
    pids=$(echo $all_pids | sort -u)

    # For each process waiting, log stack trace
    for pid in $pids ; do
	gstack $pid | logger -t "ctdbd-lock $pid"
#	gcore -o /var/log/core-deadlock-ctdb $pid
    done
fi

exit 0
