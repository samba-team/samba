#!/bin/sh

[ -n "$CTDB_BASE" ] || \
    export CTDB_BASE=$(cd -P $(dirname "$0") ; echo "$PWD")

. "$CTDB_BASE/functions"

loadconfig ctdb

# Testing hook
if [ -n "$CTDB_DEBUG_HUNG_SCRIPT_LOGFILE" ] ; then
    exec >>"$CTDB_DEBUG_HUNG_SCRIPT_LOGFILE" 2>&1
fi

(
    flock --wait 2 9 || exit 1

    echo "===== Start of hung script debug for PID=\"$1\", event=\"$2\" ====="

    echo "pstree -p -a ${1}:"
    out=$(pstree -p -a $1)
    echo "$out"

    # Check for processes matching a regular expression and print
    # stack staces.  This could help confirm that certain processes
    # are stuck in certain places such as the cluster filesystem.  The
    # regexp should separate items with "\|" and should not contain
    # parentheses.  The default pattern can be replaced for testing.
    default_pat='exportfs\|rpcinfo'
    pat="${CTDB_DEBUG_HUNG_SCRIPT_STACKPAT:-${default_pat}}"
    echo "$out" |
    sed -n "s@.*-\(.*${pat}.*\),\([0-9]*\).*@\2 \1@p" |
    while read pid name ; do
	trace=$(cat "/proc/${pid}/stack" 2>/dev/null)
	if [ $? -eq 0 ] ; then
	    echo "---- Stack trace of interesting process ${pid}[${name}] ----"
	    echo "$trace"
	fi
    done

    if [ "$2" = "init" ] ; then
	exit 0
    fi

    echo "---- ctdb scriptstatus ${2}: ----"
    # No use running several of these in parallel if, say, "releaseip"
    # event hangs for multiple IPs.  In that case the output would be
    # interleaved in the log and would just be confusing.
    ctdb scriptstatus "$2"

    echo "===== End of hung script debug for PID=\"$1\", event=\"$2\" ====="

) 9>"${CTDB_VARDIR}/debug-hung-script.lock"
