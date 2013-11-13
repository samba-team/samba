#!/bin/sh

(
    flock --wait 2 9 || exit 1

    echo "===== Start of hung script debug for PID=\"$1\", event=\"$2\" ====="

    echo "pstree -p -a ${1}:"
    pstree -p -a $1

    if [ "$2" = "init" ] ; then
	exit 0
    fi

    echo "ctdb scriptstatus ${2}:"
    # No use running several of these in parallel if, say, "releaseip"
    # event hangs for multiple IPs.  In that case the output would be
    # interleaved in the log and would just be confusing.
    ctdb scriptstatus "$2"

    echo "===== End of hung script debug for PID=\"$1\", event=\"$2\" ====="

) 9>"${CTDB_VARDIR}/debug-hung-script.lock"
