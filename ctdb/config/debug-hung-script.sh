#!/bin/sh

# This script only works on Linux.  Please modify (and submit patches)
# for other operating systems.

[ -n "$CTDB_BASE" ] || \
    CTDB_BASE=$(d=$(dirname "$0") ; cd -P "$d" ; echo "$PWD")

. "${CTDB_BASE}/functions"

load_script_options

# Testing hook
if [ -n "$CTDB_DEBUG_HUNG_SCRIPT_LOGFILE" ] ; then
    tmp="${CTDB_DEBUG_HUNG_SCRIPT_LOGFILE}.part"
    exec >>"$tmp" 2>&1
fi

(
    # No use running several of these in parallel if, say, "releaseip"
    # event hangs for multiple IPs.  In that case the output would be
    # interleaved in the log and would just be confusing.
    flock --wait 2 9 || exit 1

    echo "===== Start of hung script debug for PID=\"$1\", event=\"$2\" ====="

    echo "pstree -p -a ${1}:"
    out=$(pstree -p -a "$1")
    echo "$out"

    # Check for processes matching a regular expression and print
    # stack staces.  This could help confirm that certain processes
    # are stuck in certain places such as the cluster filesystem.  The
    # regexp must separate items with "|" and must not contain
    # parentheses.  The default pattern can be replaced for testing.
    default_pat='exportfs|rpcinfo'
    pat="${CTDB_DEBUG_HUNG_SCRIPT_STACKPAT:-${default_pat}}"
    echo "$out" |
    sed -r -n "s@.*-(.*(${pat}).*),([0-9]*).*@\\3 \\1@p" |
    while read pid name ; do
	trace=$(cat "/proc/${pid}/stack" 2>/dev/null)
	# No! Checking the exit code afterwards is actually clearer...
	# shellcheck disable=SC2181
	if [ $? -eq 0 ] ; then
	    echo "---- Stack trace of interesting process ${pid}[${name}] ----"
	    echo "$trace"
	fi
    done

    if [ "$2" != "init" ] ; then
	echo "---- ctdb scriptstatus ${2}: ----"
	$CTDB scriptstatus "$2"
    fi

    echo "===== End of hung script debug for PID=\"$1\", event=\"$2\" ====="

    if [ -n "$CTDB_DEBUG_HUNG_SCRIPT_LOGFILE" ] ; then
	mv "$tmp" "$CTDB_DEBUG_HUNG_SCRIPT_LOGFILE"
    fi

) 9>"${CTDB_SCRIPT_VARDIR}/debug-hung-script.lock"
