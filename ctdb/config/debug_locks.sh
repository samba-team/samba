#!/bin/sh

# This script parses /proc/locks and finds the processes that are holding
# locks on CTDB databases.  For all those processes the script dumps a
# stack trace.
#
# This script can be used only if Samba is configured to use fcntl locks
# rather than mutex locks.

[ -n "$CTDB_BASE" ] || \
    CTDB_BASE=$(d=$(dirname "$0") ; cd -P "$d" ; echo "$PWD")

. "${CTDB_BASE}/functions"

# type is at least mentioned in POSIX and more is portable than which(1)
# shellcheck disable=SC2039
if ! type gstack >/dev/null 2>&1 ; then
	gstack ()
	{
		_pid="$1"

		gdb -batch --quiet -nx "/proc/${_pid}/exe" "$_pid" \
		    -ex "thread apply all bt" 2>/dev/null |
			grep '^\(#\|Thread \)'
	}
fi

# Load/cache database options from configuration file
ctdb_get_db_options

(
    flock -n 9 || exit 1

    echo "===== Start of debug locks PID=$$ ====="

    # Create sed expression to convert inodes to names.
    # Filenames don't contain dashes and we want basenames
    # shellcheck disable=SC2035
    sed_cmd=$(cd "$CTDB_DBDIR" &&
		  stat -c "s#[0-9a-f]*:[0-9a-f]*:%i #%n #" *.tdb.* 2>/dev/null ;
	      cd "$CTDB_DBDIR_PERSISTENT" &&
		  stat -c "s#[0-9a-f]*:[0-9a-f]*:%i #%n #" *.tdb.* 2>/dev/null)

    # Parse /proc/locks and extract following information
    #    pid process_name tdb_name offsets [W]
    out=$( grep -F "POSIX  ADVISORY  WRITE" /proc/locks |
    awk '{ if($2 == "->") { print $6, $7, $8, $9, "W" } else { print $5, $6, $7, $8 } }' |
    while read pid rest ; do
	pname=$(readlink "/proc/${pid}/exe")
	echo "$pid $pname $rest"
    done | sed -e "$sed_cmd" | grep '\.tdb' )

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
	# Use word splitting to squash whitespace
	# shellcheck disable=SC2086
	pids=$(echo $all_pids | tr ' ' '\n' | sort -u)

	# For each process waiting, log stack trace
	for pid in $pids ; do
	    echo "----- Stack trace for PID=$pid -----"
	    # x is intentionally ignored
	    # shellcheck disable=SC2034
	    read x x state x <"/proc/${pid}/stat"
	    if [ "$state" = "D" ] ; then
		# Don't run gstack on a process in D state since
		# gstack will hang until the process exits D state.
		# Although it is possible for a process to transition
		# to D state after this check, it is unlikely because
		# if a process is stuck in D state then it is probably
		# the reason why this script was called.  Note that a
		# kernel stack almost certainly won't help diagnose a
		# deadlock... but it will probably give us someone to
		# blame!
		echo "----- Process in D state, printing kernel stack only"
		cat "/proc/${pid}/stack"
	    else
		gstack "$pid"
	    fi
	done
    fi

    echo "===== End of debug locks PID=$$ ====="
)9>"${CTDB_SCRIPT_VARDIR}/debug_locks.lock" | script_log "ctdbd-lock"

exit 0
