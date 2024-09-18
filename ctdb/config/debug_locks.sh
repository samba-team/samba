#!/bin/sh

# This script attempts to find processes holding locks on a particular
# CTDB database and dumps a stack trace for each such process.
#
# There are 2 cases:
#
# * Samba is configured to use fcntl locks
#
#   In this case /proc/locks is parsed to find potential lock holders
#
# * Samba is configured to use POSIX robust mutexes
#
#   In this case the helper program tdb_mutex_check is used to find
#   potential lock holders.
#
#   This helper program uses a private glibc struct field, so is
#   neither portable nor supported.  If this field is not available
#   then the helper is not built.  Unexpected changes in internal
#   glibc structures may cause unexpected results, including crashes.
#   Bug reports for this helper program are not accepted without an
#   accompanying patch.

[ -n "$CTDB_BASE" ] || \
	CTDB_BASE=$(d=$(dirname "$0") && cd -P "$d" && echo "$PWD")

. "${CTDB_BASE}/functions"

if [ $# -ne 4 ] ; then
	die "usage: $0 <pid> { DB | RECORD } <tdb_path> { FCNTL | MUTEX }"
fi

lock_helper_pid="$1"
# lock_scope is unused for now
# shellcheck disable=SC2034
lock_scope="$2"
tdb_path="$3"
lock_type="$4"

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

dump_stack ()
{
	_pid="$1"

	echo "----- Stack trace for PID=${_pid} -----"
	_state=$(ps -p "$_pid" -o state= | cut -c 1)
	if [ "$_state" = "D" ] ; then
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
		get_proc "${_pid}/stack"
	else
		gstack "$_pid"
	fi
}

dump_stacks ()
{
	_pids="$1"

	# Use word splitting to squash whitespace
	# shellcheck disable=SC2086
	_pids=$(echo $_pids | tr ' ' '\n' | sort -u)

	for _pid in $_pids; do
		dump_stack "$_pid"
	done
}

get_tdb_file_id ()
{
	if ! _device_inode=$(stat -c "%d:%i" "$tdb_path" 2>/dev/null) ; then
		die "Unable to stat \"${tdb_path}\""
	fi
	_device="${_device_inode%%:*}"
	_device_major=$((_device >> 8))
	_device_minor=$((_device & 0xff))
	_inode="${_device_inode#*:}"
	printf '%02x:%02x:%u\n' "$_device_major" "$_device_minor" "$_inode"
}

debug_via_proc_locks ()
{
	# Get file ID to match relevant column in /proc/locks
	_file_id=$(get_tdb_file_id)

	# Log information from /proc/locks about the waiting process
	_tdb=$(basename "$tdb_path")
	_comm=$(ps -p "$lock_helper_pid" -o comm=)
	_out=$(get_proc "locks" |
	       awk -v pid="$lock_helper_pid" \
		   -v file_id="$_file_id" \
		   -v file="$_tdb" \
		   -v comm="$_comm" \
		   '$2 == "->" &&
		    $3 == "POSIX" &&
		    $4 == "ADVISORY" &&
		    $5 == "WRITE" &&
		    $6 == pid &&
		    $7 == file_id { print $6, comm, file, $8, $9 }')
	if [ -n "$_out" ] ; then
		echo "Waiter:"
		echo "$_out"
	fi

	# Parse /proc/locks and find process holding locks on $tdb_path
	# extract following information
	#    pid process_name tdb_name offsets
	_out=$(get_proc "locks" |
	       awk -v pid="$lock_helper_pid" \
		   -v file_id="$_file_id" \
		   -v file="$_tdb" \
		   '$2 == "POSIX" &&
		    $3 == "ADVISORY" &&
		    $4 == "WRITE" &&
		    $5 != pid &&
		    $6 == file_id { print $5, file, $7, $8 }' |
	       while read -r _pid _rest ; do
		       _pname=$(ps -p "$_pid" -o comm=)
		       echo "$_pid $_pname $_rest"
	       done)

	if [ -z "$_out" ]; then
		return
	fi

	# Log information about locks
	echo "Lock holders:"
	echo "$_out"

	_pids=$(echo "$_out" | awk '{ print $1 }')

	lock_holder_pids="${lock_holder_pids:+${lock_holder_pids} }${_pids}"
}

debug_via_tdb_mutex ()
{
	_helper="${CTDB_HELPER_BINDIR}/tdb_mutex_check"
	if [ ! -x "$_helper" ] ; then
		# Mutex helper not available - not supported?
		# Avoid not found error...
		return
	fi

	# Helper should always succeed
	if ! _t=$("$_helper" "$tdb_path") ; then
		return
	fi

	_out=$(echo "$_t" | sed -n -e 's#^\[\(.*\)\] pid=\(.*\)#\2 \1#p')

	if [ -z "$_out" ]; then
		if [ -n "$_t" ] ; then
			echo "$_t" | grep -F 'trylock failed'
		fi
		return
	fi

	# Get process names, append $tdb_path
	_out=$(echo "$_out" |
	       while read -r _pid _rest ; do
		       _pname=$(ps -p "$_pid" -o comm=)
		       _tdb=$(basename "$tdb_path")
		       echo "${_pid} ${_pname} ${_tdb} ${_rest}"
	       done)

	# Log information about locks
	echo "Lock holders:"
	echo "$_out"

	# Get PIDs of processes that are holding locks
	_pids=$(echo "$_out" |
		awk -v pid="$lock_helper_pid" '$1 != pid {print $1}')

	lock_holder_pids="${lock_holder_pids:+${lock_holder_pids} }${_pids}"
}

(
	flock -n 9 || exit 1

	echo "===== Start of debug locks PID=$$ ====="

	lock_holder_pids=""

	debug_via_proc_locks

	if [ "$lock_type" = "MUTEX" ] ; then
		debug_via_tdb_mutex
	fi

	dump_stacks "$lock_holder_pids"

	echo "===== End of debug locks PID=$$ ====="
)9>"${CTDB_SCRIPT_VARDIR}/debug_locks.lock" | script_log "ctdbd-lock"

exit 0
