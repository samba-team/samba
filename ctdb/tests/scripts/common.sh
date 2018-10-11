# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Common variables and functions for all CTDB tests.

# Print a message and exit.
die ()
{
	echo "$1" >&2 ; exit ${2:-1}
}

# This expands the most probable problem cases like "." and "..".
TEST_SUBDIR=$(dirname "$0")
if [ $(dirname "$TEST_SUBDIR") = "." ] ; then
	TEST_SUBDIR=$(cd "$TEST_SUBDIR" ; pwd)
fi

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

if [ -d "$CTDB_SCRIPTS_TOOLS_BIN_DIR" ] ; then
	PATH="${CTDB_SCRIPTS_TOOLS_BIN_DIR}:${PATH}"
fi

if [ -d "$CTDB_SCRIPTS_TESTS_BINDIR" ] ; then
	PATH="${CTDB_SCRIPTS_TESTS_BINDIR}:${PATH}"
fi

# Wait until either timeout expires or command succeeds.  The command
# will be tried once per second, unless timeout has format T/I, where
# I is the recheck interval.
wait_until ()
{
    local timeout="$1" ; shift # "$@" is the command...

    local interval=1
    case "$timeout" in
	*/*)
	    interval="${timeout#*/}"
	    timeout="${timeout%/*}"
    esac

    local negate=false
    if [ "$1" = "!" ] ; then
	negate=true
	shift
    fi

    echo -n "<${timeout}|"
    local t=$timeout
    while [ $t -gt 0 ] ; do
	local rc=0
	"$@" || rc=$?
	if { ! $negate && [ $rc -eq 0 ] ; } || \
	    { $negate && [ $rc -ne 0 ] ; } ; then
	    echo "|$(($timeout - $t))|"
	    echo "OK"
	    return 0
	fi
	local i
	for i in $(seq 1 $interval) ; do
	    echo -n .
	done
	t=$(($t - $interval))
	sleep $interval
    done

    echo "*TIMEOUT*"

    return 1
}

# setup_ctdb_base <parent> <subdir> [item-to-copy]...
setup_ctdb_base ()
{
	[ $# -ge 2 ] || die "usage: setup_ctdb_base <parent> <subdir> [item]..."
	# If empty arguments are passed then we attempt to remove /
	# (i.e. the root directory) below
	[ -n "$1" -a -n "$2" ] || \
		die "usage: setup_ctdb_base <parent> <subdir> [item]..."

	_parent="$1"
	_subdir="$2"

	# Other arguments are files/directories to copy
	shift 2

	export CTDB_BASE="${_parent}/${_subdir}"
	if [ -d "$CTDB_BASE" ] ; then
		rm -r "$CTDB_BASE"
	fi
	mkdir -p "$CTDB_BASE" || die "Failed to create CTDB_BASE=$CTDB_BASE"
	mkdir -p "${CTDB_BASE}/run" || die "Failed to create ${CTDB_BASE}/run"
	mkdir -p "${CTDB_BASE}/var" || die "Failed to create ${CTDB_BASE}/var"

	for _i ; do
		cp -pr "${CTDB_SCRIPTS_BASE}/${_i}" "${CTDB_BASE}/"
	done

	mkdir -p "${CTDB_BASE}/events/legacy"

	if [ -z "$TEST_SUBDIR" ] ; then
		return
	fi

	for _i in "${TEST_SUBDIR}/etc-ctdb/"* ; do
		# No/empty etc-ctdb directory
		[ -e "$_i" ] || break

		cp -pr "$_i" "${CTDB_BASE}/"
	done
}
