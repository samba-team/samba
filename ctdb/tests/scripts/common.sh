# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Common variables and functions for all CTDB tests.


# Commands on different platforms may quote or sort things differently
# without this
export LANG=C

# Print a message and exit.
die ()
{
	echo "$1" >&2 ; exit "${2:-1}"
}

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

if [ -d "$CTDB_SCRIPTS_TOOLS_BIN_DIR" ] ; then
	PATH="${CTDB_SCRIPTS_TOOLS_BIN_DIR}:${PATH}"
fi

if [ -d "$CTDB_SCRIPTS_TESTS_LIBEXEC_DIR" ] ; then
	PATH="${CTDB_SCRIPTS_TESTS_LIBEXEC_DIR}:${PATH}"
fi

ctdb_test_error ()
{
	if [ $# -gt 0 ] ; then
		echo "$*"
	fi
	exit 99
}

ctdb_test_fail ()
{
	if [ $# -gt 0 ] ; then
		echo "$*"
	fi
	exit 1
}

ctdb_test_skip ()
{
	if [ $# -gt 0 ] ; then
		echo "$*"
	fi
	exit 77
}

# "$@" is supported OSes
ctdb_test_check_supported_OS ()
{
	_os=$(uname -s)
	for _i ; do
		if [ "$_os" = "$_i" ] ; then
			return
		fi
	done

	ctdb_test_skip "This test is not supported on ${_os}"
}

# Wait until either timeout expires or command succeeds.  The command
# will be tried once per second, unless timeout has format T/I, where
# I is the recheck interval.
wait_until ()
{
	_timeout="$1" ; shift # "$@" is the command...

	_interval=1
	case "$_timeout" in
	*/*)
		_interval="${_timeout#*/}"
		_timeout="${_timeout%/*}"
	esac

	_negate=false
	if [ "$1" = "!" ] ; then
		_negate=true
		shift
	fi

	printf '<%d|' "$_timeout"
	_t="$_timeout"
	while [ "$_t" -gt 0 ] ; do
		_rc=0
		"$@" || _rc=$?
		if { ! $_negate && [ $_rc -eq 0 ] ; } || \
			   { $_negate && [ $_rc -ne 0 ] ; } ; then
			echo "|$((_timeout - _t))|"
			echo "OK"
			return 0
		fi
		for _i in $(seq 1 "$_interval") ; do
			printf '.'
		done
		_t=$((_t - _interval))
		sleep "$_interval"
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
	if [ -z "$1" ] || [ -z "$2" ] ; then
		die "usage: setup_ctdb_base <parent> <subdir> [item]..."
	fi

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

	if [ -z "$CTDB_TEST_SUITE_DIR" ] ; then
		return
	fi

	for _i in "${CTDB_TEST_SUITE_DIR}/etc-ctdb/"* ; do
		# No/empty etc-ctdb directory
		[ -e "$_i" ] || break

		cp -pr "$_i" "${CTDB_BASE}/"
	done
}
