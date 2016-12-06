# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Augment PATH with stubs/ directory.

if "$TEST_VERBOSE" ; then
	debug () { echo "$@" ; }
else
	debug () { : ; }
fi

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

ctdbd_socket="${TEST_VAR_DIR}/ctdbd.socket.$$"
ctdbd_pidfile="${TEST_VAR_DIR}/ctdbd.pid.$$"

define_test ()
{
	_f=$(basename "$0" ".sh")

	printf "%-28s - %s\n" "$_f" "$1"

	if [ -z "$FAKE_CTDBD_DEBUGLEVEL" ] ; then
		FAKE_CTDBD_DEBUGLEVEL="ERR"
	fi
	if [ -z "$HELPER_DEBUGLEVEL" ] ; then
		HELPER_DEBUGLEVEL="NOTICE"
	fi
	if [ -z "$CTDB_DEBUGLEVEL" ] ; then
		CTDB_DEBUGLEVEL="ERR"
	fi
}

cleanup_ctdbd ()
{
	debug "Cleaning up fake ctdbd"

	pid=$(cat "$ctdbd_pidfile" 2>/dev/null || echo)
	if [ -n "$pid" ] ; then
		kill $pid || true
		rm -f "$ctdbd_pidfile"
	fi
	rm -f "$ctdbd_socket"
}

setup_ctdbd ()
{
	debug "Setting up fake ctdbd"

	$VALGRIND fake_ctdbd -d "$FAKE_CTDBD_DEBUGLEVEL" \
		  -s "$ctdbd_socket" -p "$ctdbd_pidfile"
	# This current translates to a 6 second timeout for the
	# important controls
	ctdb --socket $ctdbd_socket setvar TakeoverTimeout 2
	test_cleanup cleanup_ctdbd
}

ctdbd_getpid ()
{
	cat "$ctdbd_pidfile"
}

# Render non-printable characters.  The helper prints the status as
# binary, so render it for easy comparison.
result_filter ()
{
	sed -e 's|ctdb-takeover\[[0-9]*\]: ||'
}

ctdb_cmd ()
{
	echo Running: ctdb -d "$CTDB_DEBUGLEVEL" --socket $ctdbd_socket "$@"
	ctdb -d "$CTDB_DEBUGLEVEL" --socket $ctdbd_socket "$@"
}

test_ctdb_ip_all ()
{
	unit_test ctdb -d "$CTDB_DEBUGLEVEL" \
		  --socket $ctdbd_socket ip all || exit $?
}

takeover_helper_out="${TEST_VAR_DIR}/takover_helper.out"

takeover_helper_format_outfd ()
{
	od -A n -t d4 "$takeover_helper_out" | sed -e 's|^[[:space:]]*||'
}

test_takeover_helper ()
{
	(
		export CTDB_DEBUGLEVEL="$HELPER_DEBUGLEVEL"
		export CTDB_LOGGING="file:"
		unit_test ctdb_takeover_helper 3 "$ctdbd_socket" "$@" \
			  3>"$takeover_helper_out"
	) || exit $?

	case "$required_rc" in
	255) _t="-1" ;;
	*) _t="$required_rc" ;;
	esac
	ok "$_t"

	unit_test_notrace takeover_helper_format_outfd
	_ret=$?
	rm "$takeover_helper_out"
	[ $? -eq 0 ] || exit $?
}
