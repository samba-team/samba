# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

if "$CTDB_TEST_VERBOSE" ; then
	debug () { echo "$@" ; }
else
	debug () { : ; }
fi

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

PATH="${PATH}:${CTDB_SCRIPTS_TOOLS_HELPER_DIR}"
PATH="${PATH}:${CTDB_SCRIPTS_HELPER_BINDIR}"

setup_ctdb_base "$CTDB_TEST_TMP_DIR" "ctdb-etc"

ctdbd_socket=$(ctdb-path socket "ctdbd")
ctdbd_pidfile=$(ctdb-path pidfile "ctdbd")
ctdbd_dbdir=$(ctdb-path vardir append "db")

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
	rm -rf "$ctdbd_dbdir"
}

setup_ctdbd ()
{
	debug "Setting up fake ctdbd"

	mkdir -p "$ctdbd_dbdir"
	$VALGRIND fake_ctdbd -d "$FAKE_CTDBD_DEBUGLEVEL" \
		  -s "$ctdbd_socket" -p "$ctdbd_pidfile" \
		  -D "$ctdbd_dbdir"
	# This current translates to a 6 second timeout for the
	# important controls
	ctdb setvar TakeoverTimeout 2
	test_cleanup cleanup_ctdbd
}

# Render non-printable characters.  The helper prints the status as
# binary, so render it for easy comparison.
result_filter ()
{
	sed -e 's|ctdb-takeover\[[0-9]*\]: ||'
}

ctdb_cmd ()
{
	echo Running: ctdb -d "$CTDB_DEBUGLEVEL" "$@"
	ctdb -d "$CTDB_DEBUGLEVEL" "$@"
}

test_ctdb_ip_all ()
{
	unit_test ctdb -d "$CTDB_DEBUGLEVEL" ip all || exit $?
}

takeover_helper_out="${CTDB_TEST_TMP_DIR}/takover_helper.out"

takeover_helper_format_outfd ()
{
	od -A n -t d4 "$takeover_helper_out" | sed -e 's|[[:space:]]*||g'
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
	[ $_ret -eq 0 ] || exit $_ret
}
