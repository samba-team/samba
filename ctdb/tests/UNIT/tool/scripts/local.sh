# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

PATH="${PATH}:${CTDB_SCRIPTS_TOOLS_HELPER_DIR}"
PATH="${PATH}:${CTDB_SCRIPTS_HELPER_BINDIR}"

setup_ctdb_base "$CTDB_TEST_TMP_DIR" "ctdb-etc" \
		functions

if "$CTDB_TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

ctdbd_socket=$(ctdb-path socket "ctdbd")
ctdbd_pidfile=$(ctdb-path pidfile "ctdbd")
ctdbd_dbdir=$(ctdb-path vardir append "db")

define_test ()
{
    _f=$(basename "$0" ".sh")

    case "$_f" in
	ctdb.*)
	    _cmd="${_f#ctdb.}"
	    _cmd="${_cmd%.*}" # Strip test number
	    export CTDB="ctdb"
	    export CTDB_DEBUGLEVEL=NOTICE
	    if [ -z "$FAKE_CTDBD_DEBUGLEVEL" ] ; then
		    FAKE_CTDBD_DEBUGLEVEL="ERR"
	    fi
	    export FAKE_CTDBD_DEBUGLEVEL
	    test_args="$_cmd"
	    ;;
	*)
	    die "Unknown pattern for testcase \"$_f\""
    esac

    printf "%-28s - %s\n" "$_f" "$1"
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
	echo "Setting up fake ctdbd"

	mkdir -p "$ctdbd_dbdir"
	$VALGRIND fake_ctdbd -d "$FAKE_CTDBD_DEBUGLEVEL" \
		  -s "$ctdbd_socket" -p "$ctdbd_pidfile" \
		  -D "$ctdbd_dbdir"
	# Wait till fake_ctdbd is running
	wait_until 10 test -S "$ctdbd_socket" || \
		die "fake_ctdbd failed to start"

	test_cleanup cleanup_ctdbd
}

ctdbd_getpid ()
{
	cat "$ctdbd_pidfile"
}

setup_natgw ()
{
	debug "Setting up NAT gateway"

	export CTDB_NATGW_HELPER="${CTDB_SCRIPTS_TOOLS_HELPER_DIR}/ctdb_natgw"
	export CTDB_NATGW_NODES="${CTDB_BASE}/natgw_nodes"

	cat >"$CTDB_NATGW_NODES"
}

setup_lvs ()
{
	debug "Setting up LVS"

	export CTDB_LVS_HELPER="${CTDB_SCRIPTS_TOOLS_HELPER_DIR}/ctdb_lvs"
	export CTDB_LVS_NODES="${CTDB_BASE}/lvs_nodes"

	cat >"$CTDB_LVS_NODES"
}

setup_nodes ()
{
    _pnn="$1"

    _f="${CTDB_BASE}/nodes${_pnn:+.}${_pnn}"

    cat >"$_f"
}

simple_test_other ()
{
	unit_test $CTDB -d $CTDB_DEBUGLEVEL "$@"
}

simple_test ()
{
	simple_test_other $test_args "$@"
}
