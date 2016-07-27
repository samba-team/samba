# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Augment PATH with stubs/ directory.

if "$TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

ctdbd_socket="${TEST_VAR_DIR}/ctdbd.socket.$$"
ctdbd_pidfile="${TEST_VAR_DIR}/ctdbd.pid.$$"

define_test ()
{
    _f=$(basename "$0" ".sh")

    case "$_f" in
	ctdb.*)
	    _cmd="${_f#ctdb.}"
	    _cmd="${_cmd%.*}" # Strip test number
	    export CTDB="ctdb --socket $ctdbd_socket"
	    export CTDB_DEBUGLEVEL=2
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
}

setup_ctdbd ()
{
	debug "Setting up fake ctdbd"

	$VALGRIND fake_ctdbd -s "$ctdbd_socket" -p "$ctdbd_pidfile"
	test_cleanup cleanup_ctdbd
}

ctdbd_getpid ()
{
	cat "$ctdbd_pidfile"
}

setup_natgw ()
{
	debug "Setting up NAT gateway"

	# Use in-tree binaries if running against local daemons.
	# Otherwise CTDB need to be installed on all nodes.
	if [ -n "$ctdb_dir" -a -d "${ctdb_dir}/bin" ] ; then
		if [ -z "$CTDB_NATGW_HELPER" ] ; then
			export CTDB_NATGW_HELPER="${ctdb_dir}/tools/ctdb_natgw"
		fi
		# Only want to find functions file, so this is OK
		export CTDB_BASE="${ctdb_dir}/config"
	fi

	natgw_config_dir="${TEST_VAR_DIR}/natgw_config"
	mkdir -p "$natgw_config_dir"

	export CTDB_NATGW_NODES=$(mktemp --tmpdir="$natgw_config_dir")
	test_cleanup "rm -f $CTDB_NATGW_NODES"

	cat >"$CTDB_NATGW_NODES"
}

setup_lvs ()
{
	debug "Setting up LVS"

	# Use in-tree binaries if running against local daemons.
	# Otherwise CTDB need to be installed on all nodes.
	if [ -n "$ctdb_dir" -a -d "${ctdb_dir}/bin" ] ; then
		if [ -z "$CTDB_LVS_HELPER" ] ; then
			export CTDB_LVS_HELPER="${ctdb_dir}/tools/ctdb_lvs"
		fi
		# Only want to find functions file, so this is OK
		export CTDB_BASE="${ctdb_dir}/config"
	fi

	lvs_config_dir="${TEST_VAR_DIR}/lvs_config"
	mkdir -p "$lvs_config_dir"

	export CTDB_LVS_NODES=$(mktemp --tmpdir="$lvs_config_dir")
	test_cleanup "rm -f ${CTDB_LVS_NODES}"

	cat >"$CTDB_LVS_NODES"
}

setup_nodes ()
{
    _pnn="$1"

    _v="CTDB_NODES${_pnn:+_}${_pnn}"
    debug "Setting up ${_v}"

    eval export "${_v}"=$(mktemp --tmpdir="$TEST_VAR_DIR")

    eval _f="\${${_v}}"
    test_cleanup "rm -f ${_f}"
    cat >"$_f"

    # You can't be too careful about what might be in the
    # environment...  so clean up when setting the default variable.
    if [ -z "$_pnn" ] ; then
	_n=$(wc -l "$CTDB_NODES" | awk '{ print $1 }')
	for _i in $(seq 0 $_n) ; do
	    eval unset "CTDB_NODES_${_i}"
	done
    fi
}

simple_test_other ()
{
	(unit_test $CTDB -d $CTDB_DEBUGLEVEL "$@")
	status=$?
	[ $status -eq 0 ] || exit $status
}

simple_test ()
{
	simple_test_other $test_args "$@"
}
