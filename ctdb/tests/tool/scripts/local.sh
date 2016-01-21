# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Augment PATH with stubs/ directory.

if [ -d "${TEST_SUBDIR}/stubs" ] ; then
    PATH="${TEST_SUBDIR}/stubs:$PATH"
fi

if "$TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

define_test ()
{
    _f=$(basename "$0" ".sh")

    case "$_f" in
	func.*)
	    _func="${_f#func.}"
	    _func="${_func%.*}" # Strip test number
	    export CTDB_TEST_PROG="ctdb_functest"
	    test_args="$_func"
	    ;;
	stubby.*)
	    _cmd="${_f#stubby.}"
	    _cmd="${_cmd%.*}" # Strip test number
	    export CTDB_TEST_PROG="ctdb_stubtest"
	    test_args="$_cmd"
	    ;;
	*)
	    die "Unknown pattern for testcase \"$_f\""
    esac

    printf "%-28s - %s\n" "$_f" "$1"
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

	# These will accumulate, 1 per test... but will be cleaned up
	# at the end.
	export CTDB_NATGW_NODES=$(mktemp --tmpdir="$natgw_config_dir")

	cat >"$CTDB_NATGW_NODES"
}

setup_nodes ()
{
    _pnn="$1"

    _v="CTDB_NODES${_pnn:+_}${_pnn}"
    debug "Setting up ${_v}"

    # These will accumulate, 1 per test... but will be cleaned up at
    # the end.
    eval export "${_v}"=$(mktemp --tmpdir="$TEST_VAR_DIR")

    eval _f="\${${_v}}"
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

simple_test ()
{
    : ${CTDB_DEBUGLEVEL:=3}
    export CTDB_DEBUGLEVEL

    unit_test ctdb $test_args "$@"
}
