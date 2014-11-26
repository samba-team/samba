# If we're not running on a real cluster then we need a local copy of
# ctdb (and other stuff) in $PATH and we will use local daemons.

export CTDB_NODES_SOCKETS=""
for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
    CTDB_NODES_SOCKETS="${CTDB_NODES_SOCKETS}${CTDB_NODES_SOCKETS:+ }${TEST_VAR_DIR}/sock.${i}"
done

# Use in-tree binaries if running against local daemons.
# Otherwise CTDB need to be installed on all nodes.
if [ -n "$ctdb_dir" -a -d "${ctdb_dir}/bin" ] ; then
    PATH="${ctdb_dir}/bin:${PATH}"
    export CTDB_LOCK_HELPER="${ctdb_dir}/bin/ctdb_lock_helper"
    export CTDB_EVENT_HELPER="${ctdb_dir}/bin/ctdb_event_helper"
fi

export CTDB_NODES="${TEST_VAR_DIR}/nodes.txt"

#######################################

daemons_stop ()
{
    echo "Attempting to politely shutdown daemons..."
    onnode 1 $CTDB shutdown -n all || true

    echo "Sleeping for a while..."
    sleep_for 1

    local pat="ctdbd --socket=${TEST_VAR_DIR}/.* --nlist .* --nopublicipcheck"
    if pgrep -f "$pat" >/dev/null ; then
	echo "Killing remaining daemons..."
	pkill -f "$pat"

	if pgrep -f "$pat" >/dev/null ; then
	    echo "Once more with feeling.."
	    pkill -9 -f "$pat"
	fi
    fi

    rm -rf "${TEST_VAR_DIR}/test.db"
}

setup_ctdb ()
{
    mkdir -p "${TEST_VAR_DIR}/test.db/persistent"

    local public_addresses_all="${TEST_VAR_DIR}/public_addresses_all"
    local no_public_addresses="${TEST_VAR_DIR}/no_public_addresses.txt"
    rm -f $CTDB_NODES $public_addresses_all $no_public_addresses

    # If there are (strictly) greater than 2 nodes then we'll randomly
    # choose a node to have no public addresses.
    local no_public_ips=-1
    [ $TEST_LOCAL_DAEMONS -gt 2 ] && no_public_ips=$(($RANDOM % $TEST_LOCAL_DAEMONS))
    echo "$no_public_ips" >$no_public_addresses

    # When running certain tests we add and remove eventscripts, so we
    # need to be able to modify the events.d/ directory.  Therefore,
    # we use a temporary events.d/ directory under $TEST_VAR_DIR.  We
    # copy the actual test eventscript(s) in there from the original
    # events.d/ directory that sits alongside $TEST_SCRIPT_DIR.
    local top=$(dirname "$TEST_SCRIPTS_DIR")
    local events_d="${top}/events.d"
    mkdir -p "${TEST_VAR_DIR}/events.d"
    cp -p "${events_d}/"* "${TEST_VAR_DIR}/events.d/"

    local i
    for i in $(seq 1 $TEST_LOCAL_DAEMONS) ; do
	if [ "${CTDB_USE_IPV6}x" != "x" ]; then
	    j=$((printf "%02x" $i))
	    echo "fd00::5357:5f${j}" >>"$CTDB_NODES"
	    # FIXME: need to add addresses to lo as root before running :-(
	    # ip addr add "fc00:10::${i}/64" dev lo
	    # 2 public addresses on most nodes, just to make things interesting.
	    if [ $(($i - 1)) -ne $no_public_ips ] ; then
		echo "fc00:10::1:${i}/64 lo" >>"$public_addresses_all"
		echo "fc00:10::1:$(($i + $TEST_LOCAL_DAEMONS))/64 lo" >>"$public_addresses_all"
	    fi
	else
	    j=$(( $i + 10))
	    echo 127.0.0.$j >>"$CTDB_NODES"
	    # 2 public addresses on most nodes, just to make things interesting.
	    if [ $(($i - 1)) -ne $no_public_ips ] ; then
		echo "192.168.234.$i/24 lo" >>"$public_addresses_all"
		echo "192.168.234.$(($i + $TEST_LOCAL_DAEMONS))/24 lo" >>"$public_addresses_all"
	    fi
	fi
    done
}

daemons_start_1 ()
{
    local pnn="$1"
    shift # "$@" gets passed to ctdbd

    local public_addresses_all="${TEST_VAR_DIR}/public_addresses_all"
    local public_addresses_mine="${TEST_VAR_DIR}/public_addresses.${pnn}"
    local no_public_addresses="${TEST_VAR_DIR}/no_public_addresses.txt"

    local no_public_ips=-1
    [ -r $no_public_addresses ] && read no_public_ips <$no_public_addresses

    if  [ "$no_public_ips" = $pnn ] ; then
	echo "Node $no_public_ips will have no public IPs."
    fi

    local node_ip=$(sed -n -e "$(($pnn + 1))p" "$CTDB_NODES")
    local ctdb_options="--sloppy-start --reclock=${TEST_VAR_DIR}/rec.lock --nlist $CTDB_NODES --nopublicipcheck --listen=${node_ip} --event-script-dir=${TEST_VAR_DIR}/events.d --logfile=${TEST_VAR_DIR}/daemon.${pnn}.log -d 3 --dbdir=${TEST_VAR_DIR}/test.db --dbdir-persistent=${TEST_VAR_DIR}/test.db/persistent --dbdir-state=${TEST_VAR_DIR}/test.db/state --nosetsched"

    if [ $pnn -eq $no_public_ips ] ; then
	ctdb_options="$ctdb_options --public-addresses=/dev/null"
    else
	cp "$public_addresses_all" "$public_addresses_mine"
	ctdb_options="$ctdb_options --public-addresses=$public_addresses_mine"
    fi

    # We'll use "pkill -f" to kill the daemons with
    # "--socket=.* --nlist .* --nopublicipcheck" as context.
    $VALGRIND ctdbd --socket="${TEST_VAR_DIR}/sock.$pnn" $ctdb_options "$@" ||return 1
}

daemons_start ()
{
    # "$@" gets passed to ctdbd

    echo "Starting $TEST_LOCAL_DAEMONS ctdb daemons..."

    for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	daemons_start_1 $i "$@"
    done
}

maybe_stop_ctdb ()
{
    if $TEST_CLEANUP ; then
	daemons_stop
    fi
}

_restart_ctdb_all ()
{
    daemons_stop
    daemons_start "$@"
}
