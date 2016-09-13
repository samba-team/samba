# If we're not running on a real cluster then we need a local copy of
# ctdb (and other stuff) in $PATH and we will use local daemons.

export CTDB_NODES_SOCKETS=""
for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
    CTDB_NODES_SOCKETS="${CTDB_NODES_SOCKETS}${CTDB_NODES_SOCKETS:+ }${TEST_VAR_DIR}/sock.${i}"
done

# Use in-tree binaries if running against local daemons.
# Otherwise CTDB need to be installed on all nodes.
if [ -n "$ctdb_dir" -a -d "${ctdb_dir}/bin" ] ; then
	# ctdbd_wrapper is in config/ directory
	PATH="${ctdb_dir}/bin:${ctdb_dir}/config:${PATH}"
	hdir="${ctdb_dir}/bin"
	export CTDB_LOCK_HELPER="${hdir}/ctdb_lock_helper"
	export CTDB_EVENT_HELPER="${hdir}/ctdb_event_helper"
	export CTDB_RECOVERY_HELPER="${hdir}/ctdb_recovery_helper"
	export CTDB_CLUSTER_MUTEX_HELPER="${hdir}/ctdb_mutex_fcntl_helper"
fi

export CTDB_NODES="${TEST_VAR_DIR}/nodes.txt"

#######################################

config_from_environment ()
{
	# Override from the environment.  This would be easier if env was
	# guaranteed to quote its output so it could be reused.
	env |
	grep '^CTDB_' |
	sed -e 's@=\([^"]\)@="\1@' -e 's@[^"]$@&"@' -e 's@="$@&"@'
}

setup_ctdb ()
{
    mkdir -p "${TEST_VAR_DIR}/test.db/persistent"

    local public_addresses_all="${TEST_VAR_DIR}/public_addresses_all"
    rm -f $CTDB_NODES $public_addresses_all

    # If there are (strictly) greater than 2 nodes then we'll randomly
    # choose a node to have no public addresses.
    local no_public_ips=-1
    [ $TEST_LOCAL_DAEMONS -gt 2 ] && no_public_ips=$(($RANDOM % $TEST_LOCAL_DAEMONS))

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

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	local public_addresses_mine="${TEST_VAR_DIR}/public_addresses.${pnn}"
	local public_addresses

	if  [ "$no_public_ips" = $pnn ] ; then
	    echo "Node $no_public_ips will have no public IPs."
	    public_addresses="/dev/null"
	else
	    cp "$public_addresses_all" "$public_addresses_mine"
	    public_addresses="$public_addresses_mine"
	fi

	local node_ip=$(sed -n -e "$(($pnn + 1))p" "$CTDB_NODES")

	local pidfile="${TEST_VAR_DIR}/ctdbd.${pnn}.pid"
	local conf="${TEST_VAR_DIR}/ctdbd.${pnn}.conf"
	cat >"$conf" <<EOF
CTDB_RECOVERY_LOCK="${TEST_VAR_DIR}/rec.lock"
CTDB_NODES="$CTDB_NODES"
CTDB_NODE_ADDRESS="${node_ip}"
CTDB_EVENT_SCRIPT_DIR="${TEST_VAR_DIR}/events.d"
CTDB_LOGGING="file:${TEST_VAR_DIR}/daemon.${pnn}.log"
CTDB_DEBUGLEVEL=3
CTDB_DBDIR="${TEST_VAR_DIR}/test.db"
CTDB_DBDIR_PERSISTENT="${TEST_VAR_DIR}/test.db/persistent"
CTDB_DBDIR_STATE="${TEST_VAR_DIR}/test.db/state"
CTDB_PUBLIC_ADDRESSES="${public_addresses}"
CTDB_SOCKET="${TEST_VAR_DIR}/sock.$pnn"
CTDB_NOSETSCHED=yes
EOF

	# Append any configuration variables set in environment to
	# configuration file so they affect CTDB after each restart.
	config_from_environment >>"$conf"
    done
}

daemons_start ()
{
    echo "Starting $TEST_LOCAL_DAEMONS ctdb daemons..."

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	local pidfile="${TEST_VAR_DIR}/ctdbd.${pnn}.pid"
	local conf="${TEST_VAR_DIR}/ctdbd.${pnn}.conf"

	# If there is any CTDB configuration in the environment then
	# append it to the regular configuration in a temporary
	# configuration file and use it just this once.
	local tmp_conf=""
	local env_conf=$(config_from_environment)
	if [ -n "$env_conf" ] ; then
		tmp_conf=$(mktemp --tmpdir="$TEST_VAR_DIR")
		cat "$conf" >"$tmp_conf"
		echo "$env_conf" >>"$tmp_conf"
		conf="$tmp_conf"
	fi

	CTDBD="${VALGRIND} ctdbd --sloppy-start --nopublicipcheck" \
	     CTDBD_CONF="$conf" \
	     ctdbd_wrapper "$pidfile" start

	if [ -n "$tmp_conf" ] ; then
		rm -f "$tmp_conf"
	fi
    done
}

daemons_stop ()
{
    echo "Stopping $TEST_LOCAL_DAEMONS ctdb daemons..."

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	local pidfile="${TEST_VAR_DIR}/ctdbd.${pnn}.pid"
	local conf="${TEST_VAR_DIR}/ctdbd.${pnn}.conf"

	CTDBD_CONF="$conf" \
	     ctdbd_wrapper "$pidfile" stop
    done

    rm -rf "${TEST_VAR_DIR}/test.db"
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
    daemons_start
}

ps_ctdbd ()
{
	# If this fails to find processes then the tests fails, so
	# look at full command-line so this will work with valgrind.
	# Note that the output could be generated with pgrep's -a
	# option but it doesn't exist in older versions.
	ps -p $(pgrep -f '\<ctdbd\>' | xargs | sed -e 's| |,|g') -o args ww
	echo
}
