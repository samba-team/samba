# If we're not running on a real cluster then we need a local copy of
# ctdb (and other stuff) in $PATH and we will use local daemons.

# Use in-tree binaries if running against local daemons.
# Otherwise CTDB need to be installed on all nodes.
if [ -n "$ctdb_dir" -a -d "${ctdb_dir}/bin" ] ; then
	# ctdbd_wrapper is in config/ directory
	PATH="${ctdb_dir}/bin:${ctdb_dir}/config:${PATH}"
	hdir="${ctdb_dir}/bin"
	export CTDB_EVENTD="${hdir}/ctdb_eventd"
	export CTDB_EVENT_HELPER="${hdir}/ctdb_event"
	export CTDB_LOCK_HELPER="${hdir}/ctdb_lock_helper"
	export CTDB_RECOVERY_HELPER="${hdir}/ctdb_recovery_helper"
	export CTDB_TAKEOVER_HELPER="${hdir}/ctdb_takeover_helper"
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

# If the given IP is hosted then print 2 items: maskbits and iface
have_ip ()
{
	local addr="$1"
	local bits t

	case "$addr" in
	*:*) bits=128 ;;
	*)   bits=32  ;;
	esac

	t=$(ip addr show to "${addr}/${bits}")
	[ -n "$t" ]
}

node_dir ()
{
	local pnn="$1"

	echo "${TEST_VAR_DIR}/node.${pnn}"
}

node_conf ()
{
	local pnn="$1"

	local node_dir=$(node_dir "$pnn")
	echo "${node_dir}/ctdbd.conf"
}

node_pidfile ()
{
	local pnn="$1"

	local node_dir=$(node_dir "$pnn")
	echo "${node_dir}/ctdbd.pid"
}

node_socket ()
{
	local pnn="$1"

	local node_dir=$(node_dir "$pnn")
	echo "${node_dir}/ctdbd.socket"
}

setup_ctdb ()
{
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

    local have_all_ips=true
    local i
    for i in $(seq 1 $TEST_LOCAL_DAEMONS) ; do
	if [ -n "$CTDB_USE_IPV6" ]; then
	    local j=$(printf "%02x" $i)
	    local node_ip="fd00::5357:5f${j}"
	    if have_ip "$node_ip" ; then
		echo "$node_ip" >>"$CTDB_NODES"
	    else
		echo "ERROR: ${node_ip} not on an interface, please add it"
		have_all_ips=false
	    fi

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

    if ! $have_all_ips ; then
	    return 1
    fi

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	local node_dir=$(node_dir "$pnn")
	mkdir -p "$node_dir"

	local public_addresses_mine="${node_dir}/public_addresses"
	local public_addresses

	if  [ "$no_public_ips" = $pnn ] ; then
	    echo "Node $no_public_ips will have no public IPs."
	    public_addresses="/dev/null"
	else
	    cp "$public_addresses_all" "$public_addresses_mine"
	    public_addresses="$public_addresses_mine"
	fi

	local node_ip=$(sed -n -e "$(($pnn + 1))p" "$CTDB_NODES")

	local conf=$(node_conf "$pnn")
	local socket=$(node_socket "$pnn")

	local db_dir="${node_dir}/db"
	mkdir -p "${db_dir}/persistent"

	cat >"$conf" <<EOF
CTDB_RECOVERY_LOCK="${TEST_VAR_DIR}/rec.lock"
CTDB_NODES="$CTDB_NODES"
CTDB_NODE_ADDRESS="${node_ip}"
CTDB_EVENT_SCRIPT_DIR="${TEST_VAR_DIR}/events.d"
CTDB_LOGGING="file:${node_dir}/log.ctdb"
CTDB_DEBUGLEVEL=INFO
CTDB_DBDIR="${db_dir}"
CTDB_DBDIR_PERSISTENT="${db_dir}/persistent"
CTDB_DBDIR_STATE="${db_dir}/state"
CTDB_PUBLIC_ADDRESSES="${public_addresses}"
CTDB_SOCKET="${socket}"
CTDB_NOSETSCHED=yes
EOF

	# Append any configuration variables set in environment to
	# configuration file so they affect CTDB after each restart.
	config_from_environment >>"$conf"
    done
}

start_ctdb_1 ()
{
	local pnn="$1"
	local pidfile=$(node_pidfile "$pnn")
	local conf=$(node_conf "$pnn")

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

}

daemons_start ()
{
    echo "Starting $TEST_LOCAL_DAEMONS ctdb daemons..."

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	start_ctdb_1 "$pnn"
    done
}

stop_ctdb_1 ()
{
	local pnn="$1"
	local pidfile=$(node_pidfile "$pnn")
	local conf=$(node_conf "$pnn")

	CTDBD_CONF="$conf" \
	     ctdbd_wrapper "$pidfile" stop
}

daemons_stop ()
{
    echo "Stopping $TEST_LOCAL_DAEMONS ctdb daemons..."

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	stop_ctdb_1 "$pnn"
    done

    rm -rf "${TEST_VAR_DIR}/test.db"
}

restart_ctdb_1 ()
{
	stop_ctdb_1 "$1"
	start_ctdb_1 "$1"
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

# onnode will use CTDB_NODES_SOCKETS to help the ctdb tool connection
# to each daemon
export CTDB_NODES_SOCKETS=""
for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
    socket=$(node_socket "$i")
    CTDB_NODES_SOCKETS="${CTDB_NODES_SOCKETS}${CTDB_NODES_SOCKETS:+ }${socket}"
done
