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

export CTDB_NODES="${SIMPLE_TESTS_VAR_DIR}/nodes.txt"

if [ -n "$TEST_SOCKET_WRAPPER_SO_PATH" ] ; then
	export LD_PRELOAD="$TEST_SOCKET_WRAPPER_SO_PATH"
	export SOCKET_WRAPPER_DIR="${SIMPLE_TESTS_VAR_DIR}/sw"
	mkdir -p "$SOCKET_WRAPPER_DIR"
fi

# onnode will execute this, which fakes ssh against local daemons
export ONNODE_SSH="${TEST_SUBDIR}/scripts/ssh_local_daemons.sh"

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

	echo "${SIMPLE_TESTS_VAR_DIR}/node.${pnn}"
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

setup_nodes ()
{
	local have_all_ips=true
	local i
	for i in $(seq 1 $TEST_LOCAL_DAEMONS) ; do
		if [ -n "$CTDB_USE_IPV6" ]; then
			local j=$(printf "%02x" $i)
			local node_ip="fd00::5357:5f${j}"
			if have_ip "$node_ip" ; then
				echo "$node_ip"
			else
				cat >&2 <<EOF
ERROR: ${node_ip} not on an interface, please add it
EOF
				have_all_ips=false
			fi
		else
			local j=$((i + 10))
			echo "127.0.0.${j}"
		fi
	done

	# Fail if we don't have all of the IPv6 addresses assigned
	$have_all_ips
}

setup_public_addresses ()
{
	local pnn_no_ips="$1"

	local i
	for i in $(seq 1 $TEST_LOCAL_DAEMONS) ; do
		if  [ $((i - 1)) -eq $pnn_no_ips ] ; then
			continue
		fi

		# 2 public addresses on most nodes, just to make
		# things interesting
		local j=$((i + TEST_LOCAL_DAEMONS))
		if [ -n "$CTDB_USE_IPV6" ]; then
			printf "fc00:10::1:%x/64 lo\n" "$i"
			printf "fc00:10::1:%x/64 lo\n" "$j"
		else
			printf "192.168.234.%x/24 lo\n" "$i"
			printf "192.168.234.%x/24 lo\n" "$j"
		fi
	done
}

setup_ctdb ()
{
	setup_nodes >"$CTDB_NODES" || return 1

	# If there are (strictly) greater than 2 nodes then we'll
	# randomly choose a node to have no public addresses
	local pnn_no_ips=-1
	if [ $TEST_LOCAL_DAEMONS -gt 2 ] ; then
		pnn_no_ips=$((RANDOM % TEST_LOCAL_DAEMONS))
	fi

	local public_addresses_all="${SIMPLE_TESTS_VAR_DIR}/public_addresses"
	setup_public_addresses $pnn_no_ips >"$public_addresses_all"

	local pnn
	for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
		local node_dir=$(node_dir "$pnn")

		setup_ctdb_base "$SIMPLE_TESTS_VAR_DIR" "node.${pnn}" \
				functions

		if [ "$node_dir" != "$CTDB_BASE" ] ; then
			die "Inconsistent CTDB_BASE"
		fi

		local public_addresses="${node_dir}/public_addresses"

		if  [ $pnn_no_ips -eq $pnn ] ; then
			echo "Node ${pnn} will have no public IPs."
			: >"$public_addresses"
		else
			cp "$public_addresses_all" "$public_addresses"
		fi

		local node_ip=$(sed -n -e "$(($pnn + 1))p" "$CTDB_NODES")

		local conf=$(node_conf "$pnn")
		local socket=$(node_socket "$pnn")

		local db_dir="${node_dir}/db"
		mkdir -p "${db_dir}/persistent"

		cat >"$conf" <<EOF
CTDB_RECOVERY_LOCK="${SIMPLE_TESTS_VAR_DIR}/rec.lock"
CTDB_NODES="$CTDB_NODES"
CTDB_NODE_ADDRESS="${node_ip}"
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
	local node_dir=$(node_dir "$pnn")
	local pidfile=$(node_pidfile "$pnn")
	local conf=$(node_conf "$pnn")

	# If there is any CTDB configuration in the environment then
	# append it to the regular configuration in a temporary
	# configuration file and use it just this once.
	local tmp_conf=""
	local env_conf=$(config_from_environment)
	if [ -n "$env_conf" ] ; then
		tmp_conf=$(mktemp --tmpdir="$SIMPLE_TESTS_VAR_DIR")
		cat "$conf" >"$tmp_conf"
		echo "$env_conf" >>"$tmp_conf"
		conf="$tmp_conf"
	fi

	CTDBD="${VALGRIND} ctdbd --sloppy-start --nopublicipcheck" \
	     CTDB_BASE="$node_dir" \
	     CTDBD_CONF="$conf" \
	     CTDB_PIDFILE="$pidfile" \
	     ctdbd_wrapper start

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
	local node_dir=$(node_dir "$pnn")
	local pidfile=$(node_pidfile "$pnn")
	local conf=$(node_conf "$pnn")

	CTDB_BASE="$node_dir" \
		 CTDBD_CONF="$conf" \
		 CTDB_PIDFILE="$pidfile" \
		 ctdbd_wrapper stop
}

daemons_stop ()
{
    echo "Stopping $TEST_LOCAL_DAEMONS ctdb daemons..."

    local pnn
    for pnn in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	stop_ctdb_1 "$pnn"
    done

    rm -rf "${SIMPLE_TESTS_VAR_DIR}/test.db"
}

restart_ctdb_1 ()
{
	stop_ctdb_1 "$1"
	start_ctdb_1 "$1"
}

maybe_stop_ctdb ()
{
    daemons_stop
}

ctdb_stop_all ()
{
	daemons_stop
}

_ctdb_start_all ()
{
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

# onnode will use CTDB_BASES to help the ctdb tool connection to each
# daemon
export CTDB_BASES=""
for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	node_dir=$(node_dir "$i")
	CTDB_BASES="${CTDB_BASES}${CTDB_BASES:+ }${node_dir}"
done

# Need a default CTDB_BASE for onnode (to find the functions file).
# Any node will do, so pick the 1st...
export CTDB_BASE="${CTDB_BASES%% *}"
