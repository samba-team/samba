#!/bin/sh

set -u

export CTDB_TEST_MODE="yes"

# Following 2 lines may be modified by installation script
CTDB_TESTS_ARE_INSTALLED=false
CTDB_TEST_DIR=$(dirname "$0")
export CTDB_TESTS_ARE_INSTALLED CTDB_TEST_DIR

export TEST_SCRIPTS_DIR="${CTDB_TEST_DIR}/scripts"

. "${TEST_SCRIPTS_DIR}/common.sh"

if ! $CTDB_TESTS_ARE_INSTALLED ; then
	hdir="$CTDB_SCRIPTS_HELPER_BINDIR"
	export CTDB_EVENTD="${hdir}/ctdb-eventd"
	export CTDB_EVENT_HELPER="${hdir}/ctdb-event"
	export CTDB_LOCK_HELPER="${hdir}/ctdb_lock_helper"
	export CTDB_RECOVERY_HELPER="${hdir}/ctdb_recovery_helper"
	export CTDB_TAKEOVER_HELPER="${hdir}/ctdb_takeover_helper"
	export CTDB_CLUSTER_MUTEX_HELPER="${hdir}/ctdb_mutex_fcntl_helper"
fi

########################################

# If the given IP is hosted then print 2 items: maskbits and iface
have_ip ()
{
	_addr="$1"

	case "$_addr" in
	*:*) _bits=128 ;;
	*)   _bits=32  ;;
	esac

	_t=$(ip addr show to "${_addr}/${_bits}")
	[ -n "$_t" ]
}

setup_nodes ()
{
	_num_nodes="$1"
	_use_ipv6="$2"

	_have_all_ips=true
	for _i in $(seq 0 $((_num_nodes - 1)) ) ; do
		if $_use_ipv6 ; then
			_j=$(printf "%04x" $((0x5f00 + 1 + _i)) )
			_node_ip="fd00::5357:${_j}"
			if have_ip "$_node_ip" ; then
				echo "$_node_ip"
			else
				cat >&2 <<EOF
ERROR: ${_node_ip} not on an interface, please add it
EOF
				_have_all_ips=false
			fi
		else
			_c=$(( _i / 100 ))
			_d=$(( 1 + (_i % 100) ))
			echo "127.0.${_c}.${_d}"
		fi
	done

	# Fail if we don't have all of the IPv6 addresses assigned
	$_have_all_ips
}

setup_public_addresses ()
{
	_num_nodes="$1"
	_node_no_ips="$2"
	_use_ipv6="$3"

	for _i in $(seq 0 $((_num_nodes - 1)) ) ; do
		if  [ "$_i" -eq "$_node_no_ips" ] ; then
			continue
		fi

		# 2 public addresses on most nodes, just to make
		# things interesting
		if $_use_ipv6 ; then
			printf 'fc00:10::1:%x/64 lo\n' $((1 + _i))
			printf 'fc00:10::2:%x/64 lo\n' $((1 + _i))
		else
			_c1=$(( 100 + (_i / 100) ))
			_c2=$(( 200 + (_i / 100) ))
			_d=$(( 1 + (_i % 100) ))
			printf '192.168.%d.%d/24 lo\n' "$_c1" "$_d"
			printf '192.168.%d.%d/24 lo\n' "$_c2" "$_d"
		fi
	done
}

setup_socket_wrapper ()
{
	_socket_wrapper_so="$1"

	_so="${directory}/libsocket-wrapper.so"
	if [ ! -f "$_socket_wrapper_so" ] ; then
		die "$0 setup: Unable to find ${_socket_wrapper_so}"
	fi

	# Find absolute path if only relative is given
	case "$_socket_wrapper_so" in
	/*) : ;;
	*) _socket_wrapper_so="${PWD}/${_socket_wrapper_so}" ;;
	esac

	rm -f "$_so"
	ln -s "$_socket_wrapper_so" "$_so"

	_d="${directory}/sw"
	rm -rf "$_d"
	mkdir -p "$_d"
}

local_daemons_setup_usage ()
{
	cat >&2 <<EOF
$0 <directory> setup [ <options>... ]

Options:
  -F            Disable failover (default: failover enabled)
  -N <file>     Nodes file (default: automatically generated)
  -n <num>      Number of nodes (default: 3)
  -P <file>     Public addresses file (default: automatically generated)
  -R            Use a command for the recovery lock (default: use a file)
  -r <time>     Like -R and set recheck interval to <time> (default: use a file)
  -S <library>  Socket wrapper shared library to preload (default: none)
  -6            Generate IPv6 IPs for nodes, public addresses (default: IPv4)
EOF

	exit 1
}

local_daemons_setup ()
{
	_disable_failover=false
	_nodes_file=""
	_num_nodes=3
	_public_addresses_file=""
	_recovery_lock_use_command=false
	_recovery_lock_recheck_interval=""
	_socket_wrapper=""
	_use_ipv6=false

	set -e

	while getopts "FN:n:P:Rr:S:6h?" _opt ; do
		case "$_opt" in
		F) _disable_failover=true ;;
		N) _nodes_file="$OPTARG" ;;
		n) _num_nodes="$OPTARG" ;;
		P) _public_addresses_file="$OPTARG" ;;
		R) _recovery_lock_use_command=true ;;
		r) _recovery_lock_use_command=true
		   _recovery_lock_recheck_interval="$OPTARG"
		   ;;
		S) _socket_wrapper="$OPTARG" ;;
		6) _use_ipv6=true ;;
		\?|h) local_daemons_setup_usage ;;
		esac
	done
	shift $((OPTIND - 1))

	mkdir -p "$directory"

	_nodes_all="${directory}/nodes"
	if [ -n "$_nodes_file" ] ; then
		cp "$_nodes_file" "$_nodes_all"
	else
		setup_nodes "$_num_nodes" $_use_ipv6 >"$_nodes_all"
	fi

	# If there are (strictly) greater than 2 nodes then we'll
	# "randomly" choose a node to have no public addresses
	_node_no_ips=-1
	if [ "$_num_nodes" -gt 2 ] ; then
		_node_no_ips=$(($$ % _num_nodes))
	fi

	_public_addresses_all="${directory}/public_addresses"
	if [ -n "$_public_addresses_file" ] ; then
		cp "$_public_addresses_file" "$_public_addresses_all"
	else
		setup_public_addresses "$_num_nodes" \
				       $_node_no_ips \
				       $_use_ipv6 >"$_public_addresses_all"
	fi

	_recovery_lock_dir="${directory}/shared/.ctdb"
	mkdir -p "$_recovery_lock_dir"
	_recovery_lock="${_recovery_lock_dir}/rec.lock"
	if $_recovery_lock_use_command ; then
		_helper="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb_mutex_fcntl_helper"
		_t="! ${_helper} ${_recovery_lock}"
		if [ -n "$_recovery_lock_recheck_interval" ] ; then
			_t="${_t} ${_recovery_lock_recheck_interval}"
		fi
		_recovery_lock="$_t"
	fi

	if [ -n "$_socket_wrapper" ] ; then
		setup_socket_wrapper "$_socket_wrapper"
	fi

	for _n in $(seq 0 $((_num_nodes - 1))) ; do
		# CTDB_TEST_SUITE_DIR needs to be correctly set so
		# setup_ctdb_base() finds the etc-ctdb/ subdirectory
		# and the test event script is correctly installed
		# shellcheck disable=SC2034
		CTDB_TEST_SUITE_DIR="$CTDB_TEST_DIR" \
			   setup_ctdb_base "$directory" "node.${_n}" \
				functions notify.sh debug-hung-script.sh

		cp "$_nodes_all" "${CTDB_BASE}/nodes"

		_public_addresses="${CTDB_BASE}/public_addresses"

		if  [ -z "$_public_addresses_file" ] && \
			    [ $_node_no_ips -eq "$_n" ] ; then
			echo "Node ${_n} will have no public IPs."
			: >"$_public_addresses"
		else
			cp "$_public_addresses_all" "$_public_addresses"
		fi

		_node_ip=$(sed -n -e "$((_n + 1))p" "$_nodes_all")

		_db_dir="${CTDB_BASE}/db"
		for _d in "volatile" "persistent" "state" ; do
			mkdir -p "${_db_dir}/${_d}"
		done

		cat >"${CTDB_BASE}/ctdb.conf" <<EOF
[logging]
	location = file:${CTDB_BASE}/log.ctdb
	log level = INFO

[cluster]
	recovery lock = ${_recovery_lock}
	node address = ${_node_ip}

[database]
	volatile database directory = ${_db_dir}/volatile
	persistent database directory = ${_db_dir}/persistent
	state database directory = ${_db_dir}/state

[failover]
	disabled = ${_disable_failover}

[event]
	debug script = debug-hung-script.sh
EOF
	done
}

local_daemons_ssh_usage ()
{
	cat >&2 <<EOF
usage: $0 <directory> ssh [ -n ] <ip> <command>
EOF

	exit 1
}

local_daemons_ssh ()
{
	if [ $# -lt 2 ] ; then
		local_daemons_ssh_usage
	fi

	# Only try to respect ssh -n option, others can't be used so discard them
	_close_stdin=false
	while getopts "nh?" _opt ; do
		case "$_opt" in
		n) _close_stdin=true ;;
		\?|h) local_daemons_ssh_usage ;;
		*) : ;;
		esac
	done
	shift $((OPTIND - 1))

	if [ $# -lt 2 ] ; then
		local_daemons_ssh_usage
	fi

	_nodes="${directory}/nodes"

	# IP adress of node. onnode can pass hostnames but not in these tests
	_ip="$1" ; shift
	# "$*" is command


	# Determine the correct CTDB base directory
	_num=$(awk -v ip="$_ip" '$1 == ip { print NR }' "$_nodes")
	_node=$((_num - 1))
	export CTDB_BASE="${directory}/node.${_node}"

	if [ ! -d "$CTDB_BASE" ] ; then
		die "$0 ssh: Unable to find base for node ${_ip}"
	fi

	if $_close_stdin ; then
		exec sh -c "$*" </dev/null
	else
		exec sh -c "$*"
	fi
}

onnode_common ()
{
	# onnode will execute this, which fakes ssh against local daemons
	export ONNODE_SSH="${0} ${directory} ssh"

	# onnode just needs the nodes file, so use the common one
	export CTDB_BASE="$directory"
}

local_daemons_generic_usage ()
{
	cat >&2 <<EOF
usage: $0 <directory> ${1} <nodes>

<nodes> can be  "all", a node number or any specification supported by onnode
EOF

	exit 1
}

local_daemons_start_socket_wrapper ()
{
	_so="${directory}/libsocket-wrapper.so"
	_d="${directory}/sw"

	if [ -d "$_d" ] && [ -f "$_so" ] ; then
		export SOCKET_WRAPPER_DIR="$_d"
		export LD_PRELOAD="$_so"
	fi
}

local_daemons_start ()
{
	if [ $# -ne 1 ] || [ "$1" = "-h" ] ; then
		local_daemons_generic_usage "start"
	fi

	local_daemons_start_socket_wrapper

	_nodes="$1"

	onnode_common

	onnode -i "$_nodes" "${VALGRIND:-} ctdbd"
}

local_daemons_stop ()
{
	if [ $# -ne 1 ] || [ "$1" = "-h" ] ; then
		local_daemons_generic_usage "stop"
	fi

	_nodes="$1"

	onnode_common

	onnode -p "$_nodes" \
		"if [ -e \"\${CTDB_BASE}/run/ctdbd.pid\" ] ; then \
			${CTDB:-${VALGRIND:-} ctdb} shutdown ; \
		 fi"
}

local_daemons_onnode_usage ()
{
	cat >&2 <<EOF
usage: $0 <directory> onnode <nodes> <command>...

<nodes> can be  "all", a node number or any specification supported by onnode
EOF

	exit 1
}

local_daemons_onnode ()
{
	if [ $# -lt 2 ] || [ "$1" = "-h" ] ; then
		local_daemons_onnode_usage
	fi

	_nodes="$1"
	shift

	onnode_common

	onnode "$_nodes" "$@"
}

local_daemons_print_socket ()
{
	if [ $# -ne 1 ] || [ "$1" = "-h" ] ; then
		local_daemons_generic_usage "print-socket"
	fi

	_nodes="$1"
	shift

	onnode_common

	_path="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb-path"
	onnode -q "$_nodes" "${VALGRIND:-} ${_path} socket ctdbd"
}

local_daemons_print_log ()
{
	if [ $# -ne 1 ] || [ "$1" = "-h" ] ; then
		local_daemons_generic_usage "print-log"
	fi

	_nodes="$1"
	shift

	onnode_common

	# shellcheck disable=SC2016
	# $CTDB_BASE must only be expanded under onnode, not in top-level shell
	onnode -q "$_nodes" 'echo ${CTDB_BASE}/log.ctdb' |
	while IFS='' read -r _l ; do
		_dir=$(dirname "$_l")
		_node=$(basename "$_dir")
		# Add fake hostname after date and time, which are the
		# first 2 words on each line
		sed -e "s|^\\([^ ][^ ]* [^ ][^ ]*\\)|\\1 ${_node}|" "$_l"
	done |
	sort

}

local_daemons_tail_log ()
{
	if [ $# -ne 1 ] || [ "$1" = "-h" ] ; then
		local_daemons_generic_usage "tail-log"
	fi

	_nodes="$1"
	shift

	onnode_common

	# shellcheck disable=SC2016,SC2046
	# $CTDB_BASE must only be expanded under onnode, not in top-level shell
	# Intentional word splitting to separate log filenames
	tail -f $(onnode -q "$_nodes" 'echo ${CTDB_BASE}/log.ctdb')
}

usage ()
{
	cat <<EOF
usage: $0 <directory> <command> [ <options>... ]

Commands:
  setup          Set up daemon configuration according to given options
  start          Start specified daemon(s)
  stop           Stop specified daemon(s)
  onnode         Run a command in the environment of specified daemon(s)
  print-socket   Print the Unix domain socket used by specified daemon(s)
  print-log      Print logs for specified daemon(s) to stdout
  tail-log       Follow logs for specified daemon(s) to stdout

All commands use <directory> for daemon configuration

Run command with -h option to see per-command usage
EOF

	exit 1
}

if [ $# -lt 2 ] ; then
	usage
fi

directory="$1"
command="$2"
shift 2

case "$command" in
setup) local_daemons_setup "$@" ;;
ssh) local_daemons_ssh "$@" ;; # Internal, not shown by usage()
start) local_daemons_start "$@" ;;
stop) local_daemons_stop "$@" ;;
onnode) local_daemons_onnode "$@" ;;
print-socket) local_daemons_print_socket "$@" ;;
print-log) local_daemons_print_log "$@" ;;
tail-log) local_daemons_tail_log "$@" ;;
*) usage ;;
esac
