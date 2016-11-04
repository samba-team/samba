# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Augment PATH with relevant stubs/ directories.  We do this by actually
# setting PATH, and also by setting $EVENTSCRIPTS_PATH and then
# prepending that to $PATH in rc.local to avoid the PATH reset in
# functions.

EVENTSCRIPTS_PATH=""

if [ -d "${TEST_SUBDIR}/stubs" ] ; then
    EVENTSCRIPTS_PATH="${TEST_SUBDIR}/stubs"
    case "$EVENTSCRIPTS_PATH" in
	/*) : ;;
	*) EVENTSCRIPTS_PATH="${PWD}/${EVENTSCRIPTS_PATH}" ;;
    esac
    export CTDB_HELPER_BINDIR="$EVENTSCRIPTS_PATH"
fi

export EVENTSCRIPTS_PATH

PATH="${EVENTSCRIPTS_PATH}:${PATH}"

export CTDB="ctdb"

export EVENTSCRIPTS_TESTS_VAR_DIR="${TEST_VAR_DIR}/unit_eventscripts"
if [ -d "$EVENTSCRIPTS_TESTS_VAR_DIR" -a \
    "$EVENTSCRIPTS_TESTS_VAR_DIR" != "/unit_eventscripts" ] ; then
    rm -r "$EVENTSCRIPTS_TESTS_VAR_DIR"
fi
mkdir -p "$EVENTSCRIPTS_TESTS_VAR_DIR"
export CTDB_SCRIPT_VARDIR="$EVENTSCRIPTS_TESTS_VAR_DIR/script-state"

export CTDB_LOGGING="file:${EVENTSCRIPTS_TESTS_VAR_DIR}/log.ctdb"
touch "${CTDB_LOGGING#file:}" || \
    die "Unable to setup logging for \"$CTDB_LOGGING\""

if [ -d "${TEST_SUBDIR}/etc" ] ; then
    cp -a "${TEST_SUBDIR}/etc" "$EVENTSCRIPTS_TESTS_VAR_DIR"
    export CTDB_SYS_ETCDIR="${EVENTSCRIPTS_TESTS_VAR_DIR}/etc"
else
    die "Unable to setup \$CTDB_SYS_ETCDIR"
fi

if [ -d "${TEST_SUBDIR}/etc-ctdb" ] ; then
    cp -prL "${TEST_SUBDIR}/etc-ctdb" "$EVENTSCRIPTS_TESTS_VAR_DIR"
    export CTDB_BASE="${EVENTSCRIPTS_TESTS_VAR_DIR}/etc-ctdb"
else
    die "Unable to set \$CTDB_BASE"
fi
export CTDB_BASE

if [ ! -d "${CTDB_BASE}/events.d" ] ; then
    cat <<EOF
ERROR: Directory ${CTDB_BASE}/events.d does not exist.

That means that no eventscripts can be tested.

One possible explanation:

  You have CTDB installed via RPMs (or similar), so the regular
  CTDB_BASE directory is in /etc/ctdb/

  BUT

  You have done a regular "configure" and "make install" so the tests
  are installed under /usr/local/.

If so, one possible hack to fix this is to create a symlink:

  ln -s /etc/ctdb /usr/local/etc/ctdb

This is nasty but it works...  :-)
EOF
    exit 1
fi

######################################################################

if "$TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

######################################################################

# General setup fakery

setup_generic ()
{
    debug "Setting up shares (3 existing shares)"
    # Create 3 fake shares/exports.
    export FAKE_SHARES=""
    for i in $(seq 1 3) ; do
	_s="${EVENTSCRIPTS_TESTS_VAR_DIR}/shares/${i}_existing"
	mkdir -p "$_s"
	FAKE_SHARES="${FAKE_SHARES}${FAKE_SHARES:+ }${_s}"
    done

    export FAKE_PROC_NET_BONDING="$EVENTSCRIPTS_TESTS_VAR_DIR/proc-net-bonding"
    mkdir -p "$FAKE_PROC_NET_BONDING"
    rm -f "$FAKE_PROC_NET_BONDING"/*

    export FAKE_ETHTOOL_LINK_DOWN="$EVENTSCRIPTS_TESTS_VAR_DIR/ethtool-link-down"
    mkdir -p "$FAKE_ETHTOOL_LINK_DOWN"
    rm -f "$FAKE_ETHTOOL_LINK_DOWN"/*

    # This can only have 2 levels.  We don't want to resort to usings
    # something dangerous like "rm -r" setup time.
    export FAKE_IP_STATE="$EVENTSCRIPTS_TESTS_VAR_DIR/fake-ip-state"
    mkdir -p "$FAKE_IP_STATE"
    rm -f "$FAKE_IP_STATE"/*/*
    rm -f "$FAKE_IP_STATE"/* 2>/dev/null || true
    rmdir "$FAKE_IP_STATE"/* 2>/dev/null || true


    export CTDB_DBDIR="${EVENTSCRIPTS_TESTS_VAR_DIR}/db"
    export CTDB_DBDIR_PERSISTENT="${CTDB_DBDIR}/persistent"
    export CTDB_DBDIR_STATE="${CTDB_DBDIR}/state"
    mkdir -p "$CTDB_DBDIR_PERSISTENT"
    mkdir -p "$CTDB_DBDIR_STATE"

    export FAKE_TDBTOOL_SUPPORTS_CHECK="yes"
    export FAKE_TDB_IS_OK
    export FAKE_DATE_OUTPUT

    export FAKE_NETSTAT_TCP_ESTABLISHED FAKE_TCP_LISTEN FAKE_NETSTAT_UNIX_LISTEN
    export FAKE_NETSTAT_TCP_ESTABLISHED_FILE=$(mktemp --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR")
}

tcp_port_down ()
{
    for _i ; do
	debug "Marking TCP port \"${_i}\" as not listening"
	FAKE_TCP_LISTEN=$(echo "$FAKE_TCP_LISTEN" | sed -r -e "s@[[:space:]]*[\.0-9]+:${_i}@@g")
    done
}

shares_missing ()
{
    _fmt="$1" ; shift

    # Replace some shares with non-existent ones.
    _t=""
    _n=1
    _nl="
"
    export MISSING_SHARES_TEXT=""
    for _i in $FAKE_SHARES ; do
	if [ $_n = "$1" ] ; then
	    shift
	    _i="${_i%_existing}_missing"
	    debug "Replacing share $_n with missing share \"$_i\""
	    rmdir "$_i" 2>/dev/null || true
	    MISSING_SHARES_TEXT="${MISSING_SHARES_TEXT}${MISSING_SHARES_TEXT:+${_nl}}"$(printf "$_fmt" "${_i}")
	fi
	_t="${_t}${_t:+ }${_i}"
	_n=$(($_n + 1))
    done
    FAKE_SHARES="$_t"
}

# Setup some fake /proc/net/bonding files with just enough info for
# the eventscripts.

# arg1 is interface name, arg2 is currently active slave (use "None"
# if none), arg3 is MII status ("up" or "down").
setup_bond ()
{
    _iface="$1"
    _slave="${2:-${_iface}_sl_0}"
    _mii_s="${3:-up}"
    _mii_subs="${4:-${_mii_s:-up}}"
    echo "Setting $_iface to be a bond with active slave $_slave and MII status $_mii_s"
    cat >"${FAKE_PROC_NET_BONDING}/$_iface" <<EOF
Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Currently Active Slave: $_slave
# Status of the bond
MII Status: $_mii_s
# Status of 1st pretend adapter
MII Status: $_mii_subs
# Status of 2nd pretend adapter
MII Status: $_mii_subs
EOF
}

ethtool_interfaces_down ()
{
    for _i ; do
	echo "Marking interface $_i DOWN for ethtool"
	touch "${FAKE_ETHTOOL_LINK_DOWN}/${_i}"
    done
}

ethtool_interfaces_up ()
{
    for _i ; do
	echo "Marking interface $_i UP for ethtool"
	rm -f "${FAKE_ETHTOOL_LINK_DOWN}/${_i}"
    done
}

dump_routes ()
{
    echo "# ip rule show"
    ip rule show

    ip rule show |
    while read _p _x _i _x _t ; do
	# Remove trailing colon after priority/preference.
	_p="${_p%:}"
	# Only remove rules that match our priority/preference.
	[ "$CTDB_PER_IP_ROUTING_RULE_PREF" = "$_p" ] || continue

	echo "# ip route show table $_t"
	ip route show table "$_t"
    done
}

# Copied from 13.per_ip_routing for now... so this is lazy testing  :-(
ipv4_host_addr_to_net ()
{
    _host="$1"
    _maskbits="$2"

    # Convert the host address to an unsigned long by splitting out
    # the octets and doing the math.
    _host_ul=0
    for _o in $(export IFS="." ; echo $_host) ; do
	_host_ul=$(( ($_host_ul << 8) + $_o)) # work around Emacs color bug
    done

    # Calculate the mask and apply it.
    _mask_ul=$(( 0xffffffff << (32 - $_maskbits) ))
    _net_ul=$(( $_host_ul & $_mask_ul ))

    # Now convert to a network address one byte at a time.
    _net=""
    for _o in $(seq 1 4) ; do
	_net="$(($_net_ul & 255))${_net:+.}${_net}"
	_net_ul=$(($_net_ul >> 8))
    done

    echo "${_net}/${_maskbits}"
}

######################################################################

# CTDB fakery

# Evaluate an expression that probably calls functions or uses
# variables from the CTDB functions file.  This is used for test
# initialisation.
eventscript_call ()
{
    (
	. "$CTDB_BASE/functions"
	"$@"
    )
}

# For now this creates the same public addresses each time.  However,
# it could be made more flexible.
setup_public_addresses ()
{
    if [ -f "$CTDB_PUBLIC_ADDRESSES" -a \
	    "${CTDB_PUBLIC_ADDRESSES%/*}" = "$EVENTSCRIPTS_TESTS_VAR_DIR" ] ; then
	rm "$CTDB_PUBLIC_ADDRESSES"
    fi

    export CTDB_PUBLIC_ADDRESSES=$(mktemp \
				       --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR" \
				       "public-addresses-XXXXXXXX")

    echo "Setting up CTDB_PUBLIC_ADDRESSES=${CTDB_PUBLIC_ADDRESSES}"
    cat >"$CTDB_PUBLIC_ADDRESSES" <<EOF
10.0.0.1/24 dev123
10.0.0.2/24 dev123
10.0.0.3/24 dev123
10.0.0.4/24 dev123
10.0.0.5/24 dev123
10.0.0.6/24 dev123
10.0.1.1/24 dev456
10.0.1.2/24 dev456
10.0.1.3/24 dev456
EOF
}

# Need to cope with ctdb_get_pnn().  If a test changes PNN then it
# needs to be using a different state directory, otherwise the wrong
# PNN can already be cached in the state directory.
ctdb_set_pnn ()
{
    export FAKE_CTDB_PNN="$1"
    echo "Setting up PNN ${FAKE_CTDB_PNN}"

    export CTDB_SCRIPT_VARDIR="$EVENTSCRIPTS_TESTS_VAR_DIR/script-state/${FAKE_CTDB_PNN}"
    mkdir -p "$CTDB_SCRIPT_VARDIR"
}

setup_ctdb ()
{
    setup_generic

    export FAKE_CTDB_NUMNODES="${1:-3}"
    echo "Setting up CTDB with ${FAKE_CTDB_NUMNODES} fake nodes"

    ctdb_set_pnn "${2:-0}"

    setup_public_addresses

    export FAKE_CTDB_STATE="$EVENTSCRIPTS_TESTS_VAR_DIR/fake-ctdb"

    export FAKE_CTDB_EXTRA_CONFIG="$EVENTSCRIPTS_TESTS_VAR_DIR/fake-config.sh"
    rm -f "$FAKE_CTDB_EXTRA_CONFIG"

    export FAKE_CTDB_IFACES_DOWN="$FAKE_CTDB_STATE/ifaces-down"
    mkdir -p "$FAKE_CTDB_IFACES_DOWN"
    rm -f "$FAKE_CTDB_IFACES_DOWN"/*

    export FAKE_CTDB_SCRIPTSTATUS="$FAKE_CTDB_STATE/scriptstatus"
    mkdir -p "$FAKE_CTDB_SCRIPTSTATUS"
    rm -f "$FAKE_CTDB_SCRIPTSTATUS"/*

    export CTDB_PARTIALLY_ONLINE_INTERFACES

    export FAKE_CTDB_TUNABLES_OK="MonitorInterval TDBMutexEnabled DatabaseHashSize"
    export FAKE_CTDB_TUNABLES_OBSOLETE="EventScriptUnhealthyOnTimeout"
}

setup_config ()
{
    cat >"$FAKE_CTDB_EXTRA_CONFIG"
}

validate_percentage ()
{
    case "$1" in
	[0-9]|[0-9][0-9]|100) return 0 ;;
	*) echo "WARNING: ${1} is an invalid percentage${2:+\" in }${2}${2:+\"}"
	   return 1
    esac
}

setup_memcheck ()
{
    _mem_usage="${1:-10}" # Default is 10%
    _swap_usage="${2:-0}" # Default is  0%

    setup_ctdb

    _swap_total=5857276
    _swap_free=$(( (100 - $_swap_usage) * $_swap_total / 100 ))

    _mem_total=3940712
    _mem_free=225268
    _mem_buffers=146120
    _mem_cached=$(( $_mem_total * (100 - $_mem_usage) / 100 - $_mem_free - $_mem_buffers ))

    export FAKE_PROC_MEMINFO="\
MemTotal:        ${_mem_total} kB
MemFree:          ${_mem_free} kB
Buffers:          ${_mem_buffers} kB
Cached:          ${_mem_cached} kB
SwapCached:        56016 kB
Active:          2422104 kB
Inactive:        1019928 kB
Active(anon):    1917580 kB
Inactive(anon):   523080 kB
Active(file):     504524 kB
Inactive(file):   496848 kB
Unevictable:        4844 kB
Mlocked:            4844 kB
SwapTotal:       ${_swap_total} kB
SwapFree:        ${_swap_free} kB
..."

    export CTDB_MONITOR_MEMORY_USAGE
    export CTDB_MONITOR_SWAP_USAGE
}

setup_fscheck ()
{
    export FAKE_FS_USE="${1:-10}"  # Default is 10% usage

    # Causes some variables to be exported
    setup_ctdb

    export CTDB_MONITOR_FILESYSTEM_USAGE
}

ctdb_get_interfaces ()
{
    # The echo/subshell forces all the output onto 1 line.
    echo $(ctdb ifaces -X | awk -F'|' 'FNR > 1 {print $2}')
}

ctdb_get_1_interface ()
{
    _t=$(ctdb_get_interfaces)
    echo ${_t%% *}
}

# Print all public addresses as: interface IP maskbits
# Each line is suitable for passing to takeip/releaseip
ctdb_get_all_public_addresses ()
{
    _f="${CTDB_PUBLIC_ADDRESSES:-${CTDB_BASE}/public_addresses}"
    while IFS="/$IFS" read _ip _maskbits _ifaces ; do
	echo "$_ifaces $_ip $_maskbits"
    done <"$_f"
}

# Print public addresses on this node as: interface IP maskbits
# Each line is suitable for passing to takeip/releaseip
ctdb_get_my_public_addresses ()
{
    ctdb ip -v -X | {
	read _x # skip header line

	while IFS="|" read _x _ip _x _iface _x ; do
	    [ -n "$_iface" ] || continue
	    while IFS="/$IFS" read _i _maskbits _x ; do
		if [ "$_ip" = "$_i" ] ; then
		    echo $_iface $_ip $_maskbits
		    break
		fi
	    done <"${CTDB_PUBLIC_ADDRESSES:-${CTDB_BASE}/public_addresses}"
	done
    }
}

# Prints the 1st public address as: interface IP maskbits
# This is suitable for passing to takeip/releaseip
ctdb_get_1_public_address ()
{
    ctdb_get_my_public_addresses | { head -n 1 ; cat >/dev/null ; }
}

ctdb_not_implemented ()
{
    export CTDB_NOT_IMPLEMENTED="$1"
    ctdb_not_implemented="\
DEBUG: ctdb: command \"$1\" not implemented in stub"
}

ctdb_fake_scriptstatus ()
{
    _code="$1"
    _status="$2"
    _err_out="$3"

    _d1=$(date '+%s.%N')
    _d2=$(date '+%s.%N')

    echo "$_code $_status $_err_out" >"$FAKE_CTDB_SCRIPTSTATUS/$script"
}

######################################################################

setup_ctdb_policy_routing ()
{
    service_name="per_ip_routing"

    export CTDB_PER_IP_ROUTING_CONF="$CTDB_BASE/policy_routing"
    export CTDB_PER_IP_ROUTING_RULE_PREF=100
    export CTDB_PER_IP_ROUTING_TABLE_ID_LOW=1000
    export CTDB_PER_IP_ROUTING_TABLE_ID_HIGH=2000

    # Tests need to create and populate this file
    rm -f "$CTDB_PER_IP_ROUTING_CONF"
}

# Create policy routing configuration in $CTDB_PER_IP_ROUTING_CONF.
# $1 is the number of assigned IPs to use (<num>, all), defaulting to
# 1.  If $2 is "default" then a default route is also added.
create_policy_routing_config ()
{
    _num_ips="${1:-1}"
    _should_add_default="$2"

    ctdb_get_my_public_addresses |
    if [ "$_num_ips" = "all" ] ; then
	cat
    else
	{ head -n "$_num_ips" ; cat >/dev/null ; }
    fi |
    while read _dev _ip _bits ; do
	_net=$(ipv4_host_addr_to_net "$_ip" "$_bits")
	_gw="${_net%.*}.254" # a dumb, calculated default

	echo "$_ip $_net"

	if [ "$_should_add_default" = "default" ] ; then
	    echo "$_ip 0.0.0.0/0 $_gw"
	fi
    done >"$CTDB_PER_IP_ROUTING_CONF"
}

# Check the routes against those that are expected.  $1 is the number
# of assigned IPs to use (<num>, all), defaulting to 1.  If $2 is
# "default" then expect default routes to have been added.
check_routes ()
{
    _num_ips="${1:-1}"
    _should_add_default="$2"

    _policy_rules=""
    _policy_routes=""

    ctdb_get_my_public_addresses |
    if [ "$_num_ips" = "all" ] ; then
	cat
    else
	{ head -n "$_num_ips" ; cat >/dev/null ; }
    fi | {
	while read _dev _ip _bits ; do
	    _net=$(ipv4_host_addr_to_net "$_ip" "$_bits")
	    _gw="${_net%.*}.254" # a dumb, calculated default

	    _policy_rules="${_policy_rules}
${CTDB_PER_IP_ROUTING_RULE_PREF}:	from $_ip lookup ctdb.$_ip "
	    _policy_routes="${_policy_routes}
# ip route show table ctdb.$_ip
$_net dev $_dev  scope link "

	    if [ "$_should_add_default" = "default" ] ; then
		_policy_routes="${_policy_routes}
default via $_gw dev $_dev "
	    fi
	done

	ok <<EOF
# ip rule show
0:	from all lookup local ${_policy_rules}
32766:	from all lookup main 
32767:	from all lookup default ${_policy_routes}
EOF

	simple_test_command dump_routes
    } || test_fail
}

######################################################################

setup_ctdb_lvs ()
{
	lvs_state_dir="${EVENTSCRIPTS_TESTS_VAR_DIR}/lvs"
	mkdir -p "$lvs_state_dir"

	export FAKE_LVS_STATE_DIR="${lvs_state_dir}/state"
	mkdir "$FAKE_LVS_STATE_DIR"

	lvs_header=$(ipvsadm -l -n)

	export CTDB_LVS_PUBLIC_IP="$1"
	export CTDB_LVS_PUBLIC_IFACE="$2"

	[ -n "$CTDB_LVS_PUBLIC_IP" ] || return 0
	[ -n "$CTDB_LVS_PUBLIC_IFACE" ] || return 0

	export CTDB_LVS_NODES=$(mktemp --tmpdir="$lvs_state_dir")
	export FAKE_CTDB_LVS_MASTER=""

	# Read from stdin
	_pnn=0
	while read _ip _opts ; do
		case "$_opts" in
		master)
			FAKE_CTDB_LVS_MASTER="$_pnn"
			echo "$_ip"
			;;
		slave-only)
			printf "%s\tslave-only\n" "$_ip"
			;;
		*)
			echo "$_ip"
			;;
		esac
		_pnn=$(($_pnn + 1))
	done >"$CTDB_LVS_NODES"
}

check_ipvsadm ()
{
	if [ "$1" = "NULL" ] ; then
		required_result 0 <<EOF
$lvs_header
EOF
	else
		required_result 0 <<EOF
$lvs_header
$(cat)
EOF
	fi

	simple_test_command ipvsadm -l -n
}

check_lvs_ip ()
{
	_scope="$1"

	if [ "$_scope" = "NULL" ] ; then
		required_result 0 <<EOF
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
EOF
	else
		required_result 0 <<EOF
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet ${CTDB_LVS_PUBLIC_IP}/32 scope ${_scope} lo
       valid_lft forever preferred_lft forever
EOF
	fi

	simple_test_command ip addr show dev lo
}

######################################################################

ctdb_catdb_format_pairs ()
{
    _count=0

    while read _k _v ; do
	_kn=$(echo -n "$_k" | wc -c)
	_vn=$(echo -n "$_v" | wc -c)
	cat <<EOF
key(${_kn}) = "${_k}"
dmaster: 0
rsn: 1
data(${_vn}) = "${_v}"

EOF
	_count=$(($_count + 1))
    done

    echo "Dumped ${_count} records"
}

check_ctdb_tdb_statd_state ()
{
    ctdb_get_my_public_addresses |
    while read _x _sip _x ; do
	for _cip ; do
	    echo "statd-state@${_sip}@${_cip}" "$FAKE_DATE_OUTPUT"
	done
    done |
    ctdb_catdb_format_pairs | {
	ok
	simple_test_command ctdb catdb ctdb.tdb
    } || test_fail
}

check_statd_callout_smnotify ()
{
    _state_even=$(( $(date '+%s') / 2 * 2))
    _state_odd=$(($_state_even + 1))

    nfs_load_config

    ctdb_get_my_public_addresses |
    while read _x _sip _x ; do
	for _cip ; do
	    cat <<EOF
--client=${_cip} --ip=${_sip} --server=${_sip} --stateval=${_state_even}
--client=${_cip} --ip=${_sip} --server=${NFS_HOSTNAME} --stateval=${_state_even}
--client=${_cip} --ip=${_sip} --server=${_sip} --stateval=${_state_odd}
--client=${_cip} --ip=${_sip} --server=${NFS_HOSTNAME} --stateval=${_state_odd}
EOF
	done
    done | {
	ok
	simple_test_event "notify"
    } || test_fail
}

######################################################################

setup_ctdb_natgw ()
{
	debug "Setting up NAT gateway"

	natgw_config_dir="${TEST_VAR_DIR}/natgw_config"
	mkdir -p "$natgw_config_dir"

	# These will accumulate, 1 per test... but will be cleaned up at
	# the end.
	export CTDB_NATGW_NODES=$(mktemp --tmpdir="$natgw_config_dir")

	# Read from stdin
	while read _ip _opts ; do
		case "$_opts" in
		master)
			export FAKE_CTDB_NATGW_MASTER="$_ip"
			echo "$_ip"
			;;
		slave-only)
			printf "%s\tslave-only\n" "$_ip"
			;;
		*)
			echo "$_ip"
			;;
		esac
	done >"$CTDB_NATGW_NODES"

	# Assume all of the nodes are on a /24 network and have IPv4
	# addresses:
	read _ip <"$CTDB_NATGW_NODES"
	export CTDB_NATGW_PRIVATE_NETWORK="${_ip%.*}.0/24"

	# These are fixed.  Probably don't use the same network for the
	# private node IPs.  To unset the default gateway just set it to
	# "".  :-)
	export CTDB_NATGW_PUBLIC_IP="10.1.1.121/24"
	export CTDB_NATGW_PUBLIC_IFACE="eth1"
	export CTDB_NATGW_DEFAULT_GATEWAY="10.1.1.254"
	export CTDB_NATGW_SLAVE_ONLY=""
}

ok_natgw_master_ip_addr_show ()
{
    _mac=$(echo "$CTDB_NATGW_PUBLIC_IFACE" | md5sum | sed -r -e 's@(..)(..)(..)(..)(..)(..).*@\1:\2:\3:\4:\5:\6@')

    # This is based on CTDB_NATGW_PUBLIC_IP
    _brd="10.1.1.255"

ok <<EOF
1: ${CTDB_NATGW_PUBLIC_IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether ${_mac} brd ff:ff:ff:ff:ff:ff
    inet ${CTDB_NATGW_PUBLIC_IP} brd ${_brd} scope global ${CTDB_NATGW_PUBLIC_IFACE}
       valid_lft forever preferred_lft forever
EOF
}

ok_natgw_slave_ip_addr_show ()
{
    _mac=$(echo "$CTDB_NATGW_PUBLIC_IFACE" | md5sum | sed -r -e 's@(..)(..)(..)(..)(..)(..).*@\1:\2:\3:\4:\5:\6@')
ok <<EOF
1: ${CTDB_NATGW_PUBLIC_IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether ${_mac} brd ff:ff:ff:ff:ff:ff
EOF
}

ok_natgw_master_static_routes ()
{
    _nl="
"
    _t=""
    for _i in $CTDB_NATGW_STATIC_ROUTES ; do
	# This is intentionally different to the code in 11.natgw ;-)
	case "$_i" in
	    *@*)
		_net=$(echo "$_i" | sed -e 's|@.*||')
		_gw=$(echo "$_i" | sed -e 's|.*@||')
		;;
	    *)
		_net="$_i"
		_gw="$CTDB_NATGW_DEFAULT_GATEWAY"
	esac

	[ -n "$_gw" ] || continue
	_t="${_t}${_t:+${_nl}}"
	_t="${_t}${_net} via ${_gw} dev ethXXX  metric 10 "
    done
    _t=$(echo "$_t" | sort)
    ok "$_t"
}

ok_natgw_slave_static_routes ()
{
    _nl="
"
    _t=""
    for _i in $CTDB_NATGW_STATIC_ROUTES ; do
	# This is intentionally different to the code in 11.natgw ;-)
	_net=$(echo "$_i" | sed -e 's|@.*||')

	# The interface for the private network isn't specified as
	# part of the NATGW configuration and isn't part of the
	# command to add the route.  It is implicitly added by "ip
	# route" but our stub doesn't do this and adds "ethXXX".
	_t="${_t}${_t:+${_nl}}"
	_t="${_t}${_net} via ${FAKE_CTDB_NATGW_MASTER} dev ethXXX  metric 10 "
    done
    _t=$(echo "$_t" | sort)
    ok "$_t"
}

######################################################################

# Samba/winbind fakery

setup_samba ()
{
    setup_ctdb

    service_name="samba"

    if [ "$1" != "down" ] ; then

	debug "Marking Samba services as up, listening and managed by CTDB"
        # Get into known state.
	eventscript_call ctdb_service_managed

        # All possible service names for all known distros.
	for i in "smb" "nmb" "samba" "smbd" "nmbd" ; do
	    service "$i" force-started
	done

	export CTDB_SAMBA_SKIP_SHARE_CHECK="no"
	export CTDB_MANAGED_SERVICES="foo samba bar"

	export FAKE_TCP_LISTEN="0.0.0.0:445 0.0.0.0:139"
	export FAKE_WBINFO_FAIL="no"

	# Some things in 50.samba are backgrounded and waited for.  If
	# we don't sleep at all then timeouts can happen.  This avoids
	# that...  :-)
	export FAKE_SLEEP_FORCE=0.1
    else
	debug "Marking Samba services as down, not listening and not managed by CTDB"
        # Get into known state.
	eventscript_call ctdb_service_unmanaged

        # All possible service names for all known distros.
	for i in "smb" "nmb" "samba" "smbd" "nmbd" ; do
	    service "$i" force-stopped
	done

	export CTDB_SAMBA_SKIP_SHARE_CHECK="no"
	export CTDB_MANAGED_SERVICES="foo bar"
	unset CTDB_MANAGES_SAMBA

	export FAKE_TCP_LISTEN=""
	export FAKE_WBINFO_FAIL="yes"
    fi
}

samba_setup_fake_threads ()
{
	export FAKE_SMBD_THREAD_PIDS="$*"

	_nl="
"
	_out=""
	_count=0
	for _pid ; do
		[ "$_count" -lt 5 ] || break
		_t=$(program_stack_trace "smbd" $_pid)
		_out="${_out:+${_out}${_nl}}${_t}"
		_count=$((_count + 1))
	done
	SAMBA_STACK_TRACES="$_out"
}

setup_winbind ()
{
    setup_ctdb

    service_name="winbind"

    if [ "$1" != "down" ] ; then

	debug "Marking Winbind service as up and managed by CTDB"
        # Get into known state.
	eventscript_call ctdb_service_managed

	service "winbind" force-started

	export CTDB_MANAGED_SERVICES="foo winbind bar"

	export FAKE_WBINFO_FAIL="no"

    else
	debug "Marking Winbind service as down and not managed by CTDB"
        # Get into known state.
	eventscript_call ctdb_service_unmanaged

	service "winbind" force-stopped

	export CTDB_MANAGED_SERVICES="foo bar"
	unset CTDB_MANAGES_WINBIND

	export FAKE_WBINFO_FAIL="yes"
    fi
}

wbinfo_down ()
{
    debug "Making wbinfo commands fail"
    FAKE_WBINFO_FAIL="yes"
}

######################################################################

# NFS fakery

setup_nfs ()
{
    setup_ctdb

    service_name="nfs"

    export FAKE_RPCINFO_SERVICES=""

    export CTDB_NFS_SKIP_SHARE_CHECK="no"

    export RPCNFSDCOUNT

    # This doesn't even need to exist
    export CTDB_NFS_EXPORTS_FILE="$EVENTSCRIPTS_TESTS_VAR_DIR/etc-exports"

    # Reset the failcounts for nfs services.
    eventscript_call eval rm -f '$ctdb_fail_dir/nfs_*'

    if [ "$1" != "down" ] ; then
	debug "Setting up NFS environment: all RPC services up, NFS managed by CTDB"

	eventscript_call ctdb_service_managed
	service "nfs" force-started
	service "nfslock" force-started

	export CTDB_MANAGED_SERVICES="foo nfs bar"

	rpc_services_up \
	    "portmapper" "nfs" "mountd" "rquotad" "nlockmgr" "status"

	nfs_setup_fake_threads "nfsd"
	nfs_setup_fake_threads "rpc.foobar"  # Just set the variable to empty
    else
	debug "Setting up NFS environment: all RPC services down, NFS not managed by CTDB"

	eventscript_call ctdb_service_unmanaged
	service "nfs" force-stopped
	service "nfslock" force-stopped

	export CTDB_MANAGED_SERVICES="foo bar"
	unset CTDB_MANAGES_NFS
    fi

    # This is really nasty.  However, when we test NFS we don't
    # actually test statd-callout. If we leave it there then left
    # over, backgrounded instances of statd-callout will do horrible
    # things with the "ctdb ip" stub and cause the actual
    # statd-callout tests that follow to fail.
    rm "${CTDB_BASE}/statd-callout"
}

setup_nfs_ganesha ()
{
    setup_nfs "$@"
    export CTDB_NFS_CALLOUT="${CTDB_BASE}/nfs-ganesha-callout"
    if [ "$1" != "down" ] ; then
	export CTDB_MANAGES_NFS="yes"
    fi

    export CTDB_NFS_SKIP_SHARE_CHECK="yes"
}

rpc_services_down ()
{
    for _i ; do
	debug "Marking RPC service \"${_i}\" as unavailable"
	FAKE_RPCINFO_SERVICES=$(echo "$FAKE_RPCINFO_SERVICES" | sed -r -e "s@[[:space:]]*${_i}:[0-9]+:[0-9]+@@g")
    done
}

rpc_services_up ()
{
    for _i ; do
	debug "Marking RPC service \"${_i}\" as available"
	case "$_i" in
	    portmapper) _t="2:4" ;;
	    nfs)        _t="2:3" ;;
	    mountd)     _t="1:3" ;;
	    rquotad)    _t="1:2" ;;
	    nlockmgr)   _t="3:4" ;;
	    status)     _t="1:1" ;;
	    *) die "Internal error - unsupported RPC service \"${_i}\"" ;;
	esac

	FAKE_RPCINFO_SERVICES="${FAKE_RPCINFO_SERVICES}${FAKE_RPCINFO_SERVICES:+ }${_i}:${_t}"
    done
}


nfs_load_config ()
{
    _etc="$CTDB_SYS_ETCDIR" # shortcut for readability
    for _c in "$_etc/sysconfig/nfs" "$_etc/default/nfs" "$_etc/ctdb/sysconfig/nfs" ; do
	if [ -r "$_c" ] ; then
	    . "$_c"
	    break
	fi
    done
}

nfs_setup_fake_threads ()
{
    _prog="$1" ; shift

    case "$_prog" in
	nfsd)
	    export PROCFS_PATH=$(mktemp -d --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR")
	    _threads="${PROCFS_PATH}/fs/nfsd/threads"
	    mkdir -p $(dirname "$_threads")
	    echo $# >"$_threads"
	    export FAKE_NFSD_THREAD_PIDS="$*"
	    ;;
	*)
	    export FAKE_RPC_THREAD_PIDS="$*"
	    ;;
    esac
}

program_stack_trace ()
{
	_prog="$1"
	_pid="$2"

	cat <<EOF
Stack trace for ${_prog}[${_pid}]:
[<ffffffff87654321>] fake_stack_trace_for_pid_${_pid}/stack+0x0/0xff
EOF
}

program_stack_traces ()
{
    _prog="$1"
    _max="${2:-1}"

    _count=1
    for _pid in ${FAKE_NFSD_THREAD_PIDS:-$FAKE_RPC_THREAD_PIDS} ; do
	[ $_count -le $_max ] || break

	program_stack_trace "$_prog" "$_pid"
	_count=$(($_count + 1))
    done
}

guess_output ()
{
    case "$1" in
	$CTDB_NFS_CALLOUT\ start\ nlockmgr)
	    echo "&Starting nfslock: OK"
	    ;;
	$CTDB_NFS_CALLOUT\ start\ nfs)
	    cat <<EOF
&Starting nfslock: OK
&Starting nfs: OK
EOF
	    ;;
	*)
	    : # Nothing
    esac
}

# Set the required result for a particular RPC program having failed
# for a certain number of iterations.  This is probably still a work
# in progress.  Note that we could hook aggressively
# nfs_check_rpc_service() to try to implement this but we're better
# off testing nfs_check_rpc_service() using independent code...  even
# if it is incomplete and hacky.  So, if the 60.nfs eventscript
# changes and the tests start to fail then it may be due to this
# function being incomplete.
rpc_set_service_failure_response ()
{
    _rpc_service="$1"
    _numfails="${2:-1}" # default 1

    # Default
    ok_null
    if [ $_numfails -eq 0 ] ; then
	return
    fi

    nfs_load_config

    # A handy newline.  :-)
    _nl="
"

    _dir="${CTDB_NFS_CHECKS_DIR:-${CTDB_BASE}/nfs-checks.d}"

    _file=$(ls "$_dir"/[0-9][0-9]."${_rpc_service}.check")
    [ -r "$_file" ] || die "RPC check file \"$_file\" does not exist or is not unique"

    _out=$(mktemp --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR")
    _rc_file=$(mktemp --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR")

    (
	# Subshell to restrict scope variables...

	# Defaults
	family="tcp"
	version=""
	unhealthy_after=1
	restart_every=0
	service_stop_cmd=""
	service_start_cmd=""
	service_check_cmd=""
	service_debug_cmd=""

	# Don't bother syntax checking, eventscript does that...
	. "$_file"

	# Just use the first version, or use default.  This is dumb but
	# handles all the cases that we care about now...
	if [ -n "$version" ] ; then
	    _ver="${version%% *}"
	else
	    case "$_rpc_service" in
		portmapper) _ver="" ;;
		*) 	    _ver=1  ;;
	    esac
	fi
	_rpc_check_out="\
$_rpc_service failed RPC check:
rpcinfo: RPC: Program not registered
program $_rpc_service${_ver:+ version }${_ver} is not available"

	if [ $unhealthy_after -gt 0 -a $_numfails -ge $unhealthy_after ] ; then
	    _unhealthy=true
	    echo 1 >"$_rc_file"
	    echo "ERROR: ${_rpc_check_out}" >>"$_out"
	else
	    _unhealthy=false
	    echo 0 >"$_rc_file"
	fi

	if [ $restart_every -gt 0 ] && \
		   [ $(($_numfails % $restart_every)) -eq 0 ] ; then
	    if ! $_unhealthy ; then
		echo "WARNING: ${_rpc_check_out}" >>"$_out"
	    fi

	    echo "Trying to restart service \"${_rpc_service}\"..." >>"$_out"

	    if [ -n "$service_debug_cmd" ] ; then
		$service_debug_cmd 2>&1 >>"$_out"
	    fi

	    guess_output "$service_start_cmd" >>"$_out"
	fi
    )

    read _rc <"$_rc_file"
    required_result $_rc <"$_out"

    rm -f "$_out" "$_rc_file"
}

######################################################################

# Recovery lock fakery

cleanup_reclock ()
{
	_pattern="${script_dir}/${script}"
	while pgrep -f "$_pattern" >/dev/null ; do
		echo "Waiting for backgrounded ${script} to exit..."
		(FAKE_SLEEP_REALLY=yes sleep 1)
	done
}

setup_reclock ()
{
	CTDB_RECOVERY_LOCK=$(mktemp --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR")
	export CTDB_RECOVERY_LOCK

	test_cleanup cleanup_reclock
}

######################################################################

# VSFTPD fakery

setup_vsftpd ()
{
    service_name="vsftpd"

    if [ "$1" != "down" ] ; then
	die "setup_vsftpd up not implemented!!!"
    else
	debug "Setting up VSFTPD environment: service down, not managed by CTDB"

	eventscript_call ctdb_service_unmanaged
	service vsftpd force-stopped

	export CTDB_MANAGED_SERVICES="foo"
	unset CTDB_MANAGES_VSFTPD
    fi
}

######################################################################

# HTTPD fakery

setup_httpd ()
{
    if [ "$1" != "down" ] ; then
	die "setup_httpd up not implemented!!!"
    else
	debug "Setting up HTTPD environment: service down, not managed by CTDB"

	for service_name in "apache2" "httpd" ; do
	    eventscript_call ctdb_service_unmanaged
	    service "$service_name" force-stopped
	done

	export CTDB_MANAGED_SERVICES="foo"
	unset CTDB_MANAGES_HTTPD
    fi
}

######################################################################

# multipathd fakery

setup_multipathd ()
{
    for i ; do
	case "$i" in
	    \!*)
		_t="${i#!}"
		echo "Marking ${_t} as having no active paths"
		FAKE_MULTIPATH_FAILURES="${FAKE_MULTIPATH_FAILURES}${FAKE_MULTIPATH+FAILURES:+ }${_t}"
		;;
	    *)
		_t="$i"		
	esac
	CTDB_MONITOR_MPDEVICES="${CTDB_MONITOR_MPDEVICES}${CTDB_MONITOR_MPDEVICES:+ }${_t}"
    done

    export CTDB_MONITOR_MPDEVICES FAKE_MULTIPATH_FAILURES
    export FAKE_SLEEP_FORCE=0.1
}

######################################################################

# Result and test functions

# Set some globals and print the summary.
define_test ()
{
    desc="$1"

    _f=$(basename "$0" ".sh")

    # Remaining format should be NN.service.event.NNN or NN.service.NNN:
    _num="${_f##*.}"
    _f="${_f%.*}"

    case "$_f" in
	[0-9][0-9].*.*)
	    script="${_f%.*}"
	    event="${_f##*.}"
	    script_dir="${CTDB_BASE}/events.d"
	    ;;
	[0-9][0-9].*)
	    script="$_f"
	    unset event
	    script_dir="${CTDB_BASE}/events.d"
	    ;;
	*.*)
	    script="${_f%.*}"
	    event="${_f##*.}"
	    script_dir="${CTDB_BASE}"
	    ;;
	*)
	    script="${_f%.*}"
	    unset event
	    script_dir="${CTDB_BASE}"
    esac

    [ -r "${script_dir}/${script}" ] || \
	die "Internal error - unable to find script \"${script_dir}/${script}\""

    printf "%-17s %-10s %-4s - %s\n\n" "$script" "$event" "$_num" "$desc"
}

# Run an eventscript once.  The test passes if the return code and
# output match those required.

# Any args are passed to the eventscript.

simple_test ()
{
    [ -n "$event" ] || die 'simple_test: $event not set'

    args="$@"

    test_header ()
    {
	echo "Running script \"$script $event${args:+ }$args\""
    }

    extra_header ()
    {
	cat <<EOF

##################################################
CTDB_BASE="$CTDB_BASE"
CTDB_SYS_ETCDIR="$CTDB_SYS_ETCDIR"
ctdb client is "$(which ctdb)"
ip command is "$(which ip)"
EOF
    }

    script_test "${script_dir}/${script}" "$event" "$@"

    reset_test_header
    reset_extra_header
}

simple_test_event ()
{
    # If something has previously failed then don't continue.
    : ${_passed:=true}
    $_passed || return 1

    event="$1" ; shift
    echo "=================================================="
    simple_test "$@"
}

simple_test_command ()
{
    unit_test "$@"
}

# Run an NFS eventscript iteratively.
#
# - 1st argument is the number of iterations.
#
# - 2nd argument is the NFS/RPC service being tested
#
#   rpcinfo (or $service_check_cmd) is used on each iteration to test
#   the availability of the service
#
#   If this is not set or null then no RPC service is checked and the
#   required output is not reset on each iteration.  This is useful in
#   baseline tests to confirm that the eventscript and test
#   infrastructure is working correctly.
#
# - Subsequent arguments come in pairs: an iteration number and
#   something to eval before that iteration.  Each time an iteration
#   number is matched the associated argument is given to eval after
#   the default setup is done.  The iteration numbers need to be given
#   in ascending order.
#
#   These arguments can allow a service to be started or stopped
#   before a particular iteration.
#
nfs_iterate_test ()
{
    _repeats="$1"
    _rpc_service="$2"
    if [ -n "$2" ] ; then
	shift 2
    else
	shift
    fi

    echo "Running $_repeats iterations of \"$script $event\" $args"

    _iterate_failcount=0
    for _iteration in $(seq 1 $_repeats) ; do
	# This is not a numerical comparison because $1 will often not
	# be set.
	if [ "$_iteration" = "$1" ] ; then
	    debug "##################################################"
	    eval "$2"
	    debug "##################################################"
	    shift 2
	fi
	if [ -n "$_rpc_service" ] ; then
	    _ok=false
	    if [ -n "$service_check_cmd" ] ; then
		if eval "$service_check_cmd" ; then
		    _ok=true
		fi
	    else
		if rpcinfo -T tcp localhost "$_rpc_service" >/dev/null 2>&1 ; then
		    _ok=true
		fi
	    fi

	    if $_ok ; then
		_iterate_failcount=0
	    else
		_iterate_failcount=$(($_iterate_failcount + 1))
	    fi
	    rpc_set_service_failure_response "$_rpc_service" $_iterate_failcount
	fi
	_out=$(simple_test 2>&1)
	_ret=$?
	if "$TEST_VERBOSE" || [ $_ret -ne 0 ] ; then
	    echo "##################################################"
	    echo "Iteration ${_iteration}:"
	    echo "$_out"
	fi
	if [ $_ret -ne 0 ] ; then
	    exit $_ret
	fi
    done
}
