# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

#
# Augment PATH with relevant stubs/ directories.
#

stubs_dir="${CTDB_TEST_SUITE_DIR}/stubs"
[ -d "${stubs_dir}" ] || die "Failed to locate stubs/ subdirectory"

# Make the path absolute for tests that change directory
case "$stubs_dir" in
/*) : ;;
*) stubs_dir="${PWD}/${stubs_dir}" ;;
esac

# Use stubs as helpers
export CTDB_HELPER_BINDIR="$stubs_dir"

PATH="${stubs_dir}:${PATH}"


export CTDB="ctdb"

# Force this to be absolute - event scripts can change directory
CTDB_TEST_TMP_DIR=$(cd "$CTDB_TEST_TMP_DIR" && echo "$PWD")

export CTDB_LOGGING="file:${CTDB_TEST_TMP_DIR}/log.ctdb"
touch "${CTDB_LOGGING#file:}" || \
    die "Unable to setup logging for \"$CTDB_LOGGING\""

if [ -d "${CTDB_TEST_SUITE_DIR}/etc" ] ; then
    cp -a "${CTDB_TEST_SUITE_DIR}/etc" "$CTDB_TEST_TMP_DIR"
    export CTDB_SYS_ETCDIR="${CTDB_TEST_TMP_DIR}/etc"
else
    die "Unable to setup \$CTDB_SYS_ETCDIR"
fi

setup_ctdb_base "$CTDB_TEST_TMP_DIR" "etc-ctdb" \
		functions \
		nfs-checks.d \
		nfs-linux-kernel-callout \
		statd-callout

export FAKE_CTDB_STATE="${CTDB_TEST_TMP_DIR}/fake-ctdb"
mkdir -p "$FAKE_CTDB_STATE"

export FAKE_NETWORK_STATE="${CTDB_TEST_TMP_DIR}/fake-network-state"
mkdir -p "$FAKE_NETWORK_STATE"

######################################################################

if "$CTDB_TEST_VERBOSE" ; then
	debug ()
	{
		if [ -n "$1" ] ; then
			echo "$@" >&2
		else
			cat >&2
		fi
	}
else
	debug () { : ; }
fi

######################################################################

# General setup fakery

# Default is to use script name with ".options" appended.  With
# arguments, this can specify an alternate script name (and
# component).
setup_script_options ()
{
	if [ $# -eq 2 ] ; then
		_script="$2"
	elif [ $# -eq 0  ] ; then
		_script=""
	else
		die "usage: setup_script_options [ component script ]"
	fi

	if [ -n "$_script" ] ; then
		_options="${CTDB_BASE}/events/legacy/${_script}.options"
	else
		_options="${script_dir}/${script%.script}.options"
	fi

	cat >>"$_options"

	# Source the options so that tests can use the variables
	. "$_options"
}

setup_dbdir ()
{
	export CTDB_DBDIR_BASE="${CTDB_TEST_TMP_DIR}/db"
	CTDB_DBDIR="${CTDB_DBDIR_BASE}/volatile"
	CTDB_DBDIR_PERSISTENT="${CTDB_DBDIR_BASE}/persistent"
	CTDB_DBDIR_STATE="${CTDB_DBDIR_BASE}/state"
	cat >>"${CTDB_BASE}/ctdb.conf" <<EOF
[database]
	volatile database directory = ${CTDB_DBDIR}
	persistent database directory = ${CTDB_DBDIR_PERSISTENT}
	state database directory = ${CTDB_DBDIR_STATE}
EOF
	mkdir -p "$CTDB_DBDIR"
	mkdir -p "$CTDB_DBDIR_PERSISTENT"
	mkdir -p "$CTDB_DBDIR_STATE"
}

setup_date ()
{
	export FAKE_DATE_OUTPUT="$1"
}

setup_tcp_listen ()
{
	export FAKE_TCP_LISTEN="$*"
}

tcp_port_listening ()
{
	for _i ; do
		   FAKE_TCP_LISTEN="${FAKE_TCP_LISTEN} ${_i}"
	done
}

tcp_port_down ()
{
	_port="$1"
	debug "Marking TCP port \"${_port}\" as not listening"

	_t=""
	for _i in $FAKE_TCP_LISTEN ; do
		if [ "$_i" = "$_port" ] ; then
			continue
		fi
		_t="${_t} ${_i}"
	done

	FAKE_TCP_LISTEN="$_t"
}

setup_unix_listen ()
{
	export FAKE_NETSTAT_UNIX_LISTEN="$*"
}

unix_socket_listening ()
{
	_s="$1"

	FAKE_NETSTAT_UNIX_LISTEN="${FAKE_NETSTAT_UNIX_LISTEN} ${_s}"
}

setup_shares ()
{
	debug "Setting up shares (3 existing shares)"
	# Create 3 fake shares/exports.
	export FAKE_SHARES=""
	for i in $(seq 1 3) ; do
		_s="${CTDB_TEST_TMP_DIR}/shares/share${i}"
		mkdir -p "$_s"
		FAKE_SHARES="${FAKE_SHARES}${FAKE_SHARES:+ }${_s}"
	done
}

shares_missing ()
{
	# Mark some shares as non-existent
	_fmt="$1" ; shift

	_out=""
	_nl="
"

	_n=1
	for _i in $FAKE_SHARES ; do
		for _j ; do
			if [ $_n -ne "$_j" ] ; then
				continue
			fi

			debug "Mark share $_n as missing share \"$_i\""
			rmdir "$_i"
			_t=$(printf "$_fmt" "${_i}")
			_out="${_out}${_out:+${_nl}}${_t}"
		done
		_n=$(($_n + 1))
	done

	echo "$_out"
}

_ethtool_setup ()
{
	FAKE_ETHTOOL_LINK_DOWN="${FAKE_NETWORK_STATE}/ethtool-link-down"
	export FAKE_ETHTOOL_LINK_DOWN
	mkdir -p "$FAKE_ETHTOOL_LINK_DOWN"
}

ethtool_interfaces_down ()
{
	_ethtool_setup

	for _i ; do
		echo "Marking interface $_i DOWN for ethtool"
		touch "${FAKE_ETHTOOL_LINK_DOWN}/${_i}"
	done
}

ethtool_interfaces_up ()
{
	_ethtool_setup

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

setup_numnodes ()
{
	export FAKE_CTDB_NUMNODES="${1:-3}"
	echo "Setting up CTDB with ${FAKE_CTDB_NUMNODES} fake nodes"
}

# For now this creates the same public addresses each time.  However,
# it could be made more flexible.
setup_public_addresses ()
{
	_f="${CTDB_BASE}/public_addresses"

	echo "Setting up public addresses in ${_f}"
	cat >"$_f" <<EOF
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

    # Needed for IP allocation
    setup_numnodes
}

# Need to cope with ctdb_get_pnn().  If a test changes PNN then it
# needs to be using a different state directory, otherwise the wrong
# PNN can already be cached in the state directory.
ctdb_set_pnn ()
{
    export FAKE_CTDB_PNN="$1"
    echo "Setting up PNN ${FAKE_CTDB_PNN}"

    CTDB_SCRIPT_VARDIR="${CTDB_TEST_TMP_DIR}/scripts/${FAKE_CTDB_PNN}"
    export CTDB_SCRIPT_VARDIR
    mkdir -p "$CTDB_SCRIPT_VARDIR"
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
    _f="${CTDB_BASE}/public_addresses"
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
	    done <"${CTDB_BASE}/public_addresses"
	done
    }
}

# Prints the 1st public address as: interface IP maskbits
# This is suitable for passing to takeip/releaseip
ctdb_get_1_public_address ()
{
    ctdb_get_my_public_addresses | { head -n 1 ; cat >/dev/null ; }
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

program_stack_trace ()
{
	_prog="$1"
	_pid="$2"

	cat <<EOF
Stack trace for ${_prog}[${_pid}]:
[<ffffffff87654321>] fake_stack_trace_for_pid_${_pid}/stack+0x0/0xff
EOF
}

######################################################################

# Result and test functions


############################################################

setup ()
{
	die "setup() is not defined"
}

# Set some globals and print the summary.
define_test ()
{
	desc="$1"

	_f=$(basename "$0" ".sh")

	# Remaining format should be NN.script.event.NUM or
	# NN.script.NUM or script.NUM:
	_num="${_f##*.}"
	_f="${_f%.*}"

	case "$_f" in
	[0-9][0-9].*)
		case "$_f" in
		[0-9][0-9].*.*)
			script="${_f%.*}.script"
			event="${_f##*.}"
			;;
		[0-9][0-9].*)
			script="${_f}.script"
			unset event
			;;
		esac
		# "Enable" the script
		_subdir="events/legacy"
		script_dir="${CTDB_BASE}/${_subdir}"
		# Symlink target needs to be absolute
		case "$CTDB_SCRIPTS_DATA_DIR" in
		/*) _data_dir="${CTDB_SCRIPTS_DATA_DIR}/${_subdir}" ;;
		*)  _data_dir="${PWD}/${CTDB_SCRIPTS_DATA_DIR}/${_subdir}"
		esac
		mkdir -p "$script_dir"
		ln -s "${_data_dir}/${script}" "$script_dir"
		;;
	*)
		script="${_f%.*}"
		unset event
		script_dir="${CTDB_BASE}"
	esac

	_s="${script_dir}/${script}"
	[ -r "$_s" ] || \
		die "Internal error - unable to find script \"${_s}\""

	script_short="${script%.script}"

	printf "%-17s %-10s %-4s - %s\n\n" \
	       "$script_short" "$event" "$_num" "$desc"

	_f="${CTDB_TEST_SUITE_DIR}/scripts/${script_short}.sh"
	if [ -r "$_f" ] ; then
		. "$_f"
	fi

	ctdb_set_pnn 0
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
    unit_test_notrace "$@"
}
