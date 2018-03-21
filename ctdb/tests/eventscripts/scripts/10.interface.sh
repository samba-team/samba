setup ()
{
	setup_public_addresses
}

_tcp_connections ()
{
	_count="$1"
	_sip="$2"
	_sport="$3"
	_cip_base="$4"
	_cport_base="$5"

	_cip_prefix="${_cip_base%.*}"
	_cip_suffix="${_cip_base##*.}"

	for _i in $(seq 1 $_count) ; do
		_cip_last=$((_cip_suffix + _i))
		_cip="${_cip_prefix}.${_cip_last}"
		_cport=$((_cport_base + _i))
		echo "${_sip}:${_sport} ${_cip}:${_cport}"
	done
}

setup_tcp_connections ()
{
	_t="${FAKE_NETWORK_STATE}/tcp-established"
	export FAKE_NETSTAT_TCP_ESTABLISHED_FILE="$_t"
	_tcp_connections "$@" >"$FAKE_NETSTAT_TCP_ESTABLISHED_FILE"
}

setup_tcp_connections_unkillable ()
{
	# These connections are listed by the "ss" stub but are not
	# killed by the "ctdb killtcp" stub.  So killing these
	# connections will never succeed... and will look like a time
	# out.
	_t=$(_tcp_connections "$@" | sed -e 's/ /|/g')
	export FAKE_NETSTAT_TCP_ESTABLISHED="$_t"
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

	cat <<EOF
Setting $_iface to be a bond with active slave $_slave and MII status $_mii_s
EOF

	_t="${FAKE_NETWORK_STATE}/proc-net-bonding"
	export FAKE_PROC_NET_BONDING="$_t"
	mkdir -p "$FAKE_PROC_NET_BONDING"

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
