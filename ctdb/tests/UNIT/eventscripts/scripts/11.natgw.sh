setup ()
{
	debug "Setting up NAT gateway"

	natgw_nodes="${CTDB_BASE}/natgw_nodes"

	ctdb_set_pnn
}

# A separate function for this makes sense because it can be done
# multiple times per test
setup_ctdb_natgw ()
{
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
	done >"$natgw_nodes"

	# Assume all of the nodes are on a /24 network and have IPv4
	# addresses:
	read _ip <"$natgw_nodes"

	setup_script_options <<EOF
CTDB_NATGW_NODES="$natgw_nodes"
CTDB_NATGW_PRIVATE_NETWORK="${_ip%.*}.0/24"
# These are fixed.  Probably don't use the same network for the
# private node IPs.  To unset the default gateway just set it to
# "".  :-)
CTDB_NATGW_PUBLIC_IP="10.1.1.121/24"
CTDB_NATGW_PUBLIC_IFACE="eth1"
CTDB_NATGW_DEFAULT_GATEWAY="10.1.1.254"
EOF
}

ok_natgw_master_ip_addr_show ()
{
	_mac=$(echo "$CTDB_NATGW_PUBLIC_IFACE" |
	       cksum |
	       sed -r -e 's@(..)(..)(..).*@fe:fe:fe:\1:\2:\3@')

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
	_mac=$(echo "$CTDB_NATGW_PUBLIC_IFACE" |
	       cksum |
	       sed -r -e 's@(..)(..)(..).*@fe:fe:fe:\1:\2:\3@')

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

		# The interface for the private network isn't
		# specified as part of the NATGW configuration and
		# isn't part of the command to add the route.  It is
		# implicitly added by "ip route" but our stub doesn't
		# do this and adds "ethXXX".
		_t="${_t}${_t:+${_nl}}"
		_t="${_t}${_net} via ${FAKE_CTDB_NATGW_MASTER} dev ethXXX  metric 10 "
	done
	_t=$(echo "$_t" | sort)
	ok "$_t"
}
