setup ()
{
	setup_public_addresses

	service_name="per_ip_routing"

	setup_script_options <<EOF
CTDB_PER_IP_ROUTING_CONF="${CTDB_BASE}/policy_routing"
CTDB_PER_IP_ROUTING_RULE_PREF=100
CTDB_PER_IP_ROUTING_TABLE_ID_LOW=1000
CTDB_PER_IP_ROUTING_TABLE_ID_HIGH=2000
EOF

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
