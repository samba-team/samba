#!/bin/bash

test_info()
{
    cat <<EOF
Verify that adding/deleting IPs using 'ctdb reloadips' works

Checks that when IPs are added to and deleted from a single node then
those IPs are actually assigned and unassigned from the specified
interface.

Prerequisites:

* An active CTDB cluster with public IP addresses configured

Expected results:

* When IPs are added to a single node then they are assigned to an
  interface.

* When IPs are deleted from a single node then they disappear from an
  interface.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

select_test_node_and_ips

####################

# Search for an unused 10.B.1.0/24 network on which to add public IP
# addresses.

# The initial search is for a 10.B.0.0/16 network since some
# configurations may use a whole class B for the private network.
# Check that there are no public IP addresses (as reported by "ctdb ip
# -n -all") or other IP addresses (as reported by "ip addr show") with
# the provided prefix.  Note that this is an IPv4-specific test.

echo "Getting public IP information from CTDB..."
try_command_on_node any "$CTDB ip -X -v -n all"
ctdb_ip_info=$(echo "$out" | awk -F'|' 'NR > 1 { print $2, $3, $5 }')

echo "Getting IP information from interfaces..."
try_command_on_node all "ip addr show"
ip_addr_info=$(echo "$out" | \
    awk '$1 == "inet" { ip = $2; sub(/\/.*/, "", ip); print ip }')

prefix=""
for b in $(seq 0 255) ; do
    prefix="10.${b}"

    # Does the prefix match any IP address returned by "ip addr info"?
    while read ip ; do
	if [ "${ip#${prefix}.}" != "$ip" ] ; then
	    prefix=""
	    continue 2
	fi
    done <<<"$ip_addr_info"

    # Does the prefix match any public IP address "ctdb ip -n all"?
    while read ip pnn iface ; do
	if [ "${ip#${prefix}.}" != "$ip" ] ; then
	    prefix=""
	    continue 2
	fi
    done <<<"$ctdb_ip_info"

    # Got through the IPs without matching prefix - done!
    break
done

[ -n "$prefix" ] || die "Unable to find a usable IP address prefix"

# We really want a class C: 10.B.1.0/24
prefix="${prefix}.1"

####################

iface=$(echo "$ctdb_ip_info" | awk -v pnn=$test_node '$2 == pnn { print $3 ; exit }')

####################

new_takeover_timeout=90
echo "Setting TakeoverTimeout=${new_takeover_timeout} to avoid potential bans"
try_command_on_node $test_node "$CTDB setvar TakeoverTimeout ${new_takeover_timeout}"

####################

addresses=$(get_ctdbd_command_line_option $test_node "public-addresses")
echo "Public addresses file on node $test_node is \"$addresses\""
backup="${addresses}.$$"

backup_public_addresses ()
{
    try_command_on_node $test_node "cp -a $addresses $backup"
}

restore_public_addresses ()
{
    try_command_on_node $test_node "mv $backup $addresses >/dev/null 2>&1 || true"
}
ctdb_test_exit_hook_add restore_public_addresses

# Now create that backup
backup_public_addresses

####################

add_ips_to_original_config ()
{
    local test_node="$1"
    local addresses="$2"
    local iface="$3"
    local prefix="$4"
    local first="$5"
    local last="$6"

    echo "Adding new public IPs to original config on node ${test_node}..."
    echo "IPs will be ${prefix}.${first}/24..${prefix}.${last}/24"

    # Implement this by completely rebuilding the public_addresses
    # file.  This is easier than deleting entries on a remote node.
    restore_public_addresses
    backup_public_addresses

    # Note that tee is a safe way of creating a file on a remote node.
    # This avoids potential fragility with quoting or redirection.
    for i in $(seq $first $last) ; do
	echo "${prefix}.${i}/24 ${iface}"
    done |
    try_command_on_node -i $test_node "tee -a $addresses"
}

check_ips ()
{
    local test_node="$1"
    local iface="$2"
    local prefix="$3"
    local first="$4"
    local last="$5"

    # If just 0 specified then this is an empty range
    local public_ips_file=$(mktemp)
    if [ "$first" = 0 -a -z "$last" ] ; then
	echo "Checking that there are no IPs in ${prefix}.0/24"
    else
	local prefix_regexp="inet *${prefix//./\.}"

	echo "Checking IPs in range ${prefix}.${first}/24..${prefix}.${last}/24"

	local i
	for i in $(seq $first $last) ; do
	    echo "${prefix}.${i}"
	done | sort >"$public_ips_file"
    fi

    try_command_on_node $test_node "ip addr show dev ${iface}"
    local ip_addrs_file=$(mktemp)
    echo "$out" | \
	sed -n -e "s@.*inet * \(${prefix//./\.}\.[0-9]*\)/.*@\1@p" | \
	sort >"$ip_addrs_file"

    local diffs=$(diff "$public_ips_file" "$ip_addrs_file") || true
    rm -f "$ip_addrs_file" "$public_ips_file"

    if [ -z "$diffs" ] ; then
	echo "GOOD: IP addresses are as expected"
    else
	echo "BAD: IP addresses are incorrect:"
	echo "$diffs"
	exit 1
    fi
}

####################

new_ip_max=100

####################

add_ips_to_original_config \
    $test_node "$addresses" "$iface" "$prefix" 1 $new_ip_max

try_command_on_node $test_node "$CTDB reloadips"

check_ips $test_node "$iface" "$prefix" 1 $new_ip_max

####################

# This should be the primary.  Ensure that no other IPs are lost
echo "Using 'ctdb reloadips' to remove the 1st address just added..."

add_ips_to_original_config \
    $test_node "$addresses" "$iface" "$prefix" 2 $new_ip_max

try_command_on_node $test_node "$CTDB reloadips"

check_ips $test_node "$iface" "$prefix" 2 $new_ip_max

####################

# Get rid of about 1/2 the IPs
start=$(($new_ip_max / 2 + 1))
echo "Updating to include only about 1/2 of the new IPs..."

add_ips_to_original_config \
    $test_node "$addresses" "$iface" "$prefix" $start $new_ip_max

try_command_on_node $test_node "$CTDB reloadips"

check_ips $test_node "$iface" "$prefix" $start $new_ip_max

####################

# Delete the rest
echo "Restoring original IP configuration..."
restore_public_addresses

try_command_on_node $test_node "$CTDB reloadips"

check_ips $test_node "$iface" "$prefix" 0
