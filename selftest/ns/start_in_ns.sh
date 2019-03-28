#!/bin/sh
#
# Starts samba in a separate namespace. This gets passed the interface/IP
# to use, as well as the Samba command to run. The whole script gets run
# (via unshare) in a separate namespace.

# the first 3 args are our interface-name, parent-PID, and a exports file
# containing environment variables ($SERVER, $SERVER_IP, etc)
interface=$1
exports_file=$2
parent_pid=$3

# we write the testenv environment variables to file, which makes it easier
# to work out the $SERVER, $SERVER_IP, etc
. $exports_file

# The namespaces we use are anonymous, which means other processes would need
# to use our PID to access the new namespace
echo "-------------------------------------------------------------"
echo "Created namespace for $NETBIOSNAME ($ENVNAME) PID $$"

# generate a helper script if the developer wants to talk to this namespace
# in another shell
mk_nsenter_script="$(dirname $0)/mk_nsenter.sh"
helper_script=$($mk_nsenter_script $$ $exports_file)

echo "To communicate with this testenv, use: $helper_script"
echo "-------------------------------------------------------------"

# the rest of the args are the samba command to run
shift 3
SAMBA_CMD=$@

# make sure namespace loopback is up (it's needed for ping, etc)
ip link set dev lo up

# Create the interfaces needed for communication between namespaces.
# We use a veth pair, which acts as a tunnel between the namespaces.
# One end of the veth link is added to a common bridge in the top-level (i.e.
# selftest) namespace, and the other end is added to the testenv's namespace.
# This means each testenv DC is in its own namespace, but they can talk to
# each other via the common bridge interface.
# The new veth interfaces are named "vethX" and "vethX-br", where
# X = the testenv IP (i.e. Samba::get_interface()). E.g. ad_dc = veth30,
# and veth30-br.
# The "vethX" interface will live in the new testenv's namespace.
# The "vethX-br" end is added to the bridge in the main selftest namespace.
ip link add dev $interface-br type veth peer name $interface

# move the bridge end of the link back into the parent namespace.
ip link set $interface-br netns $parent_pid

# configure our IP address and bring the interface up
ip addr add $SERVER_IP/24 dev $interface
# Note that samba can't bind to the IPv6 address while DAD is in progress,
# so we use 'nodad' when configuring the address
ip addr add $SERVER_IPV6/112 dev $interface nodad
ip link set dev $interface up

# start samba
$SAMBA_CMD
