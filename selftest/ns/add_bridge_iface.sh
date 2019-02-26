#!/bin/sh
#
# Configures the interfaces needed for communication between namespaces.
# This handles the bridge-end of the veth pair.
interface=$1

# the main bridge interface is called 'selftest0' (although in future we may
# want to segregate the different domains by using different bridges)
bridge=$2

# we need to wait for the child namespace to start up and add the new
# interface back to our new namespace
while ! ip link show $interface > /dev/null 2>&1
do
    sleep 0.1
    echo "Waiting for $interface to be created..."
done

# bring the bridge-end of the link up and add it to the bridge
ip link set dev $interface up
ip link set $interface master $bridge

