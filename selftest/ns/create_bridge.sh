#!/bin/sh

# creates a bridge interface (i.e. 'selftest0') that connects together the
# veth interfaces for the various testenvs

br_name=$1
ip_addr=$2
ipv6_addr=$3

# make sure the loopback is up (needed for pinging between namespaces, etc)
ip link set dev lo up

# create the bridge interface and enable it
ip link add $br_name type bridge
ip addr add $ip_addr/24 dev $br_name
ip addr add $ipv6_addr/112 dev $br_name
ip link set $br_name up


