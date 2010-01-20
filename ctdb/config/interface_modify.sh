#!/bin/sh
#

OP=$1
IFACE=$2
IP=$3
MASKBITS=$4

add_ip_to_iface()
{
	local _iface=$1
	local _ip=$2
	local _maskbits=$3

	# we make sure the interface is up first
	/sbin/ip link set $_iface up || {
		echo "Failed to bringup interface $_iface"
		return 1;
	}
	/sbin/ip addr add $_ip/$_maskbits brd + dev $_iface || {
		echo "Failed to add $_ip/$_maskbits on dev $_iface"
		return 1;
	}

	return 0;
}

delete_ip_from_iface()
{
	local _iface=$1
	local _ip=$2
	local _maskbits=$3

	# the ip tool will delete all secondary IPs if this is the primary. To work around
	# this _very_ annoying behaviour we have to keep a record of the secondaries and re-add
	# them afterwards. yuck
	local _secondaries=""
	if /sbin/ip addr list dev $_iface primary | grep -q "inet $_ip/$_maskbits " ; then
	    _secondaries=`/sbin/ip addr list dev $_iface secondary | grep " inet " | awk '{print $2}'`
	fi
	local _failed=0
	/sbin/ip addr del $_ip/$_maskbits dev $_iface || _failed=1
	[ -z "$_secondaries" ] || {
	    local _i=""
	    for _i in $_secondaries; do
		if /sbin/ip addr list dev $_iface | grep -q "inet $_i" ; then
		    echo "kept secondary $_i on dev $_iface"
		else
		    echo "re-adding secondary address $_i to dev $_iface"
		    /sbin/ip addr add $_i dev $_iface || _failed=1
		fi
	    done
	}
	[ $_failed = 0 ] || {
		echo "Failed to del $_ip on dev $_iface"
		return 1;
	}
	return 0;
}

case "$OP" in
	add)
		add_ip_to_iface $IFACE $IP $MASKBITS
		exit $?
		;;
	delete)
		delete_ip_from_iface $IFACE $IP $MASKBITS
		exit $?
		;;
esac

echo "$0: unknown operation[$OP]"
exit 1
