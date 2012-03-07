#!/bin/sh
#

OP=$1
IFACE=$2
IP=$3
MASKBITS=$4
READD_BASE=$5
READD_SCRIPT=$6

add_ip_to_iface()
{
	local _iface=$1
	local _ip=$2
	local _maskbits=$3
	local _readd_base=$4
	local _script_dir="$_readd_base/$_ip.$_maskbits"

	# we make sure the interface is up first
	ip link set $_iface up || {
		echo "Failed to bringup interface $_iface"
		return 1;
	}
	ip addr add $_ip/$_maskbits brd + dev $_iface || {
		echo "Failed to add $_ip/$_maskbits on dev $_iface"
		return 1;
	}

	mkdir -p $_script_dir || {
		echo "Failed to mkdir -p $_script_dir"
		return 1;
	}

	rm -f $_script_dir/*

	return 0;
}

delete_ip_from_iface()
{
	local _iface=$1
	local _ip=$2
	local _maskbits=$3
	local _readd_base=$4
	local _script_dir="$_readd_base/$_ip.$_maskbits"

	# the ip tool will delete all secondary IPs if this is the primary. To work around
	# this _very_ annoying behaviour we have to keep a record of the secondaries and re-add
	# them afterwards. yuck
	local _secondaries=""
	if ip addr list dev $_iface primary | grep -q "inet $_ip/$_maskbits " ; then
	    _secondaries=`ip addr list dev $_iface secondary | grep " inet " | awk '{print $2}'`
	fi
	local _failed=0
	ip addr del $_ip/$_maskbits dev $_iface || _failed=1
	[ -z "$_secondaries" ] || {
	    local _i=""
	    for _i in $_secondaries; do
		if ip addr list dev $_iface | grep -q "inet $_i" ; then
		    echo "kept secondary $_i on dev $_iface"
		else
		    echo "re-adding secondary address $_i to dev $_iface"
		    ip addr add $_i brd + dev $_iface || _failed=1
		fi
	    done
	}

	test -d $_script_dir && {
		rm -f $_script_dir/*
	}

	[ $_failed = 0 ] || {
		echo "Failed to del $_ip on dev $_iface"
		return 1;
	}
	return 0;
}

case "$OP" in
	add)
		add_ip_to_iface $IFACE $IP $MASKBITS $READD_BASE
		exit $?
		;;
	delete)
		delete_ip_from_iface $IFACE $IP $MASKBITS $READD_BASE
		exit $?
		;;
esac

echo "$0: unknown operation[$OP]"
exit 1
