#!/bin/sh
#
# This script can be called from a cronjob to automatically drop/release
# all public ip addresses if CTDBD has crashed or stopped running.
#

[ -z "$CTDB_BASE" ] && {
    CTDB_BASE=/etc/ctdb
}

[ -z "$CTDB_PUBLIC_ADDRESSES" ] && {
	CTDB_PUBLIC_ADDRESSES=$CTDB_BASE/public_addresses
}

[ ! -f "$CTDB_PUBLIC_ADDRESSES" ] && {
	echo "No public addresses file found. Can't clean up."
	exit 1
}

# if ctdb is running, just return
ctdb status 2>/dev/null && {
    exit 0
}

if [ -f /etc/sysconfig/ctdb ]; then
    CTDB_CONFIG=/etc/sysconfig/ctdb
elif [ -f /etc/default/ctdb ]; then
    CTDB_CONFIG=/etc/default/ctdb
else
    echo "CTDB config not found. Can't clean up."
    exit 1
fi

(cat $CTDB_CONFIG | egrep "^CTDB_NATGW_PUBLIC_IP" | sed -e "s/.*=//" -e "s/\/.*//";cat "$CTDB_PUBLIC_ADDRESSES" | cut -d/ -f1) | while read _IP; do
	_IP_HELD=`/sbin/ip addr show | grep "inet $_IP/"`
	[ -z "$_IP_HELD" ] || {
		_IFACE=`echo $_IP_HELD | sed -e "s/.*\s//"`
		_NM=`echo $_IP_HELD | sed -e "s/.*$_IP\///" -e "s/\s.*//"`
		logger "Removing public address $_IP/$_NM from device $_IFACE"
		/sbin/ip addr del $_IP/$_NM dev $_IFACE
	}
done


