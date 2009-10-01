#!/bin/sh

# This script is activated by setting CTDB_NOTIFY_SCRIPT=/etc/ctdb/notify.sh
# in /etc/sysconfig/ctdb

# This is script is invoked from ctdb when node UNHEALTHY flag changes.
# and can be used to send SNMPtraps, email, etc
# when the status of a node changes


event="$1"
shift

case $event in
	unhealthy)
#
#               Send an snmptrap that the node is unhealthy :
#		snmptrap -m ALL -v 1 -c public 10.1.1.105 ctdb `hostname` 0 0 `date +"%s"` ctdb.nodeHealth.0 i 1
#
#               or send an email :
#               mail foo@bar -s "`hostname` is UNHEALTHY"   ...
#
#               or do something else ...
		;;
	healthy)
#
#               Send an snmptrap that the node is healthy again :
#		snmptrap -m ALL -v 1 -c public 10.1.1.105 ctdb `hostname` 0 0 `date +"%s"` ctdb.nodeHealth.0 i 0
#
#               or send an email :
#               mail foo@bar -s "`hostname` is HEALTHY"   ...
#
#               or do something else ...
		;;
	startup)
#		do some extra magic when ctdb has started?
		;;

esac

exit 0
