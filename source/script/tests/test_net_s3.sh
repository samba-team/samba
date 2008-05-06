#!/bin/sh

# tests for the "net" command

incdir=`dirname $0`
. $incdir/test_functions.sh

failed=0

net_misc() {
	echo "Running misc tests"
	$SCRIPTDIR/test_net_misc.sh \
	|| failed=`expr $failed + $?`
}

net_registry() {
	echo "Running local registry tests"
	$SCRIPTDIR/test_net_registry.sh \
	|| failed=`expr $failed + $?`
}

net_rpc_registry() {
	echo "Running remote registry tests"
	$SCRIPTDIR/test_net_registry.sh rpc \
	|| failed=`expr $failed + $?`
}

net_misc
net_registry
net_rpc_registry

testok $0 $failed

