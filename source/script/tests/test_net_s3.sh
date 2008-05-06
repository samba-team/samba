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

net_misc
net_registry

testok $0 $failed

