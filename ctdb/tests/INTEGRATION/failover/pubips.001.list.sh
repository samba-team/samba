#!/usr/bin/env bash

# Verify that 'ctdb ip' shows the correct output

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

echo "Getting list of public IPs..."
try_command_on_node -v 1 "$CTDB ip all | tail -n +2"
ips=$(sed \
	-e 's@ node\[@ @' \
	-e 's@\].*$@@' \
	"$outfile")
machineout=$(sed -r \
	-e 's@^| |$@\|@g' \
	-e 's@[[:alpha:]]+\[@@g' \
	-e 's@\]@@g' \
	"$outfile")

if ctdb_test_on_cluster ; then
	while read ip pnn ; do
		try_command_on_node $pnn "ip addr show to ${ip}"
		if [ -n "$out" ] ; then
			echo "GOOD: node $pnn appears to have $ip assigned"
		else
			die "BAD: node $pnn does not appear to have $ip assigned"
		fi
	done <<<"$ips" # bashism to avoid problem setting variable in pipeline.
fi

echo "Looks good!"

cmd="$CTDB -X ip all | tail -n +2"
echo "Checking that \"$cmd\" produces expected output..."

try_command_on_node 1 "$cmd"
if [ "$out" = "$machineout" ] ; then
    echo "Yep, looks good!"
else
    echo "Nope, it looks like this:"
    echo "$out"
    echo "Should be like this:"
    echo "$machineout"
    exit 1
fi
