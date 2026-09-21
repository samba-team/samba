#!/bin/sh
#
# Blackbox tests for 'net clusterlevel --json' output.
#
# Verifies that each subcommand produces JSON with the expected fields
# and correct value types.  Requires a running CTDB cluster
# (clusteredmember selftest environment).
#
# Usage:
#   test_clusterlevel_json.sh NET CONFIGURATION
#

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_clusterlevel_json.sh NET CONFIGURATION
EOF
	exit 1
fi

NET="$1"
CONFIGURATION="$2"

NET_CMD="$NET $CONFIGURATION"

incdir=$(dirname $0)/../../../testprogs/blackbox
. "$incdir/subunit.sh"

failed=0

test_show_json()
{
	local out
	out=$(UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		$NET_CMD clusterlevel show --json 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel show --json exited non-zero"
		return 1
	fi

	echo "$out" | jq "." > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel show --json output is not valid JSON"
		echo "  output: $out"
		return 1
	fi

	echo "$out" | jq -e '.active_level.major | numbers' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: active_level.major missing or not a number"
		return 1
	fi

	echo "$out" | jq -e '.active_level.minor | numbers' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: active_level.minor missing or not a number"
		return 1
	fi

	return 0
}

test_showall_json()
{
	local out
	out=$(UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		$NET_CMD clusterlevel showall --json 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel showall --json exited non-zero"
		return 1
	fi

	echo "$out" | jq "." > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel showall --json output is not valid JSON"
		echo "  output: $out"
		return 1
	fi

	echo "$out" | jq -e '.active_level.major | numbers' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: active_level.major missing or not a number"
		return 1
	fi

	echo "$out" | jq -e '.nodes | arrays' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: nodes missing or not an array"
		return 1
	fi

	echo "$out" | jq -e '.nodes | length > 0' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: nodes is empty"
		return 1
	fi

	echo "$out" | jq -e '.nodes | all(.pnn | type == "number")' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: nodes[].pnn missing or not a number"
		return 1
	fi

	echo "$out" | jq -e '.upgrade_possible | type == "boolean"' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: upgrade_possible missing or not a boolean"
		return 1
	fi

	# highest_level must have major/minor if present
	if echo "$out" | jq -e 'has("highest_level")' > /dev/null 2>&1; then
		echo "$out" | jq -e '.highest_level.major | numbers' > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			echo "FAIL: highest_level.major missing or not a number"
			return 1
		fi
	fi

	return 0
}

test_features_json()
{
	local out
	out=$(UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		$NET_CMD clusterlevel features --json 2>/dev/null)
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel features --json exited non-zero"
		return 1
	fi

	echo "$out" | jq "." > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel features --json output is not valid JSON"
		echo "  output: $out"
		return 1
	fi

	echo "$out" | jq -e '.cluster_support | type == "boolean"' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: cluster_support missing or not a boolean"
		return 1
	fi

	echo "$out" | jq -e '.supported_ranges | arrays' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: supported_ranges missing or not an array"
		return 1
	fi

	echo "$out" | jq -e '.supported_ranges | length > 0' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: supported_ranges is empty"
		return 1
	fi

	echo "$out" | jq -e '.supported_ranges | all(.major | type == "number")' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: supported_ranges[].major missing or not a number"
		return 1
	fi

	echo "$out" | jq -e '.supported_ranges | all(.minor_min | type == "number")' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: supported_ranges[].minor_min missing or not a number"
		return 1
	fi

	echo "$out" | jq -e '.supported_ranges | all(.minor_max | type == "number")' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: supported_ranges[].minor_max missing or not a number"
		return 1
	fi

	return 0
}

test_upgrade_dryrun_json()
{
	local out
	out=$(UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		$NET_CMD clusterlevel upgrade --test --json 2>/dev/null)
	# No exit-code check: dry-run exits non-zero for 'already_current',
	# which is a valid outcome.  Validate the JSON content instead.

	echo "$out" | jq "." > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: net clusterlevel upgrade --test --json output is not valid JSON"
		echo "  output: $out"
		return 1
	fi

	echo "$out" | jq -e '.dry_run == true' > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "FAIL: dry_run is not true"
		return 1
	fi

	local status
	status=$(echo "$out" | jq -r '.status' 2>/dev/null)
	case "$status" in
		already_current)
			: # valid
			;;
		*)
			echo "FAIL: unexpected status value: $status"
			return 1
			;;
	esac

	return 0
}

testit "clusterlevel_features_json"       test_features_json       || failed=$((failed + 1))
testit "clusterlevel_show_json"           test_show_json           || failed=$((failed + 1))
testit "clusterlevel_showall_json"        test_showall_json        || failed=$((failed + 1))
testit "clusterlevel_upgrade_dryrun_json" test_upgrade_dryrun_json || failed=$((failed + 1))

testok "$0" "$failed"
