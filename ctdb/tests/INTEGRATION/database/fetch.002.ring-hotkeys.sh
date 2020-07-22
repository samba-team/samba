#!/bin/bash

# Run the fetch_ring test, sanity check the output and check hot keys
# statistics

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

testdb="fetch_ring.tdb"

ctdb_get_all_pnns
# $all_pnns is set above
# shellcheck disable=SC2154
num_nodes=$(echo "$all_pnns" | wc -w | tr -d '[:space:]')
first=$(echo "$all_pnns" | sed -n -e '1p')

get_key ()
{
	_n="$1"

	echo "testkey${_n}"
}

run_fetch_ring ()
{
	_timelimit="$1"
	_key_num="$2"

	_key=$(get_key "$_key_num")
	_base_cmd="fetch_ring -n ${num_nodes} -D ${testdb}"
	_cmd="${_base_cmd} -t ${_timelimit} -k ${_key}"
	echo "Running \"${_cmd}\" on all $num_nodes nodes."
	testprog_onnode -v -p all "$_cmd"

	_pat='^(Waiting for cluster|Fetch\[[[:digit:]]+\]: [[:digit:]]+(\.[[:digit:]]+)? msgs/sec)$'
	sanity_check_output 1 "$_pat"

	# Get the last line of output.
	# $outfile is set above by testprog_onnode()
	# shellcheck disable=SC2154
	_last=$(tail -n 1 "$outfile")

	# $last should look like this:
	#    Fetch[1]: 10670.93 msgs/sec
	_stuff="${_last##*Fetch\[*\]: }"
	_mps="${_stuff% msgs/sec*}"

	if [ "${_mps%.*}" -ge 10 ] ; then
		echo "OK: ${_mps} msgs/sec >= 10 msgs/sec"
	else
		ctdb_test_fail "BAD: ${_mps} msgs/sec < 10 msgs/sec"
	fi
}

check_hot_keys ()
{
	_pnn="$1"
	_first_key="$2"
	_num_keys="$3"

	echo
	echo "Checking hot keys on node ${_pnn}"

	ctdb_onnode "$_pnn" dbstatistics "$testdb"

	# Get hot keys with a non-empty key
	_hotkeys=$(grep -Ex '[[:space:]]+Count:[[:digit:]]+ Key:[[:xdigit:]]+' \
			"$outfile") || true

	# Check that there are the right number of non-empty slots
	if [ -z "$_hotkeys" ] ; then
		_num=0
	else
		_num=$(echo "$_hotkeys" | wc -l | tr -d '[:space:]')
	fi
	_msg="hot key slots in use = ${_num}"
	if [ "$_num_keys" -ne "$_num" ] ; then
		echo
		cat "$outfile"
		ctdb_test_fail "BAD: ${_msg} (expected ${_num_keys})"
	fi
	echo "GOOD: ${_msg}"

	# No hot keys?  Done...
	if [ "$_num" = 0 ] ; then
		return
	fi

	# Check that hot key counts are correctly sorted
	#
	# Try to be as POSIX as possible
	# shellcheck disable=SC2001
	_counts=$(echo "$_hotkeys" | \
			  sed -e 's|.*Count:\([[:digit:]][[:digit:]]*\).*|\1|')
	_counts_sorted=$(echo "$_counts" | sort -n)
	if [ "$_counts" != "$_counts_sorted" ] ; then
		echo
		cat "$outfile"
		ctdb_test_fail "BAD: hot keys not sorted"
	fi
	echo "GOOD: hot key counts are correctly sorted"

	# Check that all keys are considered hot
	for _j in $(seq "$_first_key" $((_first_key + _num_keys - 1))) ; do
		_key=$(get_key "$_j")
		_key_hex=$(printf '%s' "$_key" | \
				   od -A n -t x1 | \
				   tr -d '[:space:]')
		if ! echo "$_hotkeys" | grep -q "Key:${_key_hex}\$" ; then
			echo
			cat "$outfile"
			ctdb_test_fail "BAD: key \"${_key}\" is not a hot key"
		fi
	done
	echo "GOOD: all keys are listed as hot keys"
}

# Run fetch_ring for each of 10 keys.  After each run confirm that all
# keys used so far are considered hot keys (and do other hot key
# sanity checks) on all nodes.
for i in $(seq 1 10) ; do
	run_fetch_ring 5 "$i"

	for pnn in $all_pnns ; do
		check_hot_keys "$pnn" 1 "$i"
	done

	echo
done

echo
echo "Resetting statistics on node ${first}"
ctdb_onnode "$first" statisticsreset

# Ensure that only node $first has had statistics reset
for pnn in $all_pnns ; do
	if [ "$pnn" = "$first" ] ; then
		check_hot_keys "$pnn" 1 0
	else
		check_hot_keys "$pnn" 1 10
	fi
done

echo

# Run fetch_ring for each of 3 new keys.  After each run confirm that
# the new keys used so far are considered hot keys (and do other hot
# key sanity checks) on node $first.
#
# Note that nothing can be said about hot keys on other nodes, since
# they may be an arbitrary blend of old and new keys.
for i in $(seq 1 3) ; do
	run_fetch_ring 5 $((100 + i))

	check_hot_keys 0 101 "$i"

	echo
done
