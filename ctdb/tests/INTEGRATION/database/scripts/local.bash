# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

check_cattdb_num_records ()
{
	local db="$1"
	local num="$2"
	local nodes="$3"

	# $nodes has embedded newlines - put list on 1 line for printing
	local t
	t=$(echo "$nodes" | xargs)
	echo "Confirm that ${db} has ${num} record(s) on node(s): ${t}"

	local ret=0
	local node
	for node in $nodes ; do
		local num_found

		num_found=$(db_ctdb_cattdb_count_records "$node" "$db")
		if [ "$num_found" = "$num" ] ; then
			continue
		fi

		printf 'BAD: %s on node %d has %d record(s), expected %d\n' \
		       "$db" "$node" "$num_found" "$num"
		ctdb_onnode -v "$node" "cattdb $db"
		ret=1
	done

	return $ret
}

vacuum_test_key_dmaster ()
{
	local node="$1"
	local db="$2"
	local key="$3"
	local dmaster="${4:-${node}}"

	testprog_onnode "$node" "ctdb-db-test local-read ${db} ${key}"

	# shellcheck disable=SC2154
	# $outfile is set above by try_command_on_node()
	if ! grep -Fqx "dmaster: ${dmaster}" "$outfile" ; then
		echo "BAD: node ${dmaster} is not dmaster"
		cat "$outfile"
		ctdb_test_fail
	fi
}

vacuum_confirm_key_empty_dmaster ()
{
	local node="$1"
	local db="$2"
	local key="$3"
	local dmaster="${4:-${node}}"

	echo "Confirm record key=\"${key}\" is empty and dmaster=${dmaster}"

	vacuum_test_key_dmaster "$node" "$db" "$key" "$dmaster"

	if ! grep -Fqx 'data(0) = ""' "$outfile" ; then
		echo "BAD: record not empty"
		cat "$outfile"
		ctdb_test_fail
	fi
}

db_confirm_key_has_value ()
{
	local node="$1"
	local db="$2"
	local key="$3"
	local val="$4"

	local out

	ctdb_onnode "$node" "readkey ${db} ${key}"
	outv=$(echo "$out" | sed -n 's|^Data: size:.* ptr:\[\(.*\)\]$|\1|p')
	if [ "$val" != "$outv" ] ; then
		ctdb_test_fail \
			"BAD: value for \"${key}\"=\"${outv}\" (not \"${val}\")"
	fi
}
