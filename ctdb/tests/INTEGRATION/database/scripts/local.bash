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
