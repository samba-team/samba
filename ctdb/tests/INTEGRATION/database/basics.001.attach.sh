#!/usr/bin/env bash

# Verify that 'ctdb getdbmap' operates as expected

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

select_test_node

# test_node set by select_test_node() above
# shellcheck disable=SC2154
ctdb_onnode -v "$test_node" getdbmap

dbid='dbid:0x[[:xdigit:]]+'
name='name:[^[:space:]]+'
path='path:[^[:space:]]+'
opts='( (PERSISTENT|STICKY|READONLY|REPLICATED|UNHEALTHY))*'
line="${dbid} ${name} ${path}${opts}"
dbmap_pattern="^(Number of databases:[[:digit:]]+|${line})\$"

# outfile set by ctdb_onnode() above
# shellcheck disable=SC2154
num_db_init=$(sed -n -e '1s/.*://p' "$outfile")

sanity_check_output $(($num_db_init + 1)) "$dbmap_pattern"

for i in $(seq 1 5) ; do
	f="attach_test_${i}.tdb"
	echo "Creating test database: $f"
	ctdb_onnode "$test_node" "attach ${f}"

	ctdb_onnode "$test_node" getdbmap
	sanity_check_output $((num_db_init + 1)) "$dbmap_pattern"
	num=$(sed -n -e '1s/^.*://p' "$outfile")
	if [ "$num" = $((num_db_init + i)) ] ; then
		echo "OK: correct number of additional databases"
	else
		ctdb_test_fail "BAD: no additional database"
	fi
	if awk '{print $2}' "$outfile" | grep -Fqx "name:$f" ; then
		echo "OK: getdbmap knows about \"$f\""
	else
		ctdb_test_fail "BAD: getdbmap does not know about \"$f\""
	fi
done
