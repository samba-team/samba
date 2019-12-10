#!/usr/bin/env bash

# Verify that 'ctdb getdbmap' operates as expected

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init

make_temp_db_filename ()
{
    dd if=/dev/urandom count=1 bs=512 2>/dev/null |
    md5sum |
    awk '{printf "%s.tdb\n", $1}'
}

try_command_on_node -v 0 "$CTDB getdbmap"

dbid='dbid:0x[[:xdigit:]]+'
name='name:[^[:space:]]+'
path='path:[^[:space:]]+'
opts='( (PERSISTENT|STICKY|READONLY|REPLICATED|UNHEALTHY))*'
line="${dbid} ${name} ${path}${opts}"
dbmap_pattern="^(Number of databases:[[:digit:]]+|${line})\$"

num_db_init=$(sed -n -e '1s/.*://p' "$outfile")

sanity_check_output $(($num_db_init + 1)) "$dbmap_pattern"

for i in $(seq 1 5) ; do
    f=$(make_temp_db_filename)
    echo "Creating test database: $f"
    try_command_on_node 0 $CTDB attach "$f"
    try_command_on_node 0 $CTDB getdbmap
    sanity_check_output $(($num_db_init + 1)) "$dbmap_pattern"
    num=$(sed -n -e '1s/^.*://p' "$outfile")
    if [ $num = $(($num_db_init + $i)) ] ; then
	echo "OK: correct number of additional databases"
    else
	echo "BAD: no additional database"
	exit 1
    fi
    if awk '{print $2}' "$outfile" | grep -Fqx "name:$f" ; then
	echo "OK: getdbmap knows about \"$f\""
    else
	echo "BAD: getdbmap does not know about \"$f\""
	exit 1
    fi
done
