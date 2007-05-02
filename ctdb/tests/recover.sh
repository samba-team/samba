#!/bin/sh

killall -q ctdbd

echo "Starting 4 ctdb daemons"
bin/ctdbd --nlist direct/4nodes.txt
bin/ctdbd --nlist direct/4nodes.txt
bin/ctdbd --nlist direct/4nodes.txt
bin/ctdbd --nlist direct/4nodes.txt

echo "Attaching to some databases"
bin/ctdb_control --socket=/tmp/ctdb.socket attach test1.tdb || exit 1
bin/ctdb_control --socket=/tmp/ctdb.socket attach test2.tdb || exit 1
bin/ctdb_control --socket=/tmp/ctdb.socket attach test3.tdb || exit 1
bin/ctdb_control --socket=/tmp/ctdb.socket attach test4.tdb || exit 1

echo "Clearing all databases to make sure they are all empty"
bin/ctdb_control --socket=/tmp/ctdb.socket getdbmap 0 | egrep "^dbid:" | sed -e "s/^dbid://" -e "s/ .*$//" | while read DB; do
	seq 0 3 | while read NODE; do
		bin/ctdb_control --socket=/tmp/ctdb.socket cleardb $NODE $DB
	done
done


echo
echo
echo "Printing all databases on all nodes. they should all be empty"
echo "============================================================="
bin/ctdb_control --socket=/tmp/ctdb.socket getdbmap 0 | egrep "^dbid:" | sed -e "s/^dbid://" -e "s/ .*$//" | while read DB; do
	seq 0 3 | while read NODE; do
		echo "Content of DB:$DB NODE:$NODE :"
		bin/ctdb_control --socket=/tmp/ctdb.socket catdb $NODE $DB
	done
done


echo
echo
echo "Populating the databases"

#leave the ctdb daemons running
#killall -q ctdbd
