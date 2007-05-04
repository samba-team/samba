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
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 0 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket setdmaster 0 0x220c2a7b 1

./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 1 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 1 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket setdmaster 1 0x220c2a7b 2

./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 2 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 2 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 2 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket setdmaster 2 0x220c2a7b 3

./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control --socket=/tmp/ctdb.socket setdmaster 3 0x220c2a7b 3


echo
echo
echo "Printing all databases on all nodes. there should be a record there"
echo "============================================================="
bin/ctdb_control --socket=/tmp/ctdb.socket getdbmap 0 | egrep "^dbid:" | sed -e "s/^dbid://" -e "s/ .*$//" | while read DB; do
	seq 0 3 | while read NODE; do
		echo "Content of DB:$DB NODE:$NODE :"
		bin/ctdb_control --socket=/tmp/ctdb.socket catdb $NODE $DB
	done
done

echo
echo
echo "killing off node #0"
echo "==================="
CTDBPID=`ps aux | grep ctdbd | grep -v grep | head -1 | sed -e "s/^[^ ]* *//" -e "s/ .*$//"`
kill $CTDBPID
sleep 1

echo
echo
echo "Recovery the cluster"
echo "===================="
./bin/ctdb_control --socket=/tmp/ctdb.socket recover 2 0x220c2a7b

echo
echo
echo "Printing all databases on all nodes."
echo "The databases should be the same now on all nodes"
echo "and the record will have been migrated to node 0"
echo "================================================="
echo "Node 1:"
bin/ctdb_control --socket=/tmp/ctdb.socket catdb 1 0x220c2a7b
echo "Node 2:"
bin/ctdb_control --socket=/tmp/ctdb.socket catdb 2 0x220c2a7b
echo "Node 3:"
bin/ctdb_control --socket=/tmp/ctdb.socket catdb 3 0x220c2a7b
echo "nodemap:"
bin/ctdb_control --socket=/tmp/ctdb.socket getnodemap 3



#leave the ctdb daemons running   so one can look at the box in more detail
#killall -q ctdbd
