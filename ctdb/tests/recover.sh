#!/bin/sh

killall -q ctdbd

echo "Starting 4 ctdb daemons"
bin/ctdbd --recovery-daemon --nlist tests/4nodes.txt
bin/ctdbd --recovery-daemon --nlist tests/4nodes.txt --listen=127.0.0.2 --socket=/tmp/ctdb.socket.127.0.0.2
bin/ctdbd --recovery-daemon --nlist tests/4nodes.txt --listen=127.0.0.3 --socket=/tmp/ctdb.socket.127.0.0.3
bin/ctdbd --recovery-daemon --nlist tests/4nodes.txt --listen=127.0.0.4 --socket=/tmp/ctdb.socket.127.0.0.4

echo
echo "Attaching to some databases"
bin/ctdb_control attach test1.tdb || exit 1
bin/ctdb_control attach test2.tdb || exit 1
bin/ctdb_control attach test3.tdb || exit 1
bin/ctdb_control attach test4.tdb || exit 1

echo "Clearing all databases to make sure they are all empty"
bin/ctdb_control getdbmap 0 | egrep "^dbid:" | sed -e "s/^dbid://" -e "s/ .*$//" | while read DB; do
	seq 0 3 | while read NODE; do
		bin/ctdb_control cleardb $NODE $DB
	done
done


echo
echo
echo "Printing all databases on all nodes. they should all be empty"
echo "============================================================="
bin/ctdb_control getdbmap 0 | egrep "^dbid:" | sed -e "s/^.*name://" -e "s/ .*$//" | while read DBNAME; do
	seq 0 3 | while read NODE; do
		echo "Content of DBNAME:$DBNAME NODE:$NODE :"
		bin/ctdb_control catdb $DBNAME $NODE
	done
done

echo
echo
echo "Populating the databases"
./bin/ctdb_control writerecord 0 0x220c2a7b testkey1 testdata1
./bin/ctdb_control setdmaster 0 0x220c2a7b 1

./bin/ctdb_control writerecord 1 0x220c2a7b testkey1 testdata1
./bin/ctdb_control writerecord 1 0x220c2a7b testkey1 testdata1
./bin/ctdb_control setdmaster 1 0x220c2a7b 2

./bin/ctdb_control writerecord 2 0x220c2a7b testkey1 testdata1
./bin/ctdb_control writerecord 2 0x220c2a7b testkey1 testdata1
./bin/ctdb_control writerecord 2 0x220c2a7b testkey1 testdata1
./bin/ctdb_control setdmaster 2 0x220c2a7b 3

./bin/ctdb_control writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control writerecord 3 0x220c2a7b testkey1 testdata1
./bin/ctdb_control setdmaster 3 0x220c2a7b 3


echo
echo
echo "Printing all databases on all nodes. there should be a record there"
echo "============================================================="
bin/ctdb_control getdbmap 0 | egrep "^dbid:" | sed -e "s/^.*name://" -e "s/ .*$//" | while read DBNAME; do
	seq 0 3 | while read NODE; do
		echo "Content of DBNAME:$DBNAME NODE:$NODE :"
		bin/ctdb_control catdb $DBNAME $NODE
	done
done

echo
echo
echo "killing off node #2"
echo "==================="
CTDBPID=`./bin/ctdb_control getpid 2 | sed -e "s/Pid://"`
kill $CTDBPID
sleep 1


echo
echo
echo "wait 3 seconds to let the recovery daemon do its job"
echo "===================================================="
sleep 3

echo
echo
echo "Printing all databases on all nodes."
echo "The databases should be the same now on all nodes"
echo "and the record will have been migrated to node 0"
echo "================================================="
echo "Node 0:"
bin/ctdb_control catdb test4.tdb 0
echo "Node 1:"
bin/ctdb_control catdb test4.tdb 1
echo "Node 3:"
bin/ctdb_control catdb test4.tdb 3
echo "nodemap:"
bin/ctdb_control getnodemap 0

echo
echo
echo "Traverse the cluster and dump the database"
bin/ctdb_control catdb test4.tdb


#leave the ctdb daemons running   so one can look at the box in more detail
#killall -q ctdbd
