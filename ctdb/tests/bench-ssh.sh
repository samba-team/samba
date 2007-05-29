#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: bench-ssh.sh <NODES> <OPTIONS>"
    exit 1
fi

while :; do
    if [ "`echo $1 | cut -c1`" = "-" -o $# -eq 0 ]; then break; fi
    nodes="$nodes $1";
    shift;
done

options=$*
dir=`pwd`

echo "Creating nodes-ssh.txt"
rm -f nodes-ssh.txt
count=0
for h in $nodes; do
    echo "$h" >> nodes-ssh.txt
    count=`expr $count + 1`
done


echo "Killing old processes"
for h in $nodes; do
    scp -q nodes-ssh.txt $h:$dir
    ssh $h killall -q ctdb_bench
done

echo "Starting nodes"
i=0
for h in $nodes; do
    if [ $i -eq `expr $count - 1` ]; then
	ssh $h $dir/bin/ctdb_bench --nlist $dir/nodes-ssh.txt --socket $h$options
    else
	ssh -f $h $dir/bin/ctdb_bench --nlist $dir/nodes-ssh.txt --socket $h $options
    fi
    i=`expr $i + 1`
done

wait
