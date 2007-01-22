#!/bin/sh

killall smbd
sleep 1
killall -9 smbd
killall -9 valgrind

type=$1

xterm -e $type bin/smbd -s /home/tridge/samba/samba4.svn/prefix/etc/smb.conf.node1 -M single -i &
xterm -e $type bin/smbd -s /home/tridge/samba/samba4.svn/prefix/etc/smb.conf.node2 -M single -i &

