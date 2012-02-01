#!/bin/sh
rm -r .streams
../../bin/vfstest -s smb.conf -f vfstest.cmd
NUM=`find .streams | wc -l`
if [ $NUM -ne 3 ] ; then
    echo "streams_depot left ${NUM} in .streams, expected 3"
    exit 1
fi
exit 0
