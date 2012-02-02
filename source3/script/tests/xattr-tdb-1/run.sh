#!/bin/sh
if ../../../bin/vfstest -s smb.conf -f vfstest.cmd |
    grep "NT_STATUS_ACCESS_DENIED" > /dev/null 2>&1
then
    exit 1
fi
exit 0
