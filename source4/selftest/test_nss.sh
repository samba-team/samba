#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

if [ ! -f $samba4bindir/nsstest ]; then
	exit 0
fi

plantest "NSS-TEST using winbind" member $VALGRIND $samba4bindir/nsstest $samba4bindir/shared/libnss_winbind.so

