#!/bin/sh

incdir=`dirname $0`
. $incdir/test_functions.sh

if [ ! -f bin/nsstest ]; then
	exit 0
fi

plantest "NSS-TEST using winbind" member $VALGRIND bin/nsstest bin/shared/libnss_winbind.so

