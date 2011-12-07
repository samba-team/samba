#!/bin/sh
# Blackbox wrapper for nsstest
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 2 ]; then
cat <<EOF
Usage: nsstest.sh NSSTEST LIBNSS_WINBIND
EOF
exit 1;
fi

nsstest=$1
libnss_winbind=$2
shift 2
failed=0

. `dirname $0`/subunit.sh

testit "run nsstest" $VALGRIND $nsstest $libnss_winbind || failed=`expr $failed + 1`

exit $failed
