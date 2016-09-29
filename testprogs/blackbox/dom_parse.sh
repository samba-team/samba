#!/bin/sh
# Blackbox wrapper for nsstest
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>

if [ $# -lt 2 ]; then
cat <<EOF
Usage: dom_parse.sh [id|getent] $USER
EOF
exit 1;
fi

USER=$2
CMD=$1
EXTRA=""
shift 2
failed=0

. `dirname $0`/subunit.sh

if [ "$CMD" = "getent" ]; then
    EXTRA="passwd"
fi

testit "samba4.winbind.dom_name_parse.cmd.$CMD" $CMD $EXTRA $USER || failed=`expr $failed + 1`

exit $failed
