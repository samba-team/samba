#!/bin/sh
# Blackbox tests for gentest
# Copyright (C) 2008 Andrew Tridgell
# based on test_smbclient.sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_gentest.sh SERVER USERNAME PASSWORD DOMAIN
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
DOMAIN=$4
shift 4
failed=0

samba4bindir=`dirname $0`/../../source/bin
gentest=$samba4bindir/gentest

testit() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

cat <<EOF > st/gentest.ignore
all_info.out.fname
internal_information.out.file_id
EOF

testit "gentest" $VALGRIND $gentest //$SERVER/test1 //$SERVER/test2 --num-ops=100 --ignore=st/gentest.ignore -W "$DOMAIN" -U"$USERNAME%$PASSWORD" -U"$USERNAME%$PASSWORD" $@ || failed=`expr $failed + 1`

/bin/rm -f st/gentest.ignore

exit $failed
