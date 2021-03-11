#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_smbspool.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"
DOMAIN="$3"
USERNAME="$4"
PASSWORD="$5"
shift 5
ADDARGS="$@"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

smbclient="$BINDIR/smbclient"

test_var_expansion() {
	$smbclient -U $DOMAIN/$USERNAME%$PASSWORD \
		   //$SERVER_IP/print_var_exp \
		   -c "print $SRCDIR/testdata/printing/example.ps" || return 1

	cat /tmp/printing_var_exp.log

	grep "Windows user: $USERNAME" /tmp/printing_var_exp.log || return 1
	grep "UNIX user: $USERNAME" /tmp/printing_var_exp.log || return 1
	grep "Domain: $DOMAIN" /tmp/printing_var_exp.log || return 1
}

testit "Test variable expansion for '%U', '%u' and '%D'" \
	test_var_expansion \
	|| failed=$(expr $failed + 1)

exit $failed
