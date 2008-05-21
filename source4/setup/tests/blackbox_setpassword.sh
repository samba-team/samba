#!/bin/sh

if [ $# -lt 2 ]; then
cat <<EOF
Usage: blackbox_setpassword.sh PREFIX CONFIGURATION
EOF
exit 1;
fi

PREFIX="$1"
CONFIGURATION="$2"
shift 2

. `dirname $0`/../../../testprogs/blackbox/subunit.sh

testit "simple-dc" $PYTHON ./setup/provision $CONFIGURATION --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc

testit "newuser" $PYTHON ./setup/newuser --configfile=$PREFIX/simple-dc/etc/smb.conf testuser testpass

testit "setpassword" $PYTHON ./setup/setpassword --configfile=$PREFIX/simple-dc/etc/smb.conf testuser --newpassword=testpass

exit $failed
