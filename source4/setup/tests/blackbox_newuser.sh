#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_newuser.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh


testit "simple-dc" $PYTHON ./setup/provision --server-role="dc" --domain=FOO --realm=foo.example.com --domain-sid=S-1-5-21-4177067393-1453636373-93818738 --targetdir=$PREFIX/simple-dc
net="./bin/net"

CONFIG="--configfile=$PREFIX/simple-dc/etc/smb.conf"

testit "newuser" $net newuser $CONFIG testuser testpass

# check the enable account script
testit "enableaccount" $net enableaccount $CONFIG testuser

# check the enable account script
testit "setpassword" $net setpassword $CONFIG testuser --newpassword=testpass2

# check the setexpiry script
testit "noexpiry" $net setexpiry $CONFIG testuser --noexpiry
testit "expiry" $net setexpiry $CONFIG testuser --days=7

exit $failed
