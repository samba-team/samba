#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_group.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/../../../testprogs/blackbox/subunit.sh


net="./bin/net"

CONFIG="--configfile=$PREFIX/etc/smb.conf"

#creation of two test subjects
testit "addspn" $net spn add FOO/bar Administrator $CONFIG
testit "delspn" $net spn delete FOO/bar $CONFIG
testit "readdspn" $net spn add FOO/bar Administrator $CONFIG
testit_expect_failure "failexistingspn" $net spn add FOO/bar Guest $CONFIG
testit "existingspnforce" $net spn add --force FOO/bar Guest  $CONFIG
testit_expect_failure "faildelspnnotgooduser" $net spn delete FOO/bar krbtgt $CONFIG
testit_expect_failure "faildelspnmoreoneuser" $net spn delete FOO/bar $CONFIG
testit "deluserspn" $net spn delete FOO/bar Guest $CONFIG
testit "dellastuserspn" $net spn delete FOO/bar $CONFIG
testit_expect_failure "faildelspn" $net spn delete FOO/bar $CONFIG
testit_expect_failure "failaddspn" $net spn add FOO/bar nonexistinguser $CONFIG

exit $failed
