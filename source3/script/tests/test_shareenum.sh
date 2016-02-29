#!/bin/sh

# this tests share enumeration with "access based share enum"

if [ $# -lt 4 ]; then
cat <<EOF
Usage: $0 SERVER USERNAME PASSWORD RPCCLIENT
EOF
exit 1;
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
RPCCLIENT="$4"
RPCCLIENT="$VALGRIND ${RPCCLIENT}"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

user_see_share() {
    local user=$1
    local share=$2
    $RPCCLIENT //$SERVER -U$user%$PASSWORD -c "netshareenumall" | grep $share > /dev/null 2>&1
}

testit "$USERNAME sees tmp" user_see_share $USERNAME tmp
testit "$USERNAME sees valid-users-tmp" user_see_share $USERNAME valid-users-tmp
testit "force_user sees tmp" user_see_share force_user tmp
testit_expect_failure "force_user does not see valid-users-tmp" user_see_share force_user valid-users-tmp
