#!/bin/sh
#
# Blackbox test for disk-free, quota, and their interaction
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_dfree_quota.sh SERVER DOMAIN USERNAME PASSWORD LOCAL_PATH SMBCLIENT SMBCQUOTAS
EOF
exit 1;
fi

SERVER=$1
DOMAIN=$2
USERNAME=$3
PASSWORD=$4
ENVDIR=`dirname $5`
WORKDIR=$5/dfree
smbclient=$6
smbcquotas=$7
shift 7
failed=0

CONFFILE=$ENVDIR/lib/dfq.conf

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

sighup_smbd() {
    kill -HUP -`cat $ENVDIR/pid/smbd.pid`
}

conf_lines() {
    local uid
    local gid
    uid=$(id -u $USERNAME)
    gid=$(id -g $USERNAME)
cat <<ABC
conf1:df:block size = 512:disk free = 10:disk size = 20
conf2:df:block size = 1024:disk free = 10:disk size = 20
conf3:df:block size = 4096:disk free = 750:disk size = 281474976710656
confq1:u$uid:block size = 4096:hard limit = 750:soft limit = 1000:cur blocks = 10
confdfq1:df:block size = 4096:disk free = 10:disk size = 20
confdfq1:u$uid:block size = 4096:hard limit = 750:soft limit = 1000:cur blocks = 10
confdfq2:df:block size = 4096:disk free = 10:disk size = 20
confdfq2:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 37
confdfq3:df:block size = 4096:disk free = 10:disk size = 80
confdfq3:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 0
confdfq4:df:block size = 4096:disk free = 10:disk size = 80
confdfq4:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 37
edquot:df:block size = 4096:disk free = 10:disk size = 80
edquot:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 41:edquot = 1
slimit:df:block size = 4096:disk free = 10:disk size = 80
slimit:u$uid:block size = 4096:hard limit = 44:soft limit = 40:cur blocks = 42
hlimit:df:block size = 4096:disk free = 10:disk size = 80
hlimit:u$uid:block size = 4096:hard limit = 44:soft limit = 0:cur blocks = 45
islimit:df:block size = 4096:disk free = 10:disk size = 80
islimit:u$uid:block size = 4096:hard limit = 44:soft limit = 40:cur blocks = 37:inode soft limit = 30:inode hard limit = 35:cur inodes = 32
ihlimit:df:block size = 4096:disk free = 10:disk size = 80
ihlimit:u$uid:block size = 4096:hard limit = 44:soft limit = 40:cur blocks = 37:inode soft limit = 0:inode hard limit = 35:cur inodes = 36
trygrp1:df:block size = 4096:disk free = 10:disk size = 80
trygrp1:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 41:err = 1
trygrp1:g$gid:block size = 4096:hard limit = 60:soft limit = 60:cur blocks = 55
trygrp2:df:block size = 4096:disk free = 10:disk size = 80
trygrp2:u$uid:block size = 4096:hard limit = 0:soft limit = 0:cur blocks = 41
trygrp2:g$gid:block size = 4096:hard limit = 60:soft limit = 60:cur blocks = 56
ABC
}

setup_1_conf() {
    conf_name="$1"
    subdir="$2"
    absdir=`realpath $WORKDIR/$subdir`
    conf_lines | sed -rn "s/^$conf_name:(.*)/\1/p" | tr ":" "\n" | \
    awk  -F '=' -v atdir=$absdir 'NF==1 {section=$1} NF==2 {sub(/\s*$/, "", $1); printf "\tfake_dfq:%s/%s/%s =%s\n", section, $1, atdir, $2}'
}

setup_conf() {
    rm $CONFFILE
    touch $CONFFILE

    until [ -z "$1" ]
    do
        setup_1_conf $1 $2 >> $CONFFILE
        shift
        shift
    done
    sighup_smbd
    #let it load...
    sleep .5
}


test_smbclient_dfree() {
	name="$1"
	dir="$2"
    confs="$3"
    expected="$4"
	shift
    shift
    shift
    shift
    subunit_start_test "$name"
    setup_conf $confs
	output=$($VALGRIND $smbclient //$SERVER/dfq -c "cd $dir; l" $@ 2>&1)
    status=$?
    if [ "$status" = "0" ]; then
		received=$(echo "$output" | awk '/blocks of size/ {print $1, $5, $6}')
		if [ "$expected" = "$received" ]; then
			subunit_pass_test "$name"
		else
			echo "$output" | subunit_fail_test "$name"
		fi
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

test_smbcquotas() {
	name="$1"
    conf="$2"
    user="$3"
    expected="$4"
	shift
    shift
    shift
    shift
	subunit_start_test "$name"
    setup_conf "$conf" "."
	output=$($VALGRIND $smbcquotas //$SERVER/dfq $@ 2>/dev/null | tr '\\' '/')
	status=$?
	if [ "$status" = "0" ]; then
		received=$(echo "$output" | awk "/$SERVER\\/$user/ {printf \"%s%s%s\", \$3, \$4, \$5}")
		if [ "$expected" = "$received" ]; then
			subunit_pass_test "$name"
		else
			echo "$output" | subunit_fail_test "$name"
		fi
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

#basic disk-free tests
test_smbclient_dfree "Test dfree share root SMB3 no quota" "." "conf1 ." "10 1024. 5" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree subdir SMB3 no quota" "subdir1" "conf1 . conf2 subdir1" "20 1024. 10" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree subdir NT1 no quota" "subdir1" "conf1 . conf2 subdir1" "10 1024. 5" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=NT1 || failed=`expr $failed + 1`
test_smbclient_dfree "Test large disk" "." "conf3 ." "1125899906842624 1024. 3000" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#basic quota test (SMB1 only)
test_smbcquotas "Test user quota" confq1 $USERNAME "40960/4096000/3072000" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=NT1 || failed=`expr $failed + 1`

#quota limit > disk size, remaining quota > disk free
test_smbclient_dfree "Test dfree share root df vs quota case 1" "." "confdfq1 ." "80 1024. 40" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#quota limit > disk size, remaining quota < disk free
test_smbclient_dfree "Test dfree share root df vs quota case 2" "." "confdfq2 ." "80 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#quota limit < disk size, remaining quota > disk free
test_smbclient_dfree "Test dfree share root df vs quota case 3" "." "confdfq3 ." "160 1024. 40" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#quota limit < disk size, remaining quota < disk free
test_smbclient_dfree "Test dfree share root df vs quota case 4" "." "confdfq4 ." "160 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree subdir df vs quota case 4" "subdir1" "confdfq4 subdir1" "160 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

#quota-->disk free special cases
test_smbclient_dfree "Test quota->dfree edquot" "subdir1" "edquot subdir1" "164 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree soft limit" "subdir1" "slimit subdir1" "168 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree hard limit" "subdir1" "hlimit subdir1" "180 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree inode soft limit" "subdir1" "islimit subdir1" "148 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree inode hard limit" "subdir1" "ihlimit subdir1" "148 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree err try group" "subdir1" "trygrp1 subdir1" "240 1024. 20" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree no-quota try group" "subdir1" "trygrp2 subdir1" "240 1024. 16" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

setup_conf
exit $failed
