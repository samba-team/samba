#!/bin/sh
#
# Blackbox test for disk-free, quota, and their interaction
#

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_dfree_quota.sh SERVER DOMAIN USERNAME PASSWORD LOCAL_PATH SMBCLIENT SMBCQUOTAS SMBCACLS
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
smbcacls=$8
protocol=$9
shift 9
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
    uid1=$(id -u user1)
    uid2=$(id -u user2)
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
blksize:df:block size = 512:disk free = 614400:disk size = 614400
blksize:u$uid:block size = 1024:hard limit = 512000:soft limit = 0:cur blocks = 0
notenforce:df:block size = 4096:disk free = 10:disk size = 80
notenforce:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 37
notenforce:udflt:block size = 4096:qflags = 0
nfs:df:block size = 4096:disk free = 10:disk size = 80
nfs:u$uid:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 37
nfs:udflt:nosys = 1
confdfqp:df:block size = 4096:disk free = 10:disk size = 80
confdfqp:u$uid1:block size = 4096:hard limit = 40:soft limit = 40:cur blocks = 36
confdfqp:u$uid2:block size = 4096:hard limit = 41:soft limit = 41:cur blocks = 36
sgid:stat:sgid = 98765
sgid:u$uid:block size = 4096:hard limit = 0:soft limit = 0:cur blocks = 80
sgid:g98765:block size = 4096:hard limit = 50:soft limit = 50:cur blocks = 40
ABC
}

setup_1_conf() {
    conf_name="$1"
    subdir="$2"
    absdir=`readlink -f $WORKDIR/$subdir`
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
    share="$2"
    dir="$3"
    confs="$4"
    expected="$5"
    shift
    shift
    shift
    shift
    subunit_start_test "$name"
    setup_conf $confs
    output=$($VALGRIND $smbclient //$SERVER/$share -c "cd $dir; l" $@ 2>&1)
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

# Issue two queries to different directories in one session to test
# caching effects
test_smbclient_dfree_2() {
	name="$1"
	share="$2"
	dir1="$3"
	dir2="$4"
	confs="$5"
	expected="$6"
	subunit_start_test "$name"
	setup_conf $confs
	output=$($VALGRIND $smbclient //$SERVER/$share \
			   -c "cd $dir1; du; cd ..; cd $dir2 ; du" $@ 2>&1)
	status=$?
	if [ "$status" = "0" ]; then
		received=$(echo "$output" | \
				   awk '/blocks of size/ {print $1, $5, $6}' | \
				   tr '\n' ' ')
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
    proto="$5"
	shift
    shift
    shift
    shift
    shift
	subunit_start_test "$name"
    setup_conf "$conf" "."
    if [ "$proto"  = "smb2" ]; then
        mproto="-m SMB2"
    else
        mproto="-m SMB1"
    fi

	output=$($VALGRIND $smbcquotas $mproto //$SERVER/dfq $@ 2>/dev/null | tr '\\' '/')
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

if [ $protocol != "SMB3" ] && [ $protocol != "NT1" ]; then
	echo "unsupported protocol $protocol" | subunit_fail_test "Test dfree quota"
	failed=`expr $failed + 1`
fi

if [ $protocol = "NT1" ]; then
	setup_conf
	#basic quota test (SMB1 only)
	test_smbcquotas "Test user quota" confq1 $USERNAME "40960/4096000/3072000" "smb1" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=NT1 || failed=`expr $failed + 1`
	exit $failed
fi

#basic disk-free tests
test_smbclient_dfree "Test dfree share root SMB3 no quota" dfq "." "conf1 ." "10 1024. 5" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree subdir SMB3 no quota" dfq "subdir1" "conf1 . conf2 subdir1" "20 1024. 10" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test large disk" dfq "." "conf3 ." "1125899906842624 1024. 3000" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#basic quota test (SMB2 only)
test_smbcquotas "Test user quota" confq1 $USERNAME "40960/4096000/3072000" "smb2" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB2 || failed=`expr $failed + 1`

# Test dfree cache through queries in two different directories
test_smbclient_dfree_2 "Test dfree cache" dfq_cache "." "subdir1" \
		       "conf1 . conf2 subdir1" "10 1024. 5 20 1024. 10 " \
		       -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 \
	|| failed=`expr $failed + 1`

#quota limit > disk size, remaining quota > disk free
test_smbclient_dfree "Test dfree share root df vs quota case 1" dfq "." "confdfq1 ." "80 1024. 40" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#quota limit > disk size, remaining quota < disk free
test_smbclient_dfree "Test dfree share root df vs quota case 2" dfq "." "confdfq2 ." "80 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#quota limit < disk size, remaining quota > disk free
test_smbclient_dfree "Test dfree share root df vs quota case 3" dfq "." "confdfq3 ." "160 1024. 40" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
#quota limit < disk size, remaining quota < disk free
test_smbclient_dfree "Test dfree share root df vs quota case 4" dfq "." "confdfq4 ." "160 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree subdir df vs quota case 4" dfq "subdir1" "confdfq4 subdir1" "160 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

#quota-->disk free special cases
test_smbclient_dfree "Test quota->dfree soft limit" dfq "subdir1" "slimit subdir1" "168 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree hard limit" dfq "subdir1" "hlimit subdir1" "180 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree inode soft limit" dfq "subdir1" "islimit subdir1" "148 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree inode hard limit" dfq "subdir1" "ihlimit subdir1" "148 1024. 0" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree err try group" dfq "subdir1" "trygrp1 subdir1" "240 1024. 20" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test quota->dfree no-quota try group" dfq "subdir1" "trygrp2 subdir1" "240 1024. 16" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

# sgid on directory
test_smbclient_dfree "Test quota on sgid directory" dfq "subdir1" \
		     "sgid subdir1" "200 1024. 40" -U$USERNAME%$PASSWORD \
		     --option=clientmaxprotocol=SMB3 \
	|| failed=`expr $failed + 1`

#block size different in quota and df systems
test_smbclient_dfree "Test quota->dfree different block size" dfq "subdir1" "blksize subdir1" "307200 1024. 307200" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

#quota configured but not enforced
test_smbclient_dfree "Test dfree share root quota not enforced" dfq "." "notenforce ." "320 1024. 40" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

#FS quota not implemented (NFS case)
test_smbclient_dfree "Test dfree share root FS quota not implemented" dfq "." "nfs ." "160 1024. 12" -U$USERNAME%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

#test for dfree when owner is inherited
#setup two folders with different owners
rm -rf $WORKDIR/subdir3/*
for d in / subdir3
do
    $VALGRIND $smbcacls -U$USERNAME%$PASSWORD -D "ACL:$SERVER\user1:ALLOWED/0x0/FULL" //$SERVER/dfq $d > /dev/null 2>&1
    $VALGRIND $smbcacls -U$USERNAME%$PASSWORD -a "ACL:$SERVER\user1:ALLOWED/0x0/FULL" //$SERVER/dfq $d || failed=`expr $failed + 1`
    $VALGRIND $smbcacls -U$USERNAME%$PASSWORD -D "ACL:$SERVER\user2:ALLOWED/0x0/FULL" //$SERVER/dfq $d > /dev/null 2>&1
    $VALGRIND $smbcacls -U$USERNAME%$PASSWORD -a "ACL:$SERVER\user2:ALLOWED/0x0/FULL" //$SERVER/dfq $d || failed=`expr $failed + 1`
done

$VALGRIND $smbclient //$SERVER/dfq -c "cd subdir3; mkdir user1" -Uuser1%$PASSWORD --option=clientmaxprotocol=SMB3 > /dev/null 2>&1 || failed=`expr $failed + 1`
$VALGRIND $smbclient //$SERVER/dfq -c "cd subdir3; mkdir user2" -Uuser2%$PASSWORD --option=clientmaxprotocol=SMB3 > /dev/null 2>&1 || failed=`expr $failed + 1`
#test quotas
test_smbclient_dfree "Test dfree without inherit owner - user1 at user1" \
    dfq "subdir3/user1" "confdfqp subdir3/user1 confdfqp subdir3/user2" "160 1024. 16" \
    -Uuser1%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree without inherit owner - user1 at user2" \
    dfq "subdir3/user2" "confdfqp subdir3/user1 confdfqp subdir3/user2" "160 1024. 16" \
    -Uuser1%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree with inherit owner - user1 at user1" \
    dfq_owner "subdir3/user1" "confdfqp subdir3/user1 confdfqp subdir3/user2" "160 1024. 16" \
    -Uuser1%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`
test_smbclient_dfree "Test dfree with inherit owner - user1 at user2" \
    dfq_owner "subdir3/user2" "confdfqp subdir3/user1 confdfqp subdir3/user2" "164 1024. 20" \
    -Uuser1%$PASSWORD --option=clientmaxprotocol=SMB3 || failed=`expr $failed + 1`

setup_conf
exit $failed
