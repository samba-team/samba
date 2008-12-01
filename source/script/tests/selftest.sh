#!/bin/sh

if [ $# != 3 ]; then
	echo "$0 <directory> <all | quick> <smbtorture4>"
	exit 1
fi

SMBTORTURE4=$3
SUBTESTS=$2

##
## create the test directory
##
PREFIX=`echo $1 | sed s+//+/+`
mkdir -p $PREFIX || exit $?
OLD_PWD=`pwd`
cd $PREFIX || exit $?
PREFIX_ABS=`pwd`
cd $OLD_PWD

if [ -z "$TORTURE_MAXTIME" ]; then
    TORTURE_MAXTIME=300
fi
export TORTURE_MAXTIME

##
## setup the various environment variables we need
##

WORKGROUP=SAMBA-TEST
SERVER=localhost2
SERVER_IP=127.0.0.2
USERNAME=`PATH=/usr/ucb:$PATH whoami`
USERID=`PATH=/usr/ucb:$PATH id | cut -d ' ' -f1 | sed -e 's/uid=\([0-9]*\).*/\1/g'`
GROUPID=`PATH=/usr/ucb:$PATH id | cut -d ' ' -f2 | sed -e 's/gid=\([0-9]*\).*/\1/g'`
PASSWORD=test

SRCDIR="`dirname $0`/../.."
BINDIR="`pwd`/bin"
SCRIPTDIR=$SRCDIR/script/tests
SHRDIR=$PREFIX_ABS/tmp
LIBDIR=$PREFIX_ABS/lib
PIDDIR=$PREFIX_ABS/pid
CONFFILE=$LIBDIR/client.conf
SAMBA4CONFFILE=$LIBDIR/samba4client.conf
SERVERCONFFILE=$LIBDIR/server.conf
COMMONCONFFILE=$LIBDIR/common.conf
PRIVATEDIR=$PREFIX_ABS/private
LOCKDIR=$PREFIX_ABS/lockdir
LOGDIR=$PREFIX_ABS/logs
SOCKET_WRAPPER_DIR=$PREFIX/sw
CONFIGURATION="--configfile $CONFFILE"
SAMBA4CONFIGURATION="-s $SAMBA4CONFFILE"
NSS_WRAPPER_PASSWD="$PRIVATEDIR/passwd"
NSS_WRAPPER_GROUP="$PRIVATEDIR/group"
WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbindd
WINBINDD_PRIV_PIPE_DIR=$LOCKDIR/winbindd_privileged

export PREFIX PREFIX_ABS
export CONFIGURATION CONFFILE SAMBA4CONFIGURATION SAMBA4CONFFILE
export PATH SOCKET_WRAPPER_DIR DOMAIN
export PRIVATEDIR LIBDIR PIDDIR LOCKDIR LOGDIR SERVERCONFFILE
export SRCDIR SCRIPTDIR BINDIR
export USERNAME PASSWORD
export WORKGROUP SERVER SERVER_IP
export NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP
export WINBINDD_SOCKET_DIR WINBINDD_PRIV_PIPE_DIR

PATH=bin:$PATH
export PATH

if test x"$LD_LIBRARY_PATH" != x""; then
	LD_LIBRARY_PATH="$BINDIR:$LD_LIBRARY_PATH"
else
	LD_LIBRARY_PATH="$BINDIR"
fi
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH

SAMBA4BINDIR=`dirname $SMBTORTURE4`
SAMBA4SHAREDDIR="$SAMBA4BINDIR/shared"

export SAMBA4SHAREDDIR
export SMBTORTURE4

##
## verify that we were built with --enable-socket-wrapper
##

if test "x`smbd -b | grep SOCKET_WRAPPER`" = "x"; then
	echo "***"
	echo "*** You must include --enable-socket-wrapper when compiling Samba"
	echo "*** in order to execute 'make test'.  Exiting...."
	echo "***"
	exit 1
fi

if test "x`smbd -b | grep NSS_WRAPPER`" = "x"; then
	echo "***"
	echo "*** You must include --enable-nss-wrapper when compiling Samba"
	echo "*** in order to execute 'make test'.  Exiting...."
	echo "***"
	exit 1
fi


## 
## create the test directory layout
##
printf "%s" "CREATE TEST ENVIRONMENT IN '$PREFIX'"...
/bin/rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $LOCKDIR $LOGDIR
mkdir -p $SOCKET_WRAPPER_DIR
mkdir -p $WINBINDD_SOCKET_DIR
chmod 755 $WINBINDD_SOCKET_DIR
mkdir -p $PREFIX_ABS/tmp
chmod 777 $PREFIX_ABS/tmp

##
## Create the common config include file with the basic settings
##

cat >$COMMONCONFFILE<<EOF
	workgroup = $WORKGROUP

	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	lock directory = $LOCKDIR
	log file = $LOGDIR/log.%m
	log level = 0

	name resolve order = bcast
EOF

TORTURE_INTERFACES='127.0.0.6/8,127.0.0.7/8,127.0.0.8/8,127.0.0.9/8,127.0.0.10/8,127.0.0.11/8'

cat >$CONFFILE<<EOF
[global]
	netbios name = TORTURE_6
	interfaces = $TORTURE_INTERFACES
	panic action = $SCRIPTDIR/gdb_backtrace %d %\$(MAKE_TEST_BINARY)
	include = $COMMONCONFFILE

	passdb backend = tdbsam
EOF

cat >$SAMBA4CONFFILE<<EOF
[global]
	netbios name = TORTURE_6
	interfaces = $TORTURE_INTERFACES
	panic action = $SCRIPTDIR/gdb_backtrace %PID% %PROG%
	include = $COMMONCONFFILE
EOF

cat >$SERVERCONFFILE<<EOF
[global]
	netbios name = $SERVER
	interfaces = $SERVER_IP/8
	bind interfaces only = yes
	panic action = $SCRIPTDIR/gdb_backtrace %d %\$(MAKE_TEST_BINARY)
	include = $COMMONCONFFILE

	passdb backend = tdbsam

	domain master = yes
	domain logons = yes
	time server = yes

	add user script = $PERL $SRCDIR/lib/nss_wrapper/nss_wrapper.pl --path $NSS_WRAPPER_PASSWD --type passwd --action add --name %u
	add machine script = $PERL $SRCDIR/lib/nss_wrapper/nss_wrapper.pl --path $NSS_WRAPPER_PASSWD --type passwd --action add --name %u
	delete user script = $PERL $SRCDIR/lib/nss_wrapper/nss_wrapper.pl --path $NSS_WRAPPER_PASSWD --type passwd --action delete --name %u

	kernel oplocks = no
	kernel change notify = no

	syslog = no
	printing = bsd
	printcap name = /dev/null

	winbindd:socket dir = $WINBINDD_SOCKET_DIR
	idmap uid = 100000-200000
	idmap gid = 100000-200000

#	min receivefile size = 4000

[tmp]
	path = $PREFIX_ABS/tmp
	read only = no
	smbd:sharedelay = 100000
	smbd:writetimeupdatedelay = 500000
	map hidden = yes
	map system = yes
	create mask = 755
	vfs objects = $BINDIR/xattr_tdb.so $BINDIR/streams_depot.so
[hideunread]
	copy = tmp
	hide unreadable = yes
[hideunwrite]
	copy = tmp
	hide unwriteable files = yes
[print1]
	copy = tmp
	printable = yes
	printing = test
[print2]
	copy = print1
[print3]
	copy = print1
[print4]
	copy = print1
EOF

##
## create a test account
##

cat >$NSS_WRAPPER_PASSWD<<EOF
nobody:x:65534:65533:nobody gecos:$PREFIX_ABS:/bin/false
$USERNAME:x:$USERID:$GROUPID:$USERNAME gecos:$PREFIX_ABS:/bin/false
EOF

cat >$NSS_WRAPPER_GROUP<<EOF
nobody:x:65533:
nogroup:x:65534:nobody
$USERNAME-group:x:$GROUPID:
EOF

MAKE_TEST_BINARY="bin/smbpasswd"
export MAKE_TEST_BINARY

(echo $PASSWORD; echo $PASSWORD) | \
	bin/smbpasswd -c $CONFFILE -L -s -a $USERNAME >/dev/null || exit 1

echo "DONE";

MAKE_TEST_BINARY=""

SERVER_TEST_FIFO="$PREFIX/server_test.fifo"
export SERVER_TEST_FIFO
NMBD_TEST_LOG="$PREFIX/nmbd_test.log"
export NMBD_TEST_LOG
WINBINDD_TEST_LOG="$PREFIX/winbindd_test.log"
export WINBINDD_TEST_LOG
SMBD_TEST_LOG="$PREFIX/smbd_test.log"
export SMBD_TEST_LOG

# start off with 0 failures
failed=0
export failed

. $SCRIPTDIR/test_functions.sh

SOCKET_WRAPPER_DEFAULT_IFACE=2
export SOCKET_WRAPPER_DEFAULT_IFACE
samba3_check_or_start


# ensure any one smbtorture call doesn't run too long
# and smbtorture will use 127.0.0.6 as source address by default
SOCKET_WRAPPER_DEFAULT_IFACE=6
export SOCKET_WRAPPER_DEFAULT_IFACE
TORTURE4_OPTIONS="$SAMBA4CONFIGURATION"
TORTURE4_OPTIONS="$TORTURE4_OPTIONS --maximum-runtime=$TORTURE_MAXTIME"
TORTURE4_OPTIONS="$TORTURE4_OPTIONS --target=samba3"
TORTURE4_OPTIONS="$TORTURE4_OPTIONS --option=torture:localdir=$PREFIX_ABS/tmp"
export TORTURE4_OPTIONS

if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
	TORTURE4_OPTIONS="$TORTURE4_OPTIONS --option=torture:progress=no"
fi


##
## ready to go...now loop through the tests
##

START=`date`
(
 # give time for nbt server to register its names
 echo "delaying for nbt name registration"
 sleep 10
 # This will return quickly when things are up, but be slow if we need to wait for (eg) SSL init 
 MAKE_TEST_BINARY="bin/nmblookup"
 bin/nmblookup $CONFIGURATION -U $SERVER_IP __SAMBA__
 bin/nmblookup $CONFIGURATION __SAMBA__
 bin/nmblookup $CONFIGURATION -U 127.255.255.255 __SAMBA__
 bin/nmblookup $CONFIGURATION -U $SERVER_IP $SERVER
 bin/nmblookup $CONFIGURATION $SERVER
 # make sure smbd is also up set
 echo "wait for smbd"
 MAKE_TEST_BINARY="bin/smbclient"
 bin/smbclient $CONFIGURATION -L $SERVER_IP -U% -p 139 | head -2
 bin/smbclient $CONFIGURATION -L $SERVER_IP -U% -p 139 | head -2
 MAKE_TEST_BINARY=""

 failed=0

 . $SCRIPTDIR/tests_$SUBTESTS.sh
 exit $failed
)
failed=$?

samba3_stop_sig_term

END=`date`
echo "START: $START ($0)";
echo "END:   $END ($0)";

# if there were any valgrind failures, show them
count=`find $PREFIX -name 'valgrind.log*' | wc -l`
if [ "$count" != 0 ]; then
    for f in $PREFIX/valgrind.log*; do
	if [ -s $f ]; then
	    echo "VALGRIND FAILURE";
	    failed=`expr $failed + 1`
	    cat $f
	fi
    done
fi

sleep 2
samba3_stop_sig_kill

teststatus $0 $failed
