#!/bin/sh

if [ $# -lt 2 ]; then
	echo "$0 <directory> <all | quick> [-t <smbtorture4>] [-s <shrdir>] " \
	     "[-c <custom conf>]"
	exit 1
fi

##
## Setup the required args
##
DIRECTORY=$1; shift;
SUBTESTS=$1; shift;

##
## Parse oprtional args
##
while getopts s:c:t: f
do
    case $f in
	t)	SMBTORTURE4=$OPTARG;;
	s)	ALT_SHRDIR_ARG=$OPTARG;;
	c)      CUSTOM_CONF_ARG=$OPTARG;;
    esac
done

echo "Running selftest with the following"
echo "Selftest Directory: $DIRECTORY"
echo "Subtests to Run: $SUBTESTS"
echo "smbtorture4 Path: $SMBTORTURE4"
echo "Alternative Share Dir: $ALT_SHRDIR_ARG"
echo "Custom Configuration: $CUSTOM_CONF_ARG"

if [ $CUSTOM_CONF_ARG ]; then
    INCLUDE_CUSTOM_CONF="include = $CUSTOM_CONF_ARG"
fi

##
## create the test directory layout
##
PREFIX=`echo $DIRECTORY | sed s+//+/+`
printf "%s" "CREATE TEST ENVIRONMENT IN '$PREFIX'"...
/bin/rm -rf $PREFIX
if [ -e "$PREFIX" ]; then
	echo "***"
	echo "*** Failed to delete test environment $PREFIX"
	echo "*** Was a previous run done as root ?"
	echo "***"
	exit 1
fi

##
## create the test directory
##
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
if [ ! "x$USER" = "x" ]; then
    USERNAME=$USER
else
    if [ ! "x$LOGNAME" = "x" ]; then
        USERNAME=$LOGNAME
    else
        USERNAME=`PATH=/usr/ucb:$PATH whoami || id -un`
    fi
fi
USERID=`PATH=/usr/ucb:$PATH id | cut -d ' ' -f1 | sed -e 's/uid=\([0-9]*\).*/\1/g'`
GROUPID=`PATH=/usr/ucb:$PATH id | cut -d ' ' -f2 | sed -e 's/gid=\([0-9]*\).*/\1/g'`
PASSWORD=testPw

SRCDIR="`dirname $0`/../.."
BINDIR="`pwd`/bin"
SCRIPTDIR=$SRCDIR/script/tests
LIBDIR=$PREFIX_ABS/lib
PIDDIR=$PREFIX_ABS/pid
CONFFILE=$LIBDIR/client.conf
SAMBA4CONFFILE=$LIBDIR/samba4client.conf
SERVERCONFFILE=$LIBDIR/server.conf
COMMONCONFFILE=$LIBDIR/common.conf
PRIVATEDIR=$PREFIX_ABS/private
NCALRPCDIR=$PREFIX_ABS/ncalrpc
LOCKDIR=$PREFIX_ABS/lockdir
EVENTLOGDIR=$LOCKDIR/eventlog
LOGDIR=$PREFIX_ABS/logs
SOCKET_WRAPPER_DIR=$PREFIX_ABS/sw
CONFIGURATION="--configfile $CONFFILE"
SAMBA4CONFIGURATION="-s $SAMBA4CONFFILE"
NSS_WRAPPER_PASSWD="$PRIVATEDIR/passwd"
NSS_WRAPPER_GROUP="$PRIVATEDIR/group"
WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbindd
WINBINDD_PRIV_PIPE_DIR=$LOCKDIR/winbindd_privileged
TEST_DIRECTORY=$DIRECTORY
LOCAL_PATH=$SHRDIR

export PREFIX PREFIX_ABS
export CONFIGURATION CONFFILE SAMBA4CONFIGURATION SAMBA4CONFFILE
export PATH SOCKET_WRAPPER_DIR DOMAIN
export PRIVATEDIR LIBDIR PIDDIR LOCKDIR LOGDIR SERVERCONFFILE
export SRCDIR SCRIPTDIR BINDIR
export USERNAME PASSWORD
export WORKGROUP SERVER SERVER_IP
export NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP
export WINBINDD_SOCKET_DIR WINBINDD_PRIV_PIPE_DIR
export TEST_DIRECTORY
export LOCAL_PATH

PATH=bin:$PATH
export PATH

if [ $SMBTORTURE4 ]; then
    SAMBA4BINDIR=`dirname $SMBTORTURE4`
fi

SAMBA4SHAREDDIR="$SAMBA4BINDIR/shared"

export SAMBA4SHAREDDIR
export SMBTORTURE4

if [ -z "$LIB_PATH_VAR" ] ; then
	echo "Warning: LIB_PATH_VAR not set. Using best guess LD_LIBRARY_PATH." >&2
	LIB_PATH_VAR=LD_LIBRARY_PATH
	export LIB_PATH_VAR
fi

eval $LIB_PATH_VAR=$BINDIR:$SAMBA4SHAREDDIR:\$$LIB_PATH_VAR
export $LIB_PATH_VAR

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


mkdir -p $PRIVATEDIR $NCALRPCDIR $LIBDIR $PIDDIR $LOCKDIR $LOGDIR $EVENTLOGDIR
mkdir -p $SOCKET_WRAPPER_DIR
mkdir -p $WINBINDD_SOCKET_DIR
chmod 755 $WINBINDD_SOCKET_DIR

##
## Create an alternate shrdir if one was specified.
##
if [ $ALT_SHRDIR_ARG ]; then
    ALT_SHRDIR=`echo $ALT_SHRDIR_ARG | sed s+//+/+`
    mkdir -p $ALT_SHRDIR || exit $?
    OLD_PWD=`pwd`
    cd $ALT_SHRDIR || exit $?
    SHRDIR=`pwd`
    cd $OLD_PWD
    /bin/rm -rf $SHRDIR/*
else
    SHRDIR=$PREFIX_ABS/tmp
    mkdir -p $SHRDIR
fi
chmod 777 $SHRDIR

##
## Create driver share dirs
##
mkdir $SHRDIR/W32X86
mkdir $SHRDIR/x64

##
## Create a read-only directory.
##
RO_SHRDIR=`echo $SHRDIR | sed -e 's:/[^/]*$::'`
RO_SHRDIR=$RO_SHRDIR/root-tmp
mkdir -p $RO_SHRDIR
chmod 755 $RO_SHRDIR
touch $RO_SHRDIR/unreadable_file
chmod 600 $RO_SHRDIR/unreadable_file
##
## Create an MS-DFS root share.
##
MSDFS_SHRDIR=`echo $SHRDIR | sed -e 's:/[^/]*$::'`
MSDFS_SHRDIR=$MSDFS_SHRDIR/msdfsshare
mkdir -p $MSDFS_SHRDIR
chmod 777 $MSDFS_SHRDIR
mkdir -p $MSDFS_SHRDIR/deeppath
chmod 777 $MSDFS_SHRDIR/deeppath
## Create something visible in the target.
touch $RO_SHRDIR/msdfs-target
chmod 666 $RO_SHRDIR/msdfs-target
ln -s msdfs:$SERVER_IP\\ro-tmp $MSDFS_SHRDIR/msdfs-src1
ln -s msdfs:$SERVER_IP\\ro-tmp $MSDFS_SHRDIR/deeppath/msdfs-src2

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
	modules dir = $SRCDIR/bin/modules
	ncalrpc dir = $NCALRPCDIR
EOF

##
## calculate uids and gids
##

if [ $USERID -lt $(( 0xffff - 2 )) ]; then
	MAXUID=0xffff
else
	MAXUID=$USERID
fi

UID_ROOT=$(( $MAXUID - 1 ))
UID_NOBODY=$(( MAXUID - 2 ))

if [ $GROUPID -lt $(( 0xffff - 3 )) ]; then
	MAXGID=0xffff
else
	MAXGID=$GROUPID
fi

GID_NOBODY=$(( $MAXGID - 3 ))
GID_NOGROUP=$(( $MAXGID - 2 ))
GID_ROOT=$(( $MAXGID - 1 ))

cat >$SERVERCONFFILE<<EOF
[global]
	netbios name = $SERVER
	interfaces = $SERVER_IP/8
	bind interfaces only = yes
	panic action = $SCRIPTDIR/gdb_backtrace %d %\$(MAKE_TEST_BINARY)
	include = $COMMONCONFFILE

	state directory = $LOCKDIR
	cache directory = $LOCKDIR

	passdb backend = tdbsam

	domain master = yes
	domain logons = yes
	lanman auth = yes
	time server = yes

	add user script =		$PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --passwd_path $NSS_WRAPPER_PASSWD --type passwd --action add --name %u --gid $GID_NOGROUP
	add group script =		$PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --group_path  $NSS_WRAPPER_GROUP  --type group  --action add --name %g
	add user to group script =	$PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --group_path  $NSS_WRAPPER_GROUP  --type member --action add --name %g --member %u --passwd_path $NSS_WRAPPER_PASSWD
	add machine script =		$PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --passwd_path $NSS_WRAPPER_PASSWD --type passwd --action add --name %u --gid $GID_NOGROUP
	delete user script =		$PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --passwd_path $NSS_WRAPPER_PASSWD --type passwd --action delete --name %u
	delete group script =		$PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --group_path  $NSS_WRAPPER_GROUP  --type group  --action delete --name %g
	delete user from group script = $PERL $SRCDIR/../lib/nss_wrapper/nss_wrapper.pl --group_path  $NSS_WRAPPER_GROUP  --type member --action delete --name %g --member %u --passwd_path $NSS_WRAPPER_PASSWD

	addprinter command =            $PERL $SRCDIR/../source3/script/tests/printing/modprinter.pl -a -s $SERVERCONFFILE --
	deleteprinter command =         $PERL $SRCDIR/../source3/script/tests/printing/modprinter.pl -d -s $SERVERCONFFILE --

	eventlog list = "dns server" application
	kernel oplocks = no
	kernel change notify = no

	syslog = no
	printing = bsd
	printcap name = /dev/null

	winbindd:socket dir = $WINBINDD_SOCKET_DIR
	idmap uid = 100000-200000
	idmap gid = 100000-200000
	winbind enum users = yes
	winbind enum groups = yes

#	min receivefile size = 4000

	read only = no
	smbd:sharedelay = 100000
#	smbd:writetimeupdatedelay = 500000
	map hidden = no
	map system = no
	map readonly = no
	store dos attributes = yes
	create mask = 755
	vfs objects = $BINDIR/xattr_tdb.so $BINDIR/streams_depot.so

	printing = vlp
	print command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb print %p %s
	lpq command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb lpq %p
	lp rm command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb lprm %p %j
	lp pause command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb lppause %p %j
	lp resume command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb lpresume %p %j
	queue pause command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb queuepause %p
	queue resume command = $BINDIR/vlp tdbfile=$LOCKDIR/vlp.tdb queueresume %p
	lpq cache time = 0

	#Include user defined custom parameters if set
	$INCLUDE_CUSTOM_CONF

[tmp]
	path = $SHRDIR
[ro-tmp]
	path = $RO_SHRDIR
	guest ok = yes
[msdfs-share]
	path = $MSDFS_SHRDIR
	msdfs root = yes
	guest ok = yes
[hideunread]
	copy = tmp
	hide unreadable = yes
[tmpcase]
	copy = tmp
	case sensitive = yes
[hideunwrite]
	copy = tmp
	hide unwriteable files = yes
[print1]
	copy = tmp
	printable = yes

[print2]
	copy = print1
[print3]
	copy = print1
[print4]
	copy = print1
[print$]
	copy = tmp
EOF

##
## create a test account
##

cat >$NSS_WRAPPER_PASSWD<<EOF
nobody:x:$UID_NOBODY:$GID_NOBODY:nobody gecos:$PREFIX_ABS:/bin/false
$USERNAME:x:$USERID:$GROUPID:$USERNAME gecos:$PREFIX_ABS:/bin/false
EOF

cat >$NSS_WRAPPER_GROUP<<EOF
nobody:x:$GID_NOBODY:
nogroup:x:$GID_NOGROUP:nobody
$USERNAME-group:x:$GROUPID:
EOF

##
## add fake root user when not running as root
##
if [ "$USERID" != 0 ]; then

cat >>$NSS_WRAPPER_PASSWD<<EOF
root:x:$UID_ROOT:$GID_ROOT:root gecos:$PREFIX_ABS:/bin/false
EOF

cat >>$NSS_WRAPPER_GROUP<<EOF
root:x:$GID_ROOT:
EOF

fi

touch $EVENTLOGDIR/dns\ server.tdb
touch $EVENTLOGDIR/application.tdb

MAKE_TEST_BINARY="bin/smbpasswd"
export MAKE_TEST_BINARY

(echo $PASSWORD; echo $PASSWORD) | \
	bin/smbpasswd -c $SERVERCONFFILE -L -s -a $USERNAME >/dev/null || exit 1

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
TORTURE4_OPTIONS="$TORTURE4_OPTIONS --option=torture:localdir=$SHRDIR"
TORTURE4_OPTIONS="$TORTURE4_OPTIONS --option=torture:winbindd_netbios_name=$SERVER"
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
