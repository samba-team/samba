#!/bin/sh

if [ "x$1" = "x" ]; then
	echo "$0 <directory>"
	exit 1
fi

if [ $# = 2 ]; then
	testnum=$2
fi

##
## create the test directory
##
PREFIX=`echo $1 | sed s+//+/+`
mkdir -p $PREFIX || exit $?
OLD_PWD=`pwd`
cd $PREFIX || exit $?
export PREFIX_ABS=`pwd`
cd $OLD_PWD

##
## setup the various environment variables we need
##

USERNAME=`whoami`
PASSWORD=test

SRCDIR=`pwd`
SCRIPTDIR=$SRCDIR/script/tests
SHRDIR=$PREFIX_ABS/tmp
LIBDIR=$PREFIX_ABS/lib
PIDDIR=$PREFIX_ABS/pid
CONFFILE=$LIBDIR/smb.conf
PRIVATEDIR=$PREFIX_ABS/private
LOCKDIR=$PREFIX_ABS/lockdir
LOGDIR=$PREFIX_ABS/logs
SOCKET_WRAPPER_DIR=$PREFIX_ABS/sockwrap
CONFIGURATION="-s $CONFFILE"
PATH=`pwd`/bin:$PATH

export PREFIX_ABS CONFIGURATION CONFFILE PATH SOCKET_WRAPPER_DIR DOMAIN
export PRIVATEDIR LIBDIR PIDDIR LOCKDIR LOGDIR
export SRCDIR SCRIPTDIR
export USERNAME PASSWORD


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

## 
## create the test directory layout
##

/bin/rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $LOCKDIR $LOGDIR $SOCKET_WRAPPER_DIR

##
## Create the common config include file with the basic settings
##

cat >$LIBDIR/common.conf<<EOF
	netbios name = LOCALHOST
	workgroup = SAMBA-TEST

	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	lock directory = $LOCKDIR
	log file = $LOGDIR/log.%m
	log level = 0

	passdb backend = tdbsam

	interfaces = lo
	bind interfaces only = yes

	panic action = $SCRIPTDIR/gdb_backtrace %d
EOF

cat >$LIBDIR/smb.conf<<EOF
[global]
	include = $LIBDIR/common.conf
EOF


##
## create a test account
##

(echo $PASSWORD; echo $PASSWORD) | smbpasswd -c $LIBDIR/smb.conf -L -s -a $USERNAME


##
## ready to go...now loop through the tests
##

if [ -f $SCRIPTDIR/t_$testnum.sh ]; then
	testfile=$SCRIPTDIR/t_$testnum.sh
	echo ">>>>>> Starting test driver `basename $testfile` <<<<<"
	sh $testfile
	if [ $? = 0 ]; then
		echo ">>>>> test ok <<<<<"
	else
		echo ">>>>> test failed <<<<<"
	fi

	exit 0
fi

for testfile in `ls $SCRIPTDIR/t_*sh | sort`; do
	echo " "
	echo ">>>>>> Starting test driver `basename $testfile` <<<<<"
	sh $testfile
	if [ $? = 0 ]; then
		echo ">>>>> test ok <<<<<"
	else
		echo ">>>>> test failed <<<<<"
	fi
done

