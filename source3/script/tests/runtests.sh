#!/bin/sh

if [ "x$1" == "x" ]; then
	echo "$0 <directory>"
	exit 1
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

SRCDIR=`pwd`
SCRIPTDIR=$SRCDIR/script/tests
TMPDIR=$PREFIX_ABS/tmp
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
export PRIVATEDIR LIBDIR PIDDIR LOCKDIR TMPDIR LOGDIR
export SRCDIR SCRIPTDIR

## 
## create the test directory layout
##

/bin/rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $LOCKDIR $TMPDIR $LOGDIR $SOCKET_WRAPPER_DIR

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

	interfaces = lo
	bind interfaces only = yes

	panic action = $PREFIX_ABS/script/tests/gdb_backtrace /proc/%d/exe %d
EOF

##
## ready to go...now loop through the tests
##

for testfile in `ls $SCRIPTDIR/t_*sh | sort`; do
	echo ">>>>>> Starting test driver `basename $testfile` <<<<<"
	sh $testfile
	if [ $? = 0 ]; then
		echo ">>>>> test ok <<<<<"
	else
		echo ">>>>> test failed <<<<<"
	fi
done

