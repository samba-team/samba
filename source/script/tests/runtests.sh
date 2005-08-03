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

DOMAIN=SAMBA-TEST

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

rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $LOCKDIR $TMPDIR $LOGDIR $SOCKET_WRAPPER_DIR

export PREFIX_ABS CONFIGURATION CONFFILE PATH SOCKET_WRAPPER_DIR DOMAIN
export PRIVATEDIR LIBDIR PIDDIR LOCKDIR TMPDIR LOGDIR
export SRCDIR SCRIPTDIR

for testfile in `ls $SCRIPTDIR/t_*sh | sort`; do
	echo ">>>>>> Starting test driver `basename $testfile` <<<<<"
	sh $testfile
	if [ $? = 0 ]; then
		echo ">>>>> test ok <<<<<"
	else
		echo ">>>>> test failed <<<<<"
	fi
done

