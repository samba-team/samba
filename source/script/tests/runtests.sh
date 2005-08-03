#!/bin/sh

DOMAIN=SAMBA-TEST
export DOMAIN

if [ "x$1" == "x" ]; then
	echo "$0 <directory>"
	exit 1
fi

PREFIX=`echo $1 | sed s+//+/+`

mkdir -p $PREFIX || exit $?
OLD_PWD=`pwd`
cd $PREFIX || exit $?
export PREFIX_ABS=`pwd`
cd $OLD_PWD

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

export PREFIX_ABS CONFIGURATION CONFFILE PATH SOCKET_WRAPPER_DIR
export PRIVATEDIR LIBDIR PIDDIR LOCKDIR TMPDIR LOGDIR

cd script/tests
for testfile in t_*sh; do
	sh $testfile
done

