#!/bin/sh

# Run this script to build samba from GIT.


_exit() {
	echo $@ >&2
	cd ${OLD_DIR}
	exit 1
}

OLD_DIR=$(pwd)
BASE_DIR=$(dirname $0)
SCRIPT_NAME=$(basename $0)

cd ${BASE_DIR} || exit 1


while true; do
    case $1 in
	--version-file)
	    VERSION_FILE=$2
	    shift 2
	    ;;
	*)
	    break
	    ;;
    esac
done

## insert all possible names (only works with 
## autoconf 2.x)
TESTAUTOHEADER="autoheader autoheader-2.53 autoheader2.50 autoheader259 autoheader253"
TESTAUTOCONF="autoconf autoconf-2.53 autoconf2.50 autoconf259 autoconf253"

AUTOHEADERFOUND="0"
AUTOCONFFOUND="0"


##
## Look for autoheader 
##
for i in $TESTAUTOHEADER; do
	if which $i > /dev/null 2>&1; then
		if test `$i --version | head -n 1 | cut -d.  -f 2 | sed "s/[^0-9]//g"` -ge 53; then
			AUTOHEADER=$i
			AUTOHEADERFOUND="1"
			break
		fi
	fi
done

## 
## Look for autoconf
##

for i in $TESTAUTOCONF; do
	if which $i > /dev/null 2>&1; then
		if test `$i --version | head -n 1 | cut -d.  -f 2 | sed "s/[^0-9]//g"` -ge 53; then
			AUTOCONF=$i
			AUTOCONFFOUND="1"
			break
		fi
	fi
done


## 
## do we have it?
##
if test "$AUTOCONFFOUND" = "0" -o "$AUTOHEADERFOUND" = "0"; then
	_exit "$0: need autoconf 2.53 or later to build samba from GIT"
fi

echo "$0: running script/mkversion.sh"
./script/mkversion.sh $VERSION_FILE || exit 1

rm -rf autom4te*.cache
rm -f configure include/config.h*

IPATHS="-Im4 -I../m4 -I../lib/replace"

echo "$0: running $AUTOHEADER $IPATHS"
$AUTOHEADER $IPATHS || _exit "ERROR running autoheader"

echo "$0: running $AUTOCONF $IPATHS"
$AUTOCONF $IPATHS || _exit "ERROR running autoconf"

rm -rf autom4te*.cache

( cd ../examples/VFS || exit 1
  echo "$0: running $AUTOHEADER in ../examples/VFS/"
  $AUTOHEADER || exit 1
  echo "$0: running $AUTOCONF in ../examples/VFS/"
  $AUTOCONF || exit 1
  rm -rf autom4te*.cache
) || _exit "ERROR running autoheader/autoconf in examples/VFS"


if gcc -E tests/preproc-dummy.c -o /dev/null ;
then
    PIDL_OUTPUTDIR="autoconf/librpc/gen_ndr" CPP="gcc -E" PIDL=../pidl/pidl \
	srcdir=. ../librpc/build_idl.sh ../librpc/idl/*.idl
    PIDL_OUTPUTDIR="autoconf/librpc/gen_ndr" CPP="gcc -E" PIDL=../pidl/pidl \
	srcdir=. script/build_idl.sh librpc/idl/*.idl
else
   echo "Warning: Could not compile idl files in autogen, "
   echo "some autconf tests might not work properly"
fi

perl ../script/mkparamdefs.pl ../lib/param/param_functions.c --file autoconf/lib/param/param_local.h --generate-scope=LOCAL
perl ../script/mkparamdefs.pl ../lib/param/loadparm.c ../lib/param/param_functions.c --file autoconf/lib/param/param_global.h --generate-scope=GLOBAL
perl ../script/mkparamdefs.pl param/loadparm.c ../lib/param/param_functions.c --file autoconf/source3/param/param_global.h --generate-scope=GLOBAL
perl ../source4/script/mkproto.pl ../lib/param/loadparm.c ../lib/param/param_functions.c --public autoconf/lib/param/param_proto.h --private autoconf/lib/param/param_proto.h
perl ../script/mks3param.pl ../lib/param/loadparm.c ../lib/param/param_functions.c --file autoconf/lib/param/s3_param.h

echo "Now run ./configure (or ./configure.developer) and then make."

cd ${OLD_DIR}
exit 0

