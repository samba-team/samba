#!/bin/sh

# Run this script to build samba from SVN.

## insert all possible names (only works with 
## autoconf 2.x
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
	echo "$0: need autoconf 2.53 or later to build samba from SVN" >&2
	exit 1
fi

echo "$0: running script/mkversion.sh"
./script/mkversion.sh || exit 1

rm -rf autom4te*.cache
rm -f configure include/config_tmp.h*

IPATHS="-I. -Ilib/replace"

echo "$0: running $AUTOHEADER $IPATHS"
$AUTOHEADER $IPATHS || exit 1

echo "$0: running $AUTOCONF $IPATHS"
$AUTOCONF $IPATHS || exit 1

rm -rf autom4te*.cache

# Run swig if it is available
SWIG=swig
SWIG_FILES="./scripting/python/misc.i ./auth/auth.i ./auth/credentials/credentials.i ./lib/talloc/talloc.i ./lib/ldb/ldb.i ./lib/registry/registry.i ./lib/tdb/tdb.i ./libcli/swig/libcli_smb.i ./libcli/swig/libcli_nbt.i ./librpc/rpc/dcerpc.i"
if which $SWIG >/dev/null 2>&1; then
	for I in $SWIG_FILES
	do
		echo "$0: running $SWIG for $I"
		swig -python -keyword $I
	done
fi

echo "Now run ./configure and then make."
exit 0
