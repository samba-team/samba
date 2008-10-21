#!/bin/sh

ARGS="--includedir=../librpc/idl --outputdir librpc/gen_ndr --header --ndr-parser --samba3-ndr-server --samba3-ndr-client $PIDL_ARGS --"
IDL_FILES="$*"

oldpwd=`pwd`
cd ${srcdir}

[ -d librpc/gen_ndr ] || mkdir -p librpc/gen_ndr || exit 1

PIDL="$PIDL $ARGS"

##
## Find newer files rather than rebuild all of them
##

list=""
for f in ${IDL_FILES}; do
	basename=`basename $f .idl`
	ndr="librpc/gen_ndr/ndr_$basename.c"

	if [ -f $ndr ]; then
		if [ "x`find $f -newer $ndr -print`" = "x$f" ]; then
			list="$list $f"
		fi
	else 
		list="$list $f"
	fi
done

##
## generate the ndr stubs
##

if [ "x$list" != x ]; then
	# echo "${PIDL} ${list}"
	$PIDL $list || exit 1
fi

cd ${oldpwd}

exit 0

