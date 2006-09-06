#!/bin/sh

PIDL_ARGS="--outputdir ${srcdir}/librpc/gen_ndr --header --ndr-parser --"
PIDL_EXTRA_ARGS="$*"

oldpwd=`pwd`
cd ${srcdir}

[ -d librpc/gen_ndr ] || mkdir -p librpc/gen_ndr || exit 1

PIDL="$PERL pidl/pidl ${PIDL_ARGS} ${PIDL_EXTRA_ARGS}"

list=""
for f in ${IDL_FILES}; do
	basename=`basename $f .idl`
	ndr="librpc/gen_ndr/ndr_$basename.c"

	if [ -f $ndr ]; then
		if [ "x`find librpc/idl/$f -newer $ndr -print`" = "xlibrpc/idl/$f" ]; then
			list="$list librpc/idl/$f"
		fi
	else 
		list="$list librpc/idl/$f"
	fi
done

if [ "x$list" != x ]; then
	$PIDL $list || exit 1
fi

for f in librpc/gen_ndr/ndr_*.c; do
	cat $f | sed 's/^static //g' | sed 's/^_PUBLIC_ //g' > $f.new
	/bin/mv -f $f.new $f
done

touch librpc/gen_ndr/ndr_dcerpc.h

cd ${oldpwd}

exit 0
