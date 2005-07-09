#!/bin/sh

FULLBUILD=$1
shift 1
PIDL_EXTRA_ARGS="$*"

[ -d librpc/gen_ndr ] || mkdir -p librpc/gen_ndr || exit 1

PIDL="$PERL -Ibuild/pidl ./build/pidl/pidl --output librpc/gen_ndr/ndr_ --parse --header --parser --server --client --dcom-proxy --com-header --swig --odl --ejs -- $PIDL_EXTRA_ARGS"

if [ x$FULLBUILD = xFULL ]; then
      echo Rebuilding all idl files in librpc/idl
      $PIDL librpc/idl/*.idl || exit 1
      exit 0
fi

list=""

for f in librpc/idl/*.idl ; do
    basename=`basename $f .idl`
    ndr="librpc/gen_ndr/ndr_$basename.c"
    # blergh - most shells don't have the -nt function
    if [ -f $ndr ]; then
	if [ x`find $f -newer $ndr -print` = x$f ]; then
	    list="$list $f"
	fi
    else 
        list="$list $f"
    fi
done

if [ "x$list" != x ]; then
    $PIDL $list || exit 1
fi

exit 0
