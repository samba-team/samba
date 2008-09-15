#!/bin/sh

FULLBUILD=$1
IDLDIR=$2
OUTDIR=$3
shift 3
PIDL_EXTRA_ARGS="$*"

[ -d $OUTDIR ] || mkdir -p $OUTDIR || exit 1

PIDL="$PIDL --outputdir $OUTDIR --header --ndr-parser --server --client --swig --python --dcom-proxy --com-header -- $PIDL_EXTRA_ARGS"

if [ x$FULLBUILD = xFULL ]; then
      echo Rebuilding all idl files in $IDLDIR
      $PIDL $IDLDIR/*.idl || exit 1
      exit 0
fi

list=""

for f in $IDLDIR/*.idl ; do
    basename=`basename $f .idl`
    ndr="$OUTDIR/ndr_$basename.c"
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
