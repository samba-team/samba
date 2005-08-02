#!/bin/sh
#####################
# build generated asn1 files in heimdal/ tree
# tridge@samba.org, June 2005

CC="$1"

TOP=`pwd`
ASN1_COMPILE=$TOP/bin/asn1_compile

build_asn1() {
    f=$1
    name=$2

    dir=`dirname $f`
    file=`basename $f`
    echo Building $f
    cd $dir && $ASN1_COMPILE $file $name || exit 1
    for f in *.x; do
	base=`basename $f .x`
	rm -f $base.c && cp $base.x $base.c
    done
    cd $TOP || exit 1
}

build_cp() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    base=`basename $f in`
    echo Building $f
    echo cp $base"in" $base
    cd $dir && cp $base"in" $base
    cd $TOP || exit 1
}

build_cp heimdal/lib/roken/vis.hin
build_cp heimdal/lib/roken/err.hin

make bin/asn1_compile || exit 1
build_asn1 heimdal/lib/hdb/hdb.asn1 hdb_asn1
build_asn1 heimdal/lib/gssapi/spnego.asn1 spnego_asn1
build_asn1 heimdal/lib/asn1/k5.asn1 krb5_asn1
