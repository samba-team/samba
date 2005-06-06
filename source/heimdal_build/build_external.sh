#!/bin/sh
#####################
# build generated asn1, et and flex files in heimdal/ tree
# tridge@samba.org, June 2005

TOP=`pwd`
ASN1_COMPILE=$TOP/bin/asn1_compile
ET_COMPILE=compile_et
FLEX=flex
BISON=bison


build_asn1() {
    f=$1
    name=$2

    dir=`dirname $f`
    file=`basename $f`
    echo Compiling $f
    cd $dir && $ASN1_COMPILE $file $name || exit 1
    for f in *.x; do
	base=`basename $f .x`
	rm -f $base.c && cp $base.x $base.c
    done
    cd $TOP || exit 1
}

build_et() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    echo Compiling $f
    cd $dir && $ET_COMPILE $file || exit 1
    cd $TOP || exit 1
}

build_lex() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    base=`basename $f .l`
    echo Compiling $f
    cd $dir && $FLEX $file
    sed '/^#/ s|$base.yy\.c|$base.c|' $base.yy.c > $base.c
    cd $TOP || exit 1
}

build_bison() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    base=`basename $f .y`
    echo Compiling $f
    cd $dir && $BISON -y -d $file
    sed -e "/^#/!b" -e "s|y\.tab\.h|$base.h|" y.tab.h > $base.h
    sed '/^#/ s|y\.tab\.c|$base.c|' y.tab.c > $base.c
    cd $TOP || exit 1
}

build_asn1 heimdal/lib/hdb/hdb.asn1 hdb_asn1
build_asn1 heimdal/lib/gssapi/spnego.asn1 spnego_asn1
build_asn1 heimdal/lib/asn1/k5.asn1 krb5_asn1


build_et heimdal/lib/hdb/hdb_err.et
build_et heimdal/lib/krb5/krb5_err.et
build_et heimdal/lib/krb5/heim_err.et
build_et heimdal/lib/krb5/k524_err.et
build_et heimdal/lib/asn1/asn1_err.et

build_lex heimdal/lib/asn1/lex.l

build_bison heimdal/lib/asn1/parse.y
