#!/bin/sh
#####################
# build generated asn1, et and flex files in heimdal/ tree
# tridge@samba.org, June 2005

TOP=`pwd`
ASN1_COMPILE=$TOP/bin/asn1_compile
ET_COMPILE=$TOP/bin/compile_et

# we need to substitute these correctly based on configure output
FLEX=flex
BISON=bison
AWK=gawk
CC=gcc

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

build_et() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    echo Building $f
    cd $dir && $ET_COMPILE $file || exit 1
    cd $TOP || exit 1
}

build_lex() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    base=`basename $f .l`
    echo Building $f
    cd $dir && $FLEX $file
    sed '/^#/ s|$base.yy\.c|$base.c|' $base.yy.c > $base.c
    cd $TOP || exit 1
}

build_bison() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    base=`basename $f .y`
    echo Building $f
    cd $dir && $BISON -y -d $file
    sed -e "/^#/!b" -e "s|y\.tab\.h|$base.h|" y.tab.h > $base.h
    sed '/^#/ s|y\.tab\.c|$base.c|' y.tab.c > $base.c
    cd $TOP || exit 1
}

build_awk() {
    f=$1
    dir=`dirname $f`
    file=`basename $f`
    base=`basename $f .h.in`
    echo Building $f
    cd $dir && $AWK -f $base.awk $base.h.in > gen.c
    $CC -I$TOP/heimdal_build -I$TOP -Iheimdal/lib/roken -DHAVE_CONFIG_H -o gen gen.c || exit 1
    ./gen > $base.h || exit 1
    rm -f gen gen.c
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
build_lex heimdal/lib/asn1/lex.l
build_lex heimdal/lib/com_err/lex.l
build_bison heimdal/lib/com_err/parse.y
build_bison heimdal/lib/asn1/parse.y
build_awk heimdal/lib/roken/roken.h.in

make bin/asn1_compile || exit 1
build_asn1 heimdal/lib/hdb/hdb.asn1 hdb_asn1
build_asn1 heimdal/lib/gssapi/spnego.asn1 spnego_asn1
build_asn1 heimdal/lib/asn1/k5.asn1 krb5_asn1

make bin/compile_et || exit 1
build_et heimdal/lib/hdb/hdb_err.et
build_et heimdal/lib/krb5/krb5_err.et
build_et heimdal/lib/krb5/heim_err.et
build_et heimdal/lib/krb5/k524_err.et
build_et heimdal/lib/asn1/asn1_err.et
