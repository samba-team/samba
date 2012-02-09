#!/bin/bash

# rebuild our heimdal lex/yacc files. Run this manually if you update heimdal

lexfiles="heimdal/lib/asn1/lex.l heimdal/lib/hx509/sel-lex.l heimdal/lib/com_err/lex.l"
yaccfiles="heimdal/lib/asn1/asn1parse.y heimdal/lib/hx509/sel-gram.y heimdal/lib/com_err/parse.y"

set -e

LEX="lex"
YACC="yacc"

top=$PWD

call_lex() {
    lfile="$1"

    echo "Calling $LEX on $lfile"

    dir=$(dirname $lfile)
    base=$(basename $lfile .l)
    cfile=$base".c"
    lfile=$base".l"

    cd $dir

    # --noline specified because line directives cause more bother than they solve (issues with lcov finding the source files)
    $LEX --noline $lfile || exit 1

    if [ -r lex.yy.c ]; then
	echo "#include \"config.h\"" > $base.c
	grep -v "^#line" lex.yy.c >> $base.c
	rm -f $base.yy.c
    elif [ -r $base.yy.c ]; then
	echo "#include \"config.h\"" > $base.c
	grep -v "^#line" $base.yy.c >> $base.c
	rm -f $base.yy.c
    elif [ -r $base.c ]; then
	mv $base.c $base.c.tmp
	echo "#include \"config.h\"" > $base.c
	grep -v "^#line" $base.c.tmp >> $base.c
	rm -f $base.c.tmp
    elif [ ! -r base.c ]; then
	echo "$base.c nor $base.yy.c nor lex.yy.c generated."
	exit 1
    fi
    cd $top
}


call_yacc() {
    yfile="$1"

    echo "Calling $YACC on $yfile"

    dir=$(dirname $yfile)
    base=$(basename $yfile .y)
    cfile=$base".c"
    yfile=$base".y"

    cd $dir

    # -l specified because line directives cause more bother than they solve (issues with lcov finding the source files)
    $YACC -l -d $yfile || exit 1
    if [ -r y.tab.h -a -r y.tab.c ];then
	cat y.tab.h > $base.h
	cat y.tab.c > $base.c
	rm -f y.tab.c y.tab.h
    elif [ ! -r $base.h -a ! -r $base.c]; then
	echo "$base.h nor $base.c generated."
	exit 1
    fi
    cd $top
}



for lfile in $lexfiles; do
    call_lex $lfile
done

for yfile in $yaccfiles; do
    call_yacc $yfile
done
