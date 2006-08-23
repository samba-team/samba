#!/bin/sh
# build ldb docs
# tridge@samba.org August 2006

XSLTPROC="$1"
SRCDIR="$2"

if ! test -x "$XSLTPROC"; then
    echo "xsltproc not installed"
    exit 0
fi

# list of places to look for the docbook style sheet
manxsl=/usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl

# list of places to look for the html style sheet
htmlxsl=/usr/share/xml/docbook/stylesheet/nwalsh/html/docbook.xsl

manstyle=""
htmlstyle=""

for f in $manxsl; do
    if [ -r "$f" ]; then
	manstyle="$f"
    fi
done

if [ -z "$manstyle" ]; then
    echo "manpages/docbook.xsl not found on system"
    exit 0
fi

for f in $htmlxsl; do
    if [ -r "$f" ]; then
	htmlstyle="$f"
    fi
done

if [ -z "$htmlstyle" ]; then
    echo "html/docbook.xsl not found on system"
    exit 0
fi

mkdir -p man html

for f in $SRCDIR/man/*.xml; do
    base=`basename $f .xml`
    out=man/"`basename $base`"
    if [ ! -f "$out" ] || [ "$base" -nt "$out" ]; then
	echo Processing manpage $f
	$XSLTPROC -o "$out" "$manstyle" $f || exit 1
    fi
done

for f in $SRCDIR/man/*.xml; do
    base=`basename $f .xml`
    out=man/"`basename $base`".html
    if [ ! -f "$out" ] || [ "$base" -nt "$out" ]; then
	echo Processing html $f
	$XSLTPROC -o "$out" "$htmlstyle" $f || exit 1
    fi
done
