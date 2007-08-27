#!/bin/sh
# install miscellaneous files

SRCDIR="$1"
JSDIR="$2"
SETUPDIR="$3"
BINDIR="$4"

cd $SRCDIR || exit 1

echo "Installing js libs"
mkdir -p $JSDIR || exit 1
cp scripting/libjs/*.js $JSDIR || exit 1

echo "Installing setup templates"
mkdir -p $SETUPDIR || exit 1
cp setup/schema-map-* $SETUPDIR || exit 1
cp setup/DB_CONFIG $SETUPDIR || exit 1
cp setup/*.inf $SETUPDIR || exit 1
cp setup/*.ldif $SETUPDIR || exit 1
cp setup/*.reg $SETUPDIR || exit 1
cp setup/*.zone $SETUPDIR || exit 1
cp setup/*.conf $SETUPDIR || exit 1

echo "Installing script tools"
mkdir -p "$BINDIR"
rm -f scripting/bin/*~
cp scripting/bin/* $BINDIR/ || exit 1

exit 0
