#!/bin/sh
# Update our copy of waf

TARGETDIR="`dirname $0`"
WORKDIR="`mktemp -d`"

mkdir -p "$WORKDIR"

svn checkout http://waf.googlecode.com/svn/branches/waf-1.5/wafadmin "$WORKDIR/wafadmin"

rsync -C -avz --delete "$WORKDIR/wafadmin/" "$TARGETDIR/wafadmin/"

rm -rf "$WORKDIR"
