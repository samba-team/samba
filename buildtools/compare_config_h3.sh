#!/bin/sh

# compare the generated config.h from a waf build with existing samba
# build

OLD_CONFIG=source3/include/autoconf/config.h
if test "x$1" != "x" ; then
	OLD_CONFIG=$1
fi

NEW_CONFIG=bin/default/include/config.h
if test "x$2" != "x" ; then
	NEW_CONFIG=$2
fi

EXCEPTIONS=`dirname $0`/compare_config_h3-exceptions.grep

if test "x$DIFF" = "x" ; then
	DIFF="comm -23"
fi

grep "^.define" $NEW_CONFIG | egrep -v -f $EXCEPTIONS | sort > waf-config.h
grep "^.define" $OLD_CONFIG | egrep -v -f $EXCEPTIONS | sort > old-config.h

$DIFF old-config.h waf-config.h
rm -f old-config.h waf-config.h

