#!/bin/sh

echo The Samba HEAD branch is deprecated pending the release of Samba 3.0
echo Please use the SAMBA_3_0 branch
echo to update to SAMBA_3_0 use this command:
echo "   cvs -z3 update -r SAMBA_3_0 -dP"
exit 1

# Run this script to build samba from CVS.

## insert all possible names (only works with 
## autoconf 2.x
TESTAUTOHEADER="autoheader autoheader-2.53"
TESTAUTOCONF="autoconf autoconf-2.53"

AUTOHEADERFOUND="0"
AUTOCONFFOUND="0"


##
## Look for autoheader 
##
for i in $TESTAUTOHEADER; do
	if which $i > /dev/null 2>&1; then
		if [ `$i --version | head -n 1 | cut -d.  -f 2` -ge 53 ]; then
			AUTOHEADER=$i
			AUTOHEADERFOUND="1"
			break
		fi
	fi
done

## 
## Look for autoconf
##

for i in $TESTAUTOCONF; do
	if which $i > /dev/null 2>&1; then
		if [ `$i --version | head -n 1 | cut -d.  -f 2` -ge 53 ]; then
			AUTOCONF=$i
			AUTOCONFFOUND="1"
			break
		fi
	fi
done


## 
## do we have it?
##
if [ "$AUTOCONFFOUND" = "0" -o "$AUTOHEADERFOUND" = "0" ]; then
	echo "$0: need autoconf 2.53 or later to build samba from CVS" >&2
	exit 1
fi



echo "$0: running $AUTOHEADER"
$AUTOHEADER || exit 1

echo "$0: running $AUTOCONF"
$AUTOCONF || exit 1

echo "Now run ./configure and then make."
exit 0

