#!/bin/sh
#
# this script finds unused lp_*() functions
#
# use it like this:
#
#   user@host:~/samba/source>./script/find_unused_options.sh
#

LIST_GLOBAL=`grep '^FN_GLOBAL' param/loadparm.c |sed -e's/^FN_GLOBAL.*(\(.*\).*,.*\(&Globals\..*\)).*/\1:\2/'`

LIST_LOCAL=`grep '^FN_LOCAL' param/loadparm.c |sed -e's/^FN_LOCAL.*(\(.*\).*,[ ]*\(.*\)).*/\1:\2/'`

for i in $LIST_GLOBAL;do
	key=`echo $i|cut -d ':' -f1`
	val=`echo $i|cut -d ':' -f2`

	found=`grep "$key[ ]*()" */*.c`

	if test -z "$found"; then
	    found=`grep "$key[ ]*()" */*/*.c`
	    if test -z "$found"; then
		echo "Not Used Global: $key() -> $val"
	    fi
	fi
done

for i in $LIST_LOCAL;do
	key=`echo $i|cut -d ':' -f1`
	val=`echo $i|cut -d ':' -f2`

	found=`grep "$key[ ]*(" */*.c`

	if test -z "$found"; then
	    found=`grep "$key[ ]*(" */*/*.c`
	    if test -z "$found"; then
		echo "Not Used LOCAL: $key() -> $val"
	    fi
	fi
done

echo "# do a 'make clean;make everything' before removing anything!"
