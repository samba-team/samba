#!/bin/sh
SRCDIR=$1/

YODLDIR=$SRCDIR/../docs/yodldocs
MANPAGEDIR=$SRCDIR/../docs/manpages
HTMLDIR=$SRCDIR/../docs/htmldocs

echo "Re-creating man pages and HTML pages from YODL sources..."

if [ ! -d $MANPAGEDIR ]; then
  echo "directory $MANPAGEDIR does not exist, are we in the right place?"
  exit 1
fi

if [ ! -d $HTMLDIR ]; then
  echo "directory $HTMLDIR does not exist, are we in the right place?"
  exit 1
fi

if [ ! -d $YODLDIR ]; then
  echo "directory $YODLDIR does not exist, are we in the right place?"
  exit 1
fi

cd $YODLDIR

for d in *.yo
do

#
# Create the basename from the YODL manpage
#
    bn=`echo $d | sed -e 's/\.yo//`

	case "$d"
	in
		*.[0-9].yo)
			echo "Creating man pages..."
			echo $d
			rm -f $bn.man
			yodl2man $d
			if [ ! -f $bn.man ]; then
				echo "Failed to make man page for $d"
				exit 1
			fi
			cp $bn.man ../manpages/$bn || echo "Cannot create $YODLDIR/../manpages/$bn"

			echo "Creating html versions of man pages..."
			echo $d
			rm -f $bn.html
			yodl2html $d
			if [ ! -f $bn.html ]; then
				echo "Failed to make html page for $d"
				exit 1
			fi
			cp $bn.html ../htmldocs || echo "Cannot create $YODLDIR/../htmldocs/$bn.html"
			;;
		*)
#
# Non man-page YODL docs - just make html.
#
			echo $d
			rm -f $bn.html
			yodl2html $d
			if [ ! -f $bn.html ]; then
                echo "Failed to make html page for $d"
                exit 1
            fi
			cp $bn.html ../htmldocs || echo "Cannot create $YODLDIR/../htmldocs/$bn.html"
		;;
	esac
done

echo "Remember to CVS check in your changes..."
exit 0
