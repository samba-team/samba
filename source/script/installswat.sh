#!/bin/sh
#first version March 1998, Andrew Tridgell

SWATDIR=`echo $1 | sed 's/\/\//\//g'`
SRCDIR=$2/
BOOKDIR=$SWATDIR/using_samba

echo Installing SWAT in $SWATDIR
echo Installing the Samba Web Administration Tool

LANGS=". `cd $SRCDIR../swat/; /bin/echo lang/??`"
echo Installing langs are `cd $SRCDIR../swat/lang/; /bin/echo ??`

for ln in $LANGS; do 
 SWATLANGDIR=$SWATDIR/$ln
 for d in $SWATLANGDIR $SWATLANGDIR/help $SWATLANGDIR/images \
	$SWATLANGDIR/include; do
    if [ ! -d $d ]; then
	mkdir -p $d
	if [ ! -d $d ]; then
	    echo Failed to make directory $d, does $USER have privileges?
	    exit 1
	fi
    fi
 done
done

# Install images
for ln in $LANGS; do

  for f in $SRCDIR../swat/$ln/images/*.gif; do
      if [ ! -f $f ] ; then
	continue
      fi
      FNAME=$SWATDIR/$ln/images/`basename $f`
      echo $FNAME
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      chmod 0644 $FNAME
  done

  # Install html help

  for f in $SRCDIR../swat/$ln/help/*.html; do
      if [ ! -f $f ] ; then
	continue
      fi
      FNAME=$SWATDIR/$ln/help/`basename $f`
      echo $FNAME
      if [ "x$BOOKDIR" = "x" ]; then
        cat $f | sed 's/@BOOKDIR@.*$//' > $f.tmp
      else
        cat $f | sed 's/@BOOKDIR@//' > $f.tmp
      fi
      f=$f.tmp
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      rm -f $f
      chmod 0644 $FNAME
  done

  # Install "server-side" includes

  for f in $SRCDIR../swat/$ln/include/*.html; do
      if [ ! -f $f ] ; then
	continue
      fi
      FNAME=$SWATDIR/$ln/include/`basename $f`
      echo $FNAME
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      chmod 0644 $FNAME
  done

done

# Install html documentation (if html documentation tree is here)

if [ -d $SRCDIR../docs/htmldocs/ ]; then

    for f in $SRCDIR../docs/htmldocs/*.html; do
	FNAME=$SWATDIR/help/`basename $f`
	echo $FNAME
	cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
	chmod 0644 $FNAME
    done

    if [ -d $SRCDIR../docs/htmldocs/images/ ]; then
        if [ ! -d $SWATDIR/help/images/ ]; then
            mkdir $SWATDIR/help/images
            if [ ! -d $SWATDIR/help/images/ ]; then
                echo Failed to make directory $SWATDIR/help/images, does $USER have privileges?
                exit 1
            fi
        fi
        for f in $SRCDIR../docs/htmldocs/images/*.png; do
            FNAME=$SWATDIR/help/images/`basename $f`
            echo $FNAME
            cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
            chmod 0644 $FNAME
        done
    fi
fi

# Install Using Samba book (but only if it is there)

if [ "x$BOOKDIR" != "x" -a -f $SRCDIR../docs/htmldocs/using_samba/toc.html ]; then

    # Create directories

    for d in $BOOKDIR $BOOKDIR/figs ; do
        if [ ! -d $d ]; then
            mkdir $d
            if [ ! -d $d ]; then
                echo Failed to make directory $d, does $USER have privileges?
                exit 1
            fi
        fi
    done

    # HTML files

    for f in $SRCDIR../docs/htmldocs/using_samba/*.html; do
        FNAME=$BOOKDIR/`basename $f`
        echo $FNAME
        cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
        chmod 0644 $FNAME
    done

    for f in $SRCDIR../docs/htmldocs/using_samba/*.gif; do
        FNAME=$BOOKDIR/`basename $f`
        echo $FNAME
        cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
        chmod 0644 $FNAME
    done

    # Figures

    for f in $SRCDIR../docs/htmldocs/using_samba/figs/*.gif; do
        FNAME=$BOOKDIR/figs/`basename $f`
        echo $FNAME
        cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
        chmod 0644 $FNAME
    done

fi

cat << EOF
======================================================================
The SWAT files have been installed. Remember to read the swat/README
for information on enabling and using SWAT
======================================================================
EOF

exit 0

