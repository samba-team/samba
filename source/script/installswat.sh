#!/bin/sh
#fist version March 1998, Andrew Tridgell

SWATDIR=$1
SRCDIR=$2/

echo Installing SWAT in $SWATDIR

echo Installing the Samba Web Administration Tool

for d in $SWATDIR $SWATDIR/help $SWATDIR/images $SWATDIR/include; do
if [ ! -d $d ]; then
  mkdir $d
if [ ! -d $d ]; then
  echo Failed to make directory $d, does $USER have privileges?
  exit 1
fi
fi
done

for f in $SRCDIR../swat/images/*.gif; do
      FNAME=$SWATDIR/images/`basename $f`
      echo $FNAME
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      chmod 0644 $FNAME
done

for f in $SRCDIR../swat/help/*.html; do
      FNAME=$SWATDIR/help/`basename $f`
      echo $FNAME
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      chmod 0644 $FNAME
done

for f in $SRCDIR../docs/htmldocs/*.html; do
      FNAME=$SWATDIR/help/`basename $f`
      echo $FNAME
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      chmod 0644 $FNAME
done

for f in $SRCDIR../swat/include/*.html; do
      FNAME=$SWATDIR/include/`basename $f`
      echo $FNAME
      cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
      chmod 0644 $FNAME
done

cat << EOF
======================================================================
The SWAT files have been installed. Remember to read the swat/README
for information on enabling and using SWAT
======================================================================
EOF

exit 0

