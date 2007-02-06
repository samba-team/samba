#!/usr/bin/env bash
################################################################################
#
#  qooxdoo - the new era of web development
#
#  http://qooxdoo.org
#
#  Copyright:
#    2007 1&1 Internet AG, Germany, http://www.1and1.org
#
#  License:
#    LGPL: http://www.gnu.org/licenses/lgpl.html
#    EPL: http://www.eclipse.org/org/documents/epl-v10.php
#    See the LICENSE file in the project's top-level directory for details.
#
#  Authors:
#    * Sebastian Werner (wpbasti)
#    * Fabian Jakobs (fjakobs)
#
################################################################################

SIZES="16 22 24 32 48 64 72 96 128"

echo ">>> Cleaning up old symlinks"
find themes/kde/use -type l | xargs rm -f

echo ">>> Symlinking identical images..."
for DIR in `find themes/kde/use -maxdepth 1 -mindepth 1 -type d ! -name .svn`
do
  THEMENAME=`basename $DIR`
  echo "  * $THEMENAME"

  for SIZE in $SIZES
  do
    for ITEM in `cat data/kde_normalize.dat`
    do
      NAME1=`echo $ITEM | cut -d"=" -f1`
      NAME2=`echo $ITEM | cut -d"=" -f2 | sed s:"=":"":g`

      FILE1=$DIR/${SIZE}x${SIZE}/$NAME1.png
      FILE2=$DIR/${SIZE}x${SIZE}/$NAME2.png

      if [ -r ${FILE1} ]
      then
        if [ ! -r ${FILE2} -a ! -L ${FILE2} ]; then
          echo "    - Linking: $SIZE/$NAME1 -> $SIZE/$NAME2"
          mkdir -p `dirname ${FILE2}`
          ln -s ${FILE1} ${FILE2}
        fi
      fi

      if [ -r ${FILE2} ]
      then
        if [ ! -r ${FILE1} -a ! -L ${FILE1} ]; then
          echo "    - Linking: $SIZE/$NAME2 -> $SIZE/$NAME1"
          mkdir -p `dirname ${FILE1}`
          ln -s ${FILE2} ${FILE1}
        fi
      fi
    done
  done
done
