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

INPUT=themes/freedesktop/use
OUTPUT=themes/qooxdoo/use

echo ">>> Cleanup..."
rm -rf ${OUTPUT}/*

echo ">>> Converting themes..."
for DIR in `find ${INPUT} -maxdepth 1 -mindepth 1 -type d ! -name .svn`
do
  THEME=`basename $DIR`
  echo "  - $THEME"

  for ITEM in `cat data/qooxdoo_whitelist.dat`
  do
    SIZE=`echo $ITEM | cut -d"x" -f1`
    SUBPATH=`echo $ITEM | cut -d"/" -f2-`

    SOURCE=${INPUT}/${THEME}/${ITEM}
    TARGET=${OUTPUT}/${THEME}/${SIZE}/${SUBPATH}
    TARGETDIR=`dirname $TARGET`

    if [ -r ${SOURCE} ]
    then
      if [ ! -r $TARGETDIR ]; then
        mkdir -p $TARGETDIR
      fi
      cp -f ${SOURCE} ${TARGET}
    else
      echo "    - Missing icon: $ITEM (Malformed whitelist!)"
    fi
  done
done
