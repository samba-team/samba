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

which rsvg-convert > /dev/null || exit 1

SIZES="16 22 24 32 48 64 72 96 128"
FORMAT=png

for TYPE in kde
do
  INPUT=themes/${TYPE}/scalable
  OUTPUT=themes/${TYPE}/use

  for THEME in `find $INPUT -maxdepth 1 -mindepth 1 -type d ! -name .svn`
  do
    THEMENAME=`basename $THEME`
    echo ">>> Processing $THEMENAME ($TYPE)"

    mkdir -p $OUTPUT

    for DIR in `find ${THEME}/scalable -maxdepth 1 -mindepth 1 -type d ! -name .svn`
    do
      CAT=`basename $DIR`
      echo "  * Category ${CAT}"

      echo "    - Creating directories..."
      for SIZE in $SIZES; do
        mkdir -p ${OUTPUT}/${THEMENAME}/${SIZE}x${SIZE}/${CAT}
      done

      echo "    - Rendering files..."
      for SVG in `find $DIR -name "*.svg"`
      do
        SVGNAME=`basename $SVG`
        RENNAME=`echo $SVGNAME | sed s:svg:$FORMAT:g`

        for SIZE in $SIZES; do
          rsvg-convert $SVG -o ${OUTPUT}/${THEMENAME}/${SIZE}x${SIZE}/${CAT}/${RENNAME} -a -w $SIZE -h $SIZE -f $FORMAT
        done
      done
    done
  done
done
