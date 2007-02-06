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

BASESIZES="16 22 32"

echo ">>> Indexing themes..."
mkdir -p temp
echo -n "" > temp/kde_content_all.txt
COUNT=0
for DIR in `find themes/kde/use -maxdepth 1 -mindepth 1 -type d ! -name .svn`
do
  THEMENAME=`basename $DIR`
  echo "  - $THEMENAME"
  find $DIR -name "*.png" | cut -d"/" -f5- >> temp/kde_content_all.txt
  COUNT=$[$COUNT+1]
done

echo ">>> Building common list..."
cat temp/kde_content_all.txt | sort | uniq -c | sort > temp/kde_content_count.txt
cat temp/kde_content_count.txt | grep "$COUNT " | cut -d" " -f8 | cut -d"." -f1 > temp/kde_content_common.txt
cat temp/kde_content_count.txt | grep "$[$COUNT-1] " | cut -d" " -f8 | cut -d"." -f1 > temp/kde_content_common_less.txt

echo ">>> Building list for base sizes..."
echo -n "" > temp/kde_content_common_base_temp.txt
for BASESIZE in $BASESIZES; do
  echo "  * $BASESIZE"
  grep ${BASESIZE}x${BASESIZE} temp/kde_content_common.txt | cut -d"/" -f2- | sort | uniq > temp/kde_content_common_${BASESIZE}.txt
  cat temp/kde_content_common_${BASESIZE}.txt >> temp/kde_content_common_base_temp.txt
done

echo ">>> Normalizing list..."
cat temp/kde_content_common_base_temp.txt | sort | uniq > temp/kde_content_common_base.txt

echo ">>> Preparing replacement map..."
cat data/kde_freedesktop.dat | cut -s -d"=" -f2 | sort | uniq > temp/kde_content_assigned.txt

echo ">>> Finding differences..."
diff temp/kde_content_common_base.txt temp/kde_content_assigned.txt > temp/kde_content_assigned.diff

echo ">>> Unassigned images..."
grep "^<" temp/kde_content_assigned.diff | cut -d" " -f2-

echo ">>> Unavailable images (hopefully empty)..."
grep "^>" temp/kde_content_assigned.diff | cut -d" " -f2-
