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

echo ">>> Indexing themes..."
mkdir -p temp
echo -n "" > temp/fd_content_all.txt
COUNT=0
for DIR in `find themes/freedesktop/use -maxdepth 1 -mindepth 1 -type d ! -name .svn`
do
  THEMENAME=`basename $DIR`
  echo "  - $THEMENAME"
  find $DIR -name "*.png" | cut -d"/" -f5- >> temp/fd_content_all.txt
  COUNT=$[$COUNT+1]
done

echo ">>> Normalizing..."
cat temp/fd_content_all.txt | sort | uniq -c | grep "${COUNT} " | cut -d" " -f8 > data/qooxdoo_whitelist.dat

echo ">>> Result..."
wc -l data/qooxdoo_whitelist.dat
