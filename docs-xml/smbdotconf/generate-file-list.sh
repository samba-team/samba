#!/bin/sh
#
set -e
echo "<!DOCTYPE section ["
$(dirname $0)/../generate-pathconf-entities.sh

echo "]>"

DIR=.
if [ "x$1" != "x" ]; then
	DIR="$1"
fi

OLD=$(pwd)
cd $DIR

echo "<section>"
for I in $(find . -mindepth 2 -type f -name '*.xml' | sort -t/ -k3 | xargs); do
	cat $I
done
echo "</section>"

cd $OLD
