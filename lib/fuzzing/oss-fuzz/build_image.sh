#!/bin/sh -e

DIST=ubuntu1604
SCRIPT_DIR=`dirname $0`

$SCRIPT_DIR/../../../bootstrap/generated-dists/$DIST/bootstrap.sh
$SCRIPT_DIR/../../../bootstrap/generated-dists/$DIST/locale.sh

apt-get install chrpath

cp $SCRIPT_DIR/build.sh $SRC/
