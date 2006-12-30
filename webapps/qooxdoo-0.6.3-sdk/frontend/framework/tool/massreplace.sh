#!/usr/bin/env bash

cd `dirname $0`/..

for file in `find source -name "*.js" -o -name "*.css"  -o -name "*.html"`; do
  echo ">>> Patching: $file"
  sed -i s:"$1":"$2":g $file
done
