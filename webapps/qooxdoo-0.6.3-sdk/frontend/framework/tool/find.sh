#!/usr/bin/env bash

cd `dirname $0`/..

if [ "$1" = "" ]; then
  exit 1
fi

find source/class/ -name "*.js" | xargs grep -n "$*"
