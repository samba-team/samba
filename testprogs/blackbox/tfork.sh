#!/bin/sh

sleep 1

echo stdout >&1
echo $1 >&1
echo stderror >&2

# close stdout and stderror, but don't exit yet
exec 1>&-
exec 2>&-

sleep 1

exit 0
