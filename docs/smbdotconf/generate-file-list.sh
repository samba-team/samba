#!/bin/sh
DIR=.
if [ "x$1" != "x" ]
then
	DIR="$1"
fi

echo "<variablelist>"
for I in `find $DIR -type f -name '*.xml' -mindepth 2 | sort -t/ -k3 | xargs`
do 
	echo "<xi:include href='$I' parse='xml'/>"
done
                
echo "</variablelist>"
