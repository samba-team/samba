#!/bin/sh
echo "<variablelist>"
for I in `find . -type f -name '*.xml' -mindepth 2 | sort -t/ -k3 | xargs`
do 
	echo "<xi:include href='$I' parse='xml' xmlns:xi='http://www.w3.org/2001/XInclude'/>"
done
                
echo "</variablelist>"
