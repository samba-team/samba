#!/bin/sh
echo "<variablelist>"
find . -type f -name '*.xml' -mindepth 2 | sort -t/ -k3 |
        while read ; do  
                echo "<xi:include href='$REPLY' parse='xml' xmlns:xi='http://www.w3.org/2001/XInclude'/>"
        done
                
echo "</variablelist>"
