#!/bin/sh
sh generate-file-list.sh >parameters.all.xml

xsltproc --xinclude \
                 --param smb.context "'G'" \
                 --output parameters.global.xml \
                 generate-context.xsl parameters.all.xml

xsltproc --xinclude \
                 --param smb.context "'S'" \
                 --output parameters.service.xml \
                 generate-context.xsl parameters.all.xml

xsltproc --xinclude expand-smb.conf.xsl smb.conf.5.xml | \
xsltproc http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl -
