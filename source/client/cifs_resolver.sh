#!/bin/sh
###############################################################################
#
# Written by Igor Mammedov (niallain@gmail.com)
# Modified by Steve French <sfrench@samba.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
###############################################################################
#
# linux-cifs-client dns name resolver helper
#     called by cifs kernel module upcall to key API to resolve server name 
#     to IP when module connects to DFS link.  We may eventually make this
#     C code, but this is a good starting point.
#     You should have appropriate kernel and keyutils installed.
#     CIFS DFS Support will require Linux kernel module 
#	cifs.ko version 1.48 or later.      
#
#     Consult the CIFS client users guide for more details
#	 http://www.samba.org/samba/ftp/cifs-cvs/linux-cifs-client-guide.pdf
#
# Put the following string in /etc/request-key.conf without comment sign :)
#    create  cifs_resolver   *       *           /sbin/cifs_resolver.sh %k %d %S
#
# Put this script into /sbin directory
# Call:  /sbin/cifs_resolver.sh <keyid> <desc> <session-keyring>
#
#     <desc> - is server name to resolve
#

status=0
{
    echo "cifs_resolver: resolving: $2"

    DATAA=`/usr/bin/host $2`
    status=$?

    if [ "x$status" != "x0" ]; then
	    echo "cifs_resolver: failed to resolve: $2"
	    exit $status
    else 
	    DATAA=`echo "$DATAA" | sed 's/.*has address //'`
	    echo "cifs_resolver: resolved: $2 to $DATAA"
	    keyctl instantiate $1 "$DATAA" $3 || exit 1
    fi
# if you want to debug the upcall, replace /dev/null (below) with ttyS0 or file
} >&/dev/null
exit 0 
