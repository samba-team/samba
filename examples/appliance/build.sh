#!/bin/sh

for dir in SOURCES RPMS/i386 SRPMS BUILD; do
    mkdir -p /tmp/$dir
done

tar --exclude=CVS cfz /tmp/SOURCES/samba-appliance-0.1-src.tar.gz samba-appliance-0.1
rpm -ba appliance.spec
