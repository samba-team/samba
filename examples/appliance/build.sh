#!/bin/sh

tar --exclude=CVS -czf /usr/src/redhat/SOURCES/samba-appliance-0.1-src.tar.gz samba-appliance-0.1
rpm -ba appliance.spec
