#!/bin/sh

tar --exclude=CVS -czf /usr/src/redhat/SOURCES/samba-appliance-0.2-src.tar.gz samba-appliance-0.2
rpm -ba appliance.spec
