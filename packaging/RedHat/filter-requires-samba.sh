#!/bin/sh

## snarfed from the RedHat Rawhide samba SRPM

/usr/lib/rpm/perl.req $* | grep -v "Net::LDAP"
