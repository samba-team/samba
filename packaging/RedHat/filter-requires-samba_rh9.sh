#!/bin/sh
/usr/lib/rpm/perl.req $* | egrep -v '(Net::LDAP|CGI)'
