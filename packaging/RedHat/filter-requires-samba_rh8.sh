#!/bin/sh
/usr/lib/rpm/find-requires $* | egrep -v '(Net::LDAP|CGI)'
