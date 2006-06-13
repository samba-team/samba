#!/bin/sh

/usr/lib/rpm/find-requires $* | grep -E -v '(Net::LDAP|Crypt::SmbHash|CGI|Unicode::MapUTF8)'
