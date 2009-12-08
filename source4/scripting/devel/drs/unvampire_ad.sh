#!/bin/bash

set -x

. `dirname $0`/vars


bin/ldbdel -r -H ldap://$server.$DNSDOMAIN -U$workgroup/administrator%$pass "CN=$machine,CN=Computers,$dn"
bin/ldbdel -r -H ldap://$server.$DNSDOMAIN -U$workgroup/administrator%$pass "CN=$machine,OU=Domain Controllers,$dn"
bin/ldbdel -r -H ldap://$server.$DNSDOMAIN -U$workgroup/administrator%$pass "CN=$machine,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$dn"
rm -f $PREFIX/private/*.ldb
