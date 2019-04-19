#!/bin/bash

#set -x

make test TESTS="samba4.blackbox.group.py"

echo adding user fred
bin/samba-tool  user add -H  st/provision/simple-dc/private/sam.ldb fred complexpassword#12

echo adding group swimmers
bin/samba-tool group add -H  st/provision/simple-dc/private/sam.ldb swimmers

echo adding fred to swimmers
bin/samba-tool group addmembers -H  st/provision/simple-dc/private/sam.ldb swimmers fred
echo

for w in swimmers fred; do
    echo grepping for $w
    echo ------------------------------------
    bin/ldbsearch -H  st/provision/simple-dc/private/sam.ldb --show-recycled --show-deleted  --show-deactivated-link --reveal | grep  $w
    echo ------------------------------------
done
echo

echo deleting fred
bin/samba-tool user delete  -H  st/provision/simple-dc/private/sam.ldb fred

for w in swimmers fred; do
    echo grepping for $w
    echo ------------------------------------
    bin/ldbsearch -H  st/provision/simple-dc/private/sam.ldb --show-recycled --show-deleted  --show-deactivated-link --reveal | grep  $w
    echo ------------------------------------
done
echo
