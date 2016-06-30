#!/bin/bash
set -x

DB=st/provision/simple-dc/private/sam.ldb
DEST=source4/selftest/provisions/simple-dc-groups-ldb/ldb.dump
SAMBA_TOOL=$(pwd)/bin/samba-tool

#make test TESTS="samba4.blackbox.group.py"

$SAMBA_TOOL user  add -H $DB fred complexpassword#12
$SAMBA_TOOL group add -H $DB swimmers
$SAMBA_TOOL group addmembers -H $DB swimmers fred

$SAMBA_TOOL user delete -H $DB fred

bin/ldbsearch -H  $DB --show-recycled --show-deleted \
              --show-deactivated-link --reveal | grep fred
bin/ldbsearch -H  $DB --show-recycled --show-deleted \
               --show-deactivated-link --reveal | grep swimmers
