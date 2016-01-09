#!/bin/bash
#

set -e
set -u
set -x

#
# All passwords are "1234"
#

./manage-ca.sh manage-CA-samba.example.com.cnf init_ca

./manage-ca.sh manage-CA-samba.example.com.cnf create_dc localdc.samba.example.com 0123456789ABCDEF
./manage-ca.sh manage-CA-samba.example.com.cnf create_user administrator@samba.example.com

./manage-ca.sh manage-CA-samba.example.com.cnf create_dc addc.addom.samba.example.com 0123456789ABCDEF
./manage-ca.sh manage-CA-samba.example.com.cnf create_user administrator@addom.samba.example.com
