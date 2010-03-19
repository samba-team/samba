#!/bin/bash

# compare the generated config.h from a waf build with existing samba
# build

grep ^.define bin/default/source3/include/config.h | sort > waf-config.h
grep ^.define $HOME/samba_old/source3/include/config.h | sort > old-config.h

comm -23 old-config.h waf-config.h

#echo
#diff -u old-config.h waf-config.h
