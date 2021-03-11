#!/bin/bash

rm -f /tmp/printing_var_exp.log

for i in $(seq 1 $#) ; do
    eval echo "arg $i: \$$i" >> /tmp/printing_var_exp.log
done
