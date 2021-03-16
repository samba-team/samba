#!/bin/bash

logfile=/tmp/$USER_printing_var_exp.log

rm -f "$logfile"

for i in $(seq 1 $#) ; do
    eval echo "arg $i: \$$i" >> "$logfile"
done
