#!/bin/bash

# compare the generated files from a waf


gen_files=$(cd bin/default && find . -type f -name '*.[ch]')

for f in $gen_files; do
    echo
    echo "==================================================="
    echo "Comparing generated file $f"
    diff -u -b $HOME/samba_old/$f bin/default/$f
done

