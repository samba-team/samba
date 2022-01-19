#!/bin/sh

find ${1:-.} -name '*.gcov' -print | while read f; do
    case "$f" in
    */.libs/*) continue;;
    *) true;;
    esac
    echo FIX $f
    f_basename=${f%%.gcno\#\#*}.c
    f_basename=${f_basename##*/}
    head -1 "$f" | grep 'Source:/' > /dev/null && continue
    #bname=$(head -1 "$f" | grep 'Source:/' | cut -d: -f4)
    dname=$(echo "$f"|cut -d'#' -f1|sed -e 's,/[^/]*$,/,')
    ex "$f" <<EOF
1,1 s,:Source:.*$,:Source:${dname}${f_basename},
wq!
EOF
done
