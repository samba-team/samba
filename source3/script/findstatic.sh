#!/bin/sh
# find a list of fns and variables in the code that could be static
# Andrew Tridgell <tridge@samba.org>

# rather linux specific, but that doesn't matter in this case
# also very slow (order is N^2) but fast enough for this project

declare -a FNS

for f in $@; do
    echo "Checking in $f"
    T_FNS=`nm $f | grep ' T ' | cut -d' ' -f3`
    C_FNS=`nm $f | egrep ' [DC] ' | cut -d' ' -f3`
    if [ "$T_FNS" = "" -a "$C_FNS" = "" ]; then
	echo "No public functions or data in $f"
	continue
    fi
    for fn in $T_FNS; do
	if [ $fn = "main" ]; then
	    continue
	fi
	found=0
	for f2 in $@; do
	    if [ $f != $f2 ]; then
		FNS2=`nm $f2 | egrep ' U ' | awk '{print $2}'`
		for fn2 in $FNS2; do
		    if [ $fn2 = $fn ]; then
			found=1
			break
		    fi
		done
	    fi
	done
	if [ $found = 0 ]; then
	    echo "Global function $fn is unique to $f"
	fi
    done

    for fn in $C_FNS; do
	if [ $fn = "main" ]; then
	    continue
	fi
	found=0
	for f2 in $@; do
	    if [ $f != $f2 ]; then
		FNS2=`nm $f2 | grep ' U ' | awk '{print $2}'`
		for fn2 in $FNS2; do
		    if [ $fn2 = $fn ]; then
			found=1
			break
		    fi
		done
	    fi
	done
	if [ $found = 0 ]; then
	    echo "Global variable $fn is unique to $f"
	fi
    done
done
