#!/bin/sh
# generate a set of ABI signatures from a shared library

SHAREDLIB="$1"

GDBSCRIPT="gdb_syms.$$"

(
	cat <<EOF
set height 0
set width 0
EOF

	# On older linker versions _init|_fini symbols are not hidden.
	objdump --dynamic-syms "${SHAREDLIB}" |
		awk '$0 !~ /.hidden/ {if ($2 == "g" && $3 ~ /D(F|O)/ && $4 ~ /(.bss|.rodata|.text)/) print $NF}' |
		sort |
		while read -r s; do
			echo "echo $s: "
			echo p "${s}"
		done
) >$GDBSCRIPT

# forcing the terminal avoids a problem on Fedora12
TERM=none gdb -n -batch -x $GDBSCRIPT "$SHAREDLIB" </dev/null
rm -f $GDBSCRIPT
