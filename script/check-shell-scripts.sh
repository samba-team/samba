#!/bin/sh

if [ $# -lt 1 ]; then
	echo "Usage: $(basename "${0}") DIR [SEVERITY]"
	exit 1
fi

DIR="${1}"
SEVERITY="${2:-error}"

# bfs is a faster drop-in replacement for find.
if command -v bfs >/dev/null 2>&1; then
	FIND="bfs"
else
	FIND="find"
fi

# List files with a shell extension or a shell shebang, skipping hidden
# directories.
find_shell_scripts()
{
	${FIND} "${1}" -name '.?*' -prune -o -type f -print0 |
		xargs -0 awk '
			FNR == 1 {
				if (FILENAME ~ /\.(sh|bash)$/ ||
				    $0 ~ /^#![ \t]*(\/usr)?\/bin\/(env[ \t]+)?(ba|da|k)?sh([ \t]|$)/) {
					print FILENAME
				}
				nextfile
			}'
}

find_shell_scripts "${DIR}" |
	grep -v -E "(bootstrap|third_party)" |
	xargs shellcheck \
		--shell=sh \
		--external-sources \
		--check-sourced \
		--format=gcc \
		--severity="${SEVERITY}"

exit $?
