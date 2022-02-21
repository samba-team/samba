#!/bin/sh

if [ $# -lt 1 ]; then
	echo "Usage: $(basename "${0}") DIR [SEVERITY]"
	exit 1
fi

DIR="${1}"
SEVERITY="${2:-error}"

shfmt -f "${DIR}" |
	grep -v -E "(bootstrap|third_party)" |
	xargs shellcheck \
		--shell=sh \
		--external-sources \
		--check-sourced \
		--format=gcc \
		--severity="${SEVERITY}"

exit $?
