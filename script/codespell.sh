#!/bin/bash
#
# Check code spelling

if [ $# -lt 1 ]; then
	echo "Usage: $(basename "${0}") DIR"
	exit 1
fi

DIR="${1}"

codespell "${DIR}"
ret=$?

if [ ${ret} -ne 0 ]; then
	echo
	echo "Fix code spelling issues. If it detected false positives" \
	     "please update .codespellignore."
fi

exit ${ret}
