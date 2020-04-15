#!/bin/bash
#

#
# I used https://github.com/kimgr/asn1ate.git
# to generate pyasn1 bindings for rfc4120.asn1
#

PATH_TO_ASN1ATE_CHECKOUT=$1
PATH_TO_ASN1_INPUT_FILE=$2

set -u
set -e

usage() {
	echo "usage: $0 PATH_TO_ASN1ATE_CHECKOUT PATH_TO_ASN1_INPUT_FILE > PATH_TO_PYASN1_OUTPUT_FILE"
}

test -n "${PATH_TO_ASN1ATE_CHECKOUT}" || {
	usage
	exit 1
}
test -n "${PATH_TO_ASN1_INPUT_FILE}" || {
	usage
	exit 1
}
test -d "${PATH_TO_ASN1ATE_CHECKOUT}" || {
	usage
	exit 1
}
test -f "${PATH_TO_ASN1_INPUT_FILE}" || {
	usage
	exit 1
}

PATH_TO_PYASN1GEN_PY="${PATH_TO_ASN1ATE_CHECKOUT}/asn1ate/pyasn1gen.py"

PYTHONPATH="${PATH_TO_ASN1ATE_CHECKOUT}:${PYTHONPATH-}"
export PYTHONPATH

python3 "${PATH_TO_PYASN1GEN_PY}" "${PATH_TO_ASN1_INPUT_FILE}"
