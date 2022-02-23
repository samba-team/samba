#!/bin/bash

if [[ $# -lt 1 ]]; then
	echo "Usage: update.sh VERSION"
	exit 1
fi

WAF_VERSION="${1}"
WAF_GIT="https://gitlab.com/ita1024/waf.git"
WAF_UPDATE_SCRIPT="$(readlink -f "$0")"
WAF_SAMBA_DIR="$(dirname "${WAF_UPDATE_SCRIPT}")"
WAF_TMPDIR=$(mktemp --tmpdir -d waf-XXXXXXXX)

echo "VERSION:       ${WAF_VERSION}"
echo "GIT URL:       ${WAF_GIT}"
echo "WAF SAMBA DIR: ${WAF_SAMBA_DIR}"
echo "WAF TMP DIR:    ${WAF_TMPDIR}"

cleanup_tmpdir()
{
	popd 2>/dev/null || true
	rm -rf "$WAF_TMPDIR"
}
trap cleanup_tmpdir SIGINT

cleanup_and_exit()
{
	cleanup_tmpdir
	if test "$1" = 0 -o -z "$1"; then
		exit 0
	else
		exit "$1"
	fi
}

# Checkout the git tree
mkdir -p "${WAF_TMPDIR}"
pushd "${WAF_TMPDIR}" || cleanup_and_exit 1

git clone "${WAF_GIT}"
ret=$?
if [ $ret -ne 0 ]; then
	echo "ERROR: Failed to clone repository"
	cleanup_and_exit 1
fi

pushd waf || cleanup_and_exit 1
git checkout -b "waf-${WAF_VERSION}" "waf-${WAF_VERSION}"
ret=$?
if [ $ret -ne 0 ]; then
	echo "ERROR: Failed to checkout waf-${WAF_VERSION} repository"
	cleanup_and_exit 1
fi
popd || cleanup_and_exit 1

popd || cleanup_and_exit 1

# Update waflib
pushd "${WAF_SAMBA_DIR}" || cleanup_and_exit 1
pwd

rm -rf waflib/
rsync -av "${WAF_TMPDIR}/waf/waflib" .
ret=$?
if [ $ret -ne 0 ]; then
	echo "ERROR: Failed copy waflib"
	cleanup_and_exit 1
fi
chmod -x waflib/Context.py

git add waflib

popd || cleanup_and_exit 1

echo
echo "Now please change VERSION in buildtools/bin/waf and"
echo "Context.HEXVERSION in buildtools/wafsamba/wafsamba.py"
grep WAFVERSION "${WAF_SAMBA_DIR}/waflib/Context.py"
grep HEXVERSION "${WAF_SAMBA_DIR}/waflib/Context.py"
echo

cleanup_and_exit 0
