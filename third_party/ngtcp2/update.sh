#!/bin/bash

if [[ $# -lt 1 ]]; then
    echo "Usage: update.sh VERSION"
    exit 1
fi

NGTCP2_VERSION="${1}"
NGTCP2_GIT="https://github.com/ngtcp2/ngtcp2.git"
NGTCP2_UPDATE_SCRIPT="$(readlink -f "$0")"
NGTCP2_SAMBA_DIR="$(dirname "${NGTCP2_UPDATE_SCRIPT}")"
NGTCP2_TMPDIR=$(mktemp --tmpdir -d ngtcp2-XXXXXXXX)

echo "VERSION:          ${NGTCP2_VERSION}"
echo "GIT URL:          ${NGTCP2_GIT}"
echo "NGTCP2 SAMBA DIR: ${NGTCP2_SAMBA_DIR}"
echo "UIC TMP DIR:      ${NGTCP2_TMPDIR}"

cleanup_tmpdir() {
    popd 2>/dev/null || true
    rm -rf "$NGTCP2_TMPDIR"
}
trap cleanup_tmpdir SIGINT

cleanup_and_exit() {
    cleanup_tmpdir
    if test "$1" = 0 -o -z "$1" ; then
        exit 0
    else
        exit "$1"
    fi
}

# Checkout the git tree
mkdir -p "${NGTCP2_TMPDIR}"
pushd "${NGTCP2_TMPDIR}" || cleanup_and_exit 1

git clone "${NGTCP2_GIT}"
ret=$?
if [ $ret -ne 0 ]; then
    echo "ERROR: Failed to clone repository"
    cleanup_and_exit 1
fi

pushd ngtcp2 || cleanup_and_exit 1
git checkout -b "ngtcp2-${NGTCP2_VERSION}" "v${NGTCP2_VERSION}"
ret=$?
if [ $ret -ne 0 ]; then
    echo "ERROR: Failed to checkout v${NGTCP2_VERSION} repository"
    cleanup_and_exit 1
fi
PAGER= git log --pretty=oneline -1
popd || cleanup_and_exit 1

popd || cleanup_and_exit 1

# Update src
pushd "${NGTCP2_SAMBA_DIR}" || cleanup_and_exit 1
pwd

rm -rf crypto/ lib/
rsync -av "${NGTCP2_TMPDIR}/ngtcp2/crypto/" crypto/
rsync -av "${NGTCP2_TMPDIR}/ngtcp2/lib/" lib/
ret=$?
if [ $ret -ne 0 ]; then
    echo "ERROR: Failed copy src"
    cleanup_and_exit 1
fi

git add lib crypto

popd || cleanup_and_exit 1

echo
echo "Now please change VERSION in buildtools/wafsamba/samba_third_party.py"
echo

cleanup_and_exit 0
