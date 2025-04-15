#!/bin/bash

if [[ $# -lt 1 ]]; then
    echo "Usage: update.sh VERSION"
    exit 1
fi

QUIC_VERSION="${1}"
QUIC_GIT="https://github.com/lxin/quic.git"
QUIC_UPDATE_SCRIPT="$(readlink -f "$0")"
QUIC_SAMBA_DIR="$(dirname "${QUIC_UPDATE_SCRIPT}")"
QUIC_TMPDIR=$(mktemp --tmpdir -d quic-XXXXXXXX)

echo "VERSION:        ${QUIC_VERSION}"
echo "GIT URL:        ${QUIC_GIT}"
echo "QUIC SAMBA DIR: ${QUIC_SAMBA_DIR}"
echo "QUIC TMP DIR:   ${QUIC_TMPDIR}"

cleanup_tmpdir() {
    popd 2>/dev/null || true
    rm -rf "$QUIC_TMPDIR"
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
mkdir -p "${QUIC_TMPDIR}"
pushd "${QUIC_TMPDIR}" || cleanup_and_exit 1

git clone "${QUIC_GIT}"
ret=$?
if [ $ret -ne 0 ]; then
    echo "ERROR: Failed to clone repository"
    cleanup_and_exit 1
fi

pushd quic || cleanup_and_exit 1
#git checkout -b "quic-${QUIC_VERSION}" "quic-${QUIC_VERSION}"
PAGER= git log --pretty=oneline -1
ret=$?
if [ $ret -ne 0 ]; then
    echo "ERROR: Failed to checkout quic-${QUIC_VERSION} repository"
    cleanup_and_exit 1
fi
popd || cleanup_and_exit 1

popd || cleanup_and_exit 1

# Update src
pushd "${QUIC_SAMBA_DIR}" || cleanup_and_exit 1
pwd

rm -rf libquic/ modules/ COPYING
mkdir -p modules/include/uapi
rsync -av "${QUIC_TMPDIR}/quic/libquic/" libquic/
rsync -av "${QUIC_TMPDIR}/quic/modules/include/uapi/" modules/include/uapi/
rsync -av "${QUIC_TMPDIR}/quic/COPYING" .
ret=$?
if [ $ret -ne 0 ]; then
    echo "ERROR: Failed copy src"
    cleanup_and_exit 1
fi

git add libquic modules/include/uapi/ COPYING

popd || cleanup_and_exit 1

echo
echo "Now please change VERSION in buildtools/wafsamba/samba_third_party.py"
echo

cleanup_and_exit 0
