#!/bin/bash

[ $# == 2 ] || {
    echo "Usage: apply_heimdal.sh <lorikeet_path>"
    exit 1
}

LORIKEET_PATH="$1"
IMPORT_HASH="$2"
S4PATH="$PWD"

pushd $LORIKEET_PATH || exit 1
git reset --hard 
git am --abort
popd

# From https://gist.github.com/kfish/7425248

apply () {
  filename=$1
  shift
  patch_args=$*

  gotSubject=no
  msg=""

  cat $filename | while read line; do
    if [ "$line" == "---" ]; then

      patch $patch_args -p1 < $filename
      git commit -a -m 'CHECK AUTHOR' -m "$msg"

      break
    fi
    if [ "$gotSubject" == "no" ]; then
      hdr=(${line//:/ })
      if [ "${hdr[0]}" == "Subject" ]; then
        gotSubject=yes
        msg="${hdr[@]:3}"
      fi
    else
      msg="$msg $line"
    fi
    msg="$msg
"
  done
}

try_patch() {
    commit="$1"
    git format-patch --stdout $commit -1 third_party/heimdal > "$commit".patch
    sed -i 's|/third_party/heimdal/|/|g' "$commit".patch
    sed -i "s|^---$|(cherry picked from Samba commit $commit)\n---|g" "$commit".patch
    pushd $LORIKEET_PATH || exit 1
    git reset --hard
    echo
    if patch -p1 --forward < "$S4PATH/$commit.patch"; then
	echo
	echo "Commit $commit can apply - applying"
	git reset --hard
	git am "$S4PATH/$commit.patch" || apply "$S4PATH/$commit.patch"
    else
	echo
	echo "Commit $commit does not apply cleanly"
	echo
    fi
    git am --abort
    popd || exit 1
}

commits="$(git log --pretty=oneline --reverse $IMPORT_HASH..HEAD -- third_party/heimdal | cut -d' ' -f1)"
for c in $commits; do
    git log $c -1
    echo -n "Try apply? [Y/n] "
    read answer
    case $answer in
	n*)
	    continue
	    ;;
	 *)
	    try_patch $c
	    ;;
    esac
done
