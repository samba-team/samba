#!/bin/sh
# add a autobuild message to the HEAD commit

branch=$(git branch --contains HEAD | grep '^\* ' | sed -e 's/^\* //')

if grep -q "^Autobuild\-User($branch): " "$1"; then
    echo "Already marked as tested for $branch"
    exit 0
fi

fullname=$(getent passwd $USER | cut -d: -f5| cut -d',' -f1)
mailaddr=$(git config user.email)
if test -z "$mailaddr" ; then
	mailaddr="$USER@samba.org"
fi
cat <<EOF >> "$1"

Autobuild-User($branch): $fullname <$mailaddr>
Autobuild-Date($branch): $(date) on $(hostname)
EOF
exit 0
