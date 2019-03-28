#!/bin/sh
#
# Helper script that gets run with nsenter to manually setup a secondary shell
# session to a given namespace testenv. This basically just sets up the same
# environment variables as you normally get with selftest, for convenience.

if [ $# -lt 1 ] ; then
    echo "Usage: $0 <exports-file>"
    exit 1
fi

# we get passed a exports file with all the environment variables defined
exports_file=$1

# read the exports file so the new shell has appropriate variables setup
# (we export rather than sourcing here so they get inherited by the subshell)
while read -r line ; do
    export $line
    # dump them for the user too
    echo $line
done < $exports_file

echo ""
echo "Entered $NETBIOSNAME namespace, with above variables defined."
echo "Use CTRL+D or exit to leave the namespace."
echo ""

# start a shell session in the new namespace
$SHELL


