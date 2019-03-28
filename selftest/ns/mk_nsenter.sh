#!/bin/sh
#
# Helper script. If you want a 2nd shell that communicates with the testenv DC
# you can use the nsenter command to change the namespace you're in. However,
# this command is a bit unwieldly and changes depending on the testenv PID.
# We can generate a helper script on the fly that abstracts all this
# complexity, allowing you to use the same, simple command to change the
# namespace that you're in, e.g.
#   st/ad_dc/nsenter.sh

pid=$1
exports_file=$2

# The basic command to enter the testenv's network namespace.
# We enter the user namespace as well (as ourself, which is really the root
# user for the namespace), otherwise we need sudo to make this work.
nsenter_cmd="nsenter -t $pid --net --user --preserve-credentials"

# By default, the nsenter command will just start a new shell in the namespace.
# we use a wrapper helper script, which first loads all the environment
# variables that are usually defined in selftest (and prints some basic help).
helper_script="$(dirname $0)/nsenter-helper.sh $exports_file"

# generate the dynamic script
dyn_script="$(dirname $2)/nsenter.sh"
echo "#!/bin/sh" > $dyn_script
echo "$nsenter_cmd $helper_script" >> $dyn_script
chmod 755 $dyn_script

# return the script we created
echo "$dyn_script"

