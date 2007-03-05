#!/bin/sh
xterm -e 'echo -e "Welcome to the Samba4 Test environment\n\
This matches the client environment used in make test\n\
smbd is pid `cat $PIDDIR/smbd.pid`\n\
\n\
Some useful environment variables:\n\
AUTH=$AUTH\n\
TORTURE_OPTIONS=$TORTURE_OPTIONS\n\
CONFIGURATION=$CONFIGURATION\n\
SERVER=$SERVER\n\
NETBIOSNAME=$NETBIOSNAME" && bash'
