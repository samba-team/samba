#!/bin/sh

PYTHON="$1"
PAM_WRAPPER_SO_PATH="$2"
shift 2

DOMAIN="$1"
export DOMAIN
USERNAME="$2"
export USERNAME
PASSWORD="$3"
export PASSWORD
shift 3

PAM_WRAPPER_PATH="$BINDIR/default/lib/pam_wrapper"

pam_winbind="$BINDIR/shared/pam_winbind.so"
service_dir="$SELFTEST_TMPDIR/pam_services"
service_file="$service_dir/samba"

mkdir $service_dir
echo "auth        required    $pam_winbind debug debug_state" > $service_file
echo "account     required    $pam_winbind debug debug_state" >> $service_file
echo "password    required    $pam_winbind debug debug_state" >> $service_file
echo "session     required    $pam_winbind debug debug_state" >> $service_file

PAM_WRAPPER="1"
export PAM_WRAPPER
PAM_WRAPPER_SERVICE_DIR="$service_dir"
export PAM_WRAPPER_SERVICE_DIR
LD_PRELOAD="$LD_PRELOAD:$PAM_WRAPPER_SO_PATH"
export LD_PRELOAD

PAM_WRAPPER_DEBUGLEVEL=${PAM_WRAPPER_DEBUGLEVEL:="2"}
export PAM_WRAPPER_DEBUGLEVEL

PYTHONPATH="$PYTHONPATH:$PAM_WRAPPER_PATH:$(dirname $0)" $PYTHON -m samba.subunit.run samba.tests.pam_winbind
exit_code=$?

rm -rf $service_dir

exit_code=0
exit $exit_code
