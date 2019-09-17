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

PAM_OPTIONS="$1"
export PAM_OPTIONS
shift 1

PAM_WRAPPER_PATH="$BINDIR/default/third_party/pam_wrapper"

pam_winbind="$BINDIR/shared/pam_winbind.so"
service_dir="$SELFTEST_TMPDIR/pam_services"
service_file="$service_dir/samba"

mkdir $service_dir

PAM_WRAPPER="1"
export PAM_WRAPPER
PAM_WRAPPER_SERVICE_DIR="$service_dir"
export PAM_WRAPPER_SERVICE_DIR
LD_PRELOAD="$LD_PRELOAD:$PAM_WRAPPER_SO_PATH"
export LD_PRELOAD

PAM_WRAPPER_DEBUGLEVEL=${PAM_WRAPPER_DEBUGLEVEL:="2"}
export PAM_WRAPPER_DEBUGLEVEL

# TEST with warn_pwd_expire=50
#
# This should produce a warning that the password will expire in 42 days
#
WARN_PWD_EXPIRE="50"
export WARN_PWD_EXPIRE

echo "auth        required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" > $service_file
echo "account     required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" >> $service_file
echo "password    required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" >> $service_file
echo "session     required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" >> $service_file

PYTHONPATH="$PYTHONPATH:$PAM_WRAPPER_PATH:$(dirname $0)" $PYTHON -m samba.subunit.run samba.tests.pam_winbind_warn_pwd_expire
exit_code=$?
if [ $exit_code -ne 0 ]; then
	rm -rf $service_dir
	exit $exit_code
fi

# TEST with warn_pwd_expire=0
#
WARN_PWD_EXPIRE="0"
export WARN_PWD_EXPIRE

echo "auth        required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" > $service_file
echo "account     required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" >> $service_file
echo "password    required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" >> $service_file
echo "session     required    $pam_winbind debug debug_state warn_pwd_expire=$WARN_PWD_EXPIRE $PAM_OPTIONS" >> $service_file

PYTHONPATH="$PYTHONPATH:$PAM_WRAPPER_PATH:$(dirname $0)" $PYTHON -m samba.subunit.run samba.tests.pam_winbind_warn_pwd_expire
exit_code=$?
if [ $exit_code -ne 0 ]; then
	rm -rf $service_dir
	exit $exit_code
fi

rm -rf $service_dir

exit $exit_code
