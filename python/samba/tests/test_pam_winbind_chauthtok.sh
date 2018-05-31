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
NEWPASSWORD="$4"
export NEWPASSWORD
PAM_OPTIONS="$5"
export PAM_OPTIONS
CREATE_USER="$6"
shift 6

if [ "$CREATE_USER" = yes ]; then
    CREATE_SERVER="$1"
    CREATE_USERNAME="$2"
    CREATE_PASSWORD="$3"
    shift 3
    ./bin/samba-tool user create "$USERNAME" "$PASSWORD" -H "ldap://$CREATE_SERVER" -U "$CREATE_USERNAME%$CREATE_PASSWORD"
fi

PAM_WRAPPER_PATH="$BINDIR/default/third_party/pam_wrapper"

pam_winbind="$BINDIR/shared/pam_winbind.so"
service_dir="$SELFTEST_TMPDIR/pam_services"
service_file="$service_dir/samba"

mkdir $service_dir
echo "auth        required    $pam_winbind debug debug_state $PAM_OPTIONS" > $service_file
echo "account     required    $pam_winbind debug debug_state $PAM_OPTIONS" >> $service_file
echo "password    required    pam_set_items.so" >> $service_file
echo "password    required    $pam_winbind debug debug_state $PAM_OPTIONS" >> $service_file
echo "session     required    $pam_winbind debug debug_state $PAM_OPTIONS" >> $service_file


PAM_WRAPPER_SERVICE_DIR="$service_dir"
export PAM_WRAPPER_SERVICE_DIR
LD_PRELOAD="$LD_PRELOAD:$PAM_WRAPPER_SO_PATH"
export LD_PRELOAD

PAM_WRAPPER_DEBUGLEVEL=${PAM_WRAPPER_DEBUGLEVEL:="2"}
export PAM_WRAPPER_DEBUGLEVEL

PAM_WRAPPER="1" PYTHONPATH="$PYTHONPATH:$PAM_WRAPPER_PATH:$(dirname $0)" $PYTHON -m samba.subunit.run samba.tests.pam_winbind_chauthtok
exit_code=$?

rm -rf $service_dir

if [ "$CREATE_USER" = yes ]; then
    ./bin/samba-tool user delete "$USERNAME" -H "ldap://$CREATE_SERVER" -U "$CREATE_USERNAME%$CREATE_PASSWORD"
fi

exit $exit_code
