#!/bin/sh

PYTHON="$1"
PAM_WRAPPER_SO_PATH="$2"
PAM_SET_ITEMS_SO_PATH="$3"
shift 3

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

samba_bindir="$BINDIR"
samba_tool="$samba_bindir/samba-tool"

if [ "$CREATE_USER" = yes ]; then
    CREATE_SERVER="$1"
    CREATE_USERNAME="$2"
    CREATE_PASSWORD="$3"
    shift 3
    $PYTHON $samba_tool user create "$USERNAME" "$PASSWORD" -H "ldap://$CREATE_SERVER" -U "$CREATE_USERNAME%$CREATE_PASSWORD"
    # reset password policies beside of minimum password age of 0 days
    $PYTHON $samba_tool domain passwordsettings set --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=0 --max-pwd-age=default -H "ldap://$CREATE_SERVER" -U "$CREATE_USERNAME%$CREATE_PASSWORD"
fi

PAM_WRAPPER_PATH="$BINDIR/default/third_party/pam_wrapper"

pam_winbind="$BINDIR/shared/pam_winbind.so"
service_dir="$SELFTEST_TMPDIR/pam_services"
service_file="$service_dir/samba"

mkdir $service_dir
echo "auth        required    $pam_winbind debug debug_state $PAM_OPTIONS" > $service_file
echo "account     required    $pam_winbind debug debug_state $PAM_OPTIONS" >> $service_file
echo "password    required    $PAM_SET_ITEMS_SO_PATH" >> $service_file
echo "password    required    $pam_winbind debug debug_state $PAM_OPTIONS" >> $service_file
echo "session     required    $pam_winbind debug debug_state $PAM_OPTIONS" >> $service_file

PAM_WRAPPER_SERVICE_DIR="$service_dir"
export PAM_WRAPPER_SERVICE_DIR
LD_PRELOAD="$LD_PRELOAD:$PAM_WRAPPER_SO_PATH"
export LD_PRELOAD

PAM_WRAPPER_DEBUGLEVEL=${PAM_WRAPPER_DEBUGLEVEL:="2"}
export PAM_WRAPPER_DEBUGLEVEL

case $PAM_OPTIONS in
    *use_authtok*)
        PAM_AUTHTOK="$NEWPASSWORD"
        export PAM_AUTHTOK
    ;;
    *try_authtok*)
        PAM_AUTHTOK="$NEWPASSWORD"
        export PAM_AUTHTOK
    ;;
esac

PAM_WRAPPER="1" PYTHONPATH="$PYTHONPATH:$PAM_WRAPPER_PATH:$(dirname $0)" $PYTHON -m samba.subunit.run samba.tests.pam_winbind_chauthtok
exit_code=$?

rm -rf $service_dir

if [ "$CREATE_USER" = yes ]; then
    $PYTHON $samba_tool user delete "$USERNAME" -H "ldap://$CREATE_SERVER" -U "$CREATE_USERNAME%$CREATE_PASSWORD"
    # reset password policies
    $PYTHON $samba_tool domain passwordsettings set --complexity=default --history-length=default --min-pwd-length=default --min-pwd-age=default --max-pwd-age=default -H "ldap://$CREATE_SERVER" -U "$CREATE_USERNAME%$CREATE_PASSWORD"
fi

exit $exit_code
