#################################################
# active directory support

with_ads_support=yes
AC_MSG_CHECKING([whether to use Active Directory])

AC_ARG_WITH(ads,
[   --with-ads  Active Directory support (default yes)],
[ case "$withval" in
    no)
	with_ads_support=no
	;;
  esac ])

if test x"$with_ads_support" = x"yes"; then
   AC_DEFINE(WITH_ADS,1,[Whether to include Active Directory support])
fi

AC_MSG_RESULT($with_ads_support)

FOUND_KRB5=no
if test x"$with_ads_support" = x"yes"; then

  #################################################
  # check for krb5-config from recent MIT and Heimdal kerberos 5
  AC_PATH_PROG(KRB5_CONFIG, krb5-config)
  AC_MSG_CHECKING(for working krb5-config)
  if test -x "$KRB5_CONFIG"; then
    LIBS="$LIBS `$KRB5_CONFIG --libs`"
    CFLAGS="$CFLAGS `$KRB5_CONFIG --cflags`" 
    CPPFLAGS="$CPPFLAGS `$KRB5_CONFIG --cflags`"
    FOUND_KRB5=yes
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no. Fallback to previous krb5 detection strategy)
  fi
  
  if test x$FOUND_KRB5 = x"no"; then
  #################################################
  # check for location of Kerberos 5 install
  AC_MSG_CHECKING(for kerberos 5 install path)
  AC_ARG_WITH(krb5,
  [  --with-krb5=base-dir    Locate Kerberos 5 support (default=/usr)],
  [ case "$withval" in
    no)
      AC_MSG_RESULT(no)
      ;;
    *)
      AC_MSG_RESULT(yes)
      LIBS="$LIBS -lkrb5"
      CFLAGS="$CFLAGS -I$withval/include"
      CPPFLAGS="$CPPFLAGS -I$withval/include"
      LDFLAGS="$LDFLAGS -L$withval/lib"
      FOUND_KRB5=yes
      ;;
    esac ],
    AC_MSG_RESULT(no)
  )
  fi

if test x$FOUND_KRB5 = x"no"; then
#################################################
# see if this box has the SuSE location for the heimdal kerberos implementation
AC_MSG_CHECKING(for /usr/include/heimdal)
if test -d /usr/include/heimdal; then
    if test -f /usr/lib/heimdal/lib/libkrb5.a; then
        LIBS="$LIBS -lkrb5"
        CFLAGS="$CFLAGS -I/usr/include/heimdal"
        CPPFLAGS="$CPPFLAGS -I/usr/include/heimdal"
        LDFLAGS="$LDFLAGS -L/usr/lib/heimdal/lib"
        AC_MSG_RESULT(yes)
    else
        LIBS="$LIBS -lkrb5"
        CFLAGS="$CFLAGS -I/usr/include/heimdal"
        CPPFLAGS="$CPPFLAGS -I/usr/include/heimdal"
        AC_MSG_RESULT(yes)
 
    fi
else
    AC_MSG_RESULT(no)
fi
fi


if test x$FOUND_KRB5 = x"no"; then
#################################################
# see if this box has the RedHat location for kerberos
AC_MSG_CHECKING(for /usr/kerberos)
if test -d /usr/kerberos -a -f /usr/kerberos/lib/libkrb5.a; then
    LIBS="$LIBS -lkrb5"
    LDFLAGS="$LDFLAGS -L/usr/kerberos/lib"
    CFLAGS="$CFLAGS -I/usr/kerberos/include"
    CPPFLAGS="$CPPFLAGS -I/usr/kerberos/include"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi
fi

  # now check for krb5.h. Some systems have the libraries without the headers!
  # note that this check is done here to allow for different kerberos
  # include paths
  AC_CHECK_HEADERS(krb5.h)

  # now check for gssapi headers.  This is also done here to allow for
  # different kerberos include paths
  AC_CHECK_HEADERS(gssapi.h gssapi/gssapi_generic.h gssapi/gssapi.h com_err.h)

  ##################################################################
  # we might need the k5crypto and com_err libraries on some systems
  AC_CHECK_LIB(com_err, _et_list, [LIBS="$LIBS -lcom_err"])
  AC_CHECK_LIB(k5crypto, krb5_encrypt_data, [LIBS="$LIBS -lk5crypto"])
  # Heimdal checks.
  AC_CHECK_LIB(crypto, des_set_key, [LIBS="$LIBS -lcrypto"])
  AC_CHECK_LIB(asn1, copy_Authenticator, [LIBS="$LIBS -lasn1 -lroken"])
  # Heimdal checks. On static Heimdal gssapi must be linked before krb5.
  AC_CHECK_LIB(gssapi, gss_display_status, [LIBS="$LIBS -lgssapi -lkrb5 -lasn1";
        AC_DEFINE(HAVE_GSSAPI,1,[Whether GSSAPI is available])])

  AC_CHECK_LIB(krb5, krb5_set_real_time, [AC_DEFINE(HAVE_KRB5_SET_REAL_TIME,1,[Whether krb5_set_real_time is available])])
  AC_CHECK_LIB(krb5, krb5_set_default_in_tkt_etypes, [AC_DEFINE(HAVE_KRB5_SET_DEFAULT_IN_TKT_ETYPES,1,[Whether krb5_set_default_in_tkt_etypes, is available])])
  AC_CHECK_LIB(krb5, krb5_set_default_tgs_ktypes, [AC_DEFINE(HAVE_KRB5_SET_DEFAULT_TGS_KTYPES,1,[Whether krb5_set_default_tgs_ktypes is available])])

  AC_CHECK_LIB(krb5, krb5_principal2salt, [AC_DEFINE(HAVE_KRB5_PRINCIPAL2SALT,1,[Whether krb5_principal2salt is available])])
  AC_CHECK_LIB(krb5, krb5_use_enctype, [AC_DEFINE(HAVE_KRB5_USE_ENCTYPE,1,[Whether krb5_use_enctype is available])])
  AC_CHECK_LIB(krb5, krb5_string_to_key, [AC_DEFINE(HAVE_KRB5_STRING_TO_KEY,1,[Whether krb5_string_to_key is available])])
  AC_CHECK_LIB(krb5, krb5_get_pw_salt, [AC_DEFINE(HAVE_KRB5_GET_PW_SALT,1,[Whether krb5_get_pw_salt is available])])
  AC_CHECK_LIB(krb5, krb5_string_to_key_salt, [AC_DEFINE(HAVE_KRB5_STRING_TO_KEY_SALT,1,[Whether krb5_string_to_key_salt is available])])
  AC_CHECK_LIB(krb5, krb5_auth_con_setkey, [AC_DEFINE(HAVE_KRB5_AUTH_CON_SETKEY,1,[Whether krb5_auth_con_setkey is available])])
  AC_CHECK_LIB(krb5, krb5_auth_con_setuseruserkey, [AC_DEFINE(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY,1,[Whether krb5_auth_con_setuseruserkey is available])])
  AC_CHECK_LIB(krb5, krb5_locate_kdc, [AC_DEFINE(HAVE_KRB5_LOCATE_KDC,1,[Whether krb5_locate_kdc is available])])
  AC_CHECK_LIB(krb5, krb5_get_permitted_enctypes, [AC_DEFINE(HAVE_KRB5_GET_PERMITTED_ENCTYPES,1,[Whether krb5_get_permitted_enctypes is available])])
  AC_CHECK_LIB(krb5, krb5_get_default_in_tkt_etypes, [AC_DEFINE(HAVE_KRB5_GET_DEFAULT_IN_TKT_ETYPES,1,[Whether krb5_get_default_in_tkt_etypes is available])])
  AC_CHECK_LIB(krb5, krb5_free_ktypes, [AC_DEFINE(HAVE_KRB5_FREE_KTYPES,1,[Whether krb5_free_ktypes is available])])

AC_CACHE_CHECK([for addrtype in krb5_address],samba_cv_HAVE_ADDRTYPE_IN_KRB5_ADDRESS,[
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_address kaddr; kaddr.addrtype = ADDRTYPE_INET;],
samba_cv_HAVE_ADDRTYPE_IN_KRB5_ADDRESS=yes,samba_cv_HAVE_ADDRTYPE_IN_KRB5_ADDRESS=no)])
if test x"$samba_cv_HAVE_ADDRTYPE_IN_KRB5_ADDRESS" = x"yes"; then
    AC_DEFINE(HAVE_ADDRTYPE_IN_KRB5_ADDRESS,1,[Whether the krb5_address struct has a addrtype property])
fi

AC_CACHE_CHECK([for addr_type in krb5_address],samba_cv_HAVE_ADDR_TYPE_IN_KRB5_ADDRESS,[
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_address kaddr; kaddr.addr_type = KRB5_ADDRESS_INET;],
samba_cv_HAVE_ADDR_TYPE_IN_KRB5_ADDRESS=yes,samba_cv_HAVE_ADDR_TYPE_IN_KRB5_ADDRESS=no)])
if test x"$samba_cv_HAVE_ADDR_TYPE_IN_KRB5_ADDRESS" = x"yes"; then
    AC_DEFINE(HAVE_ADDR_TYPE_IN_KRB5_ADDRESS,1,[Whether the krb5_address struct has a addr_type property])
fi

AC_CACHE_CHECK([for enc_part2 in krb5_ticket],samba_cv_HAVE_KRB5_TKT_ENC_PART2,[
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_ticket tkt; tkt.enc_part2->authorization_data[0]->contents = NULL;],
samba_cv_HAVE_KRB5_TKT_ENC_PART2=yes,samba_cv_HAVE_KRB5_TKT_ENC_PART2=no)])
if test x"$samba_cv_HAVE_KRB5_TKT_ENC_PART2" = x"yes"; then
    AC_DEFINE(HAVE_KRB5_TKT_ENC_PART2,1,[Whether the krb5_ticket struct has a enc_part2 property])
fi

AC_CACHE_CHECK([for keyvalue in krb5_keyblock],samba_cv_HAVE_KRB5_KEYBLOCK_KEYVALUE,[
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_keyblock key; key.keyvalue.data = NULL;],
samba_cv_HAVE_KRB5_KEYBLOCK_KEYVALUE=yes,samba_cv_HAVE_KRB5_KEYBLOCK_KEYVALUE=no)])
if test x"$samba_cv_HAVE_KRB5_KEYBLOCK_KEYVALUE" = x"yes"; then
    AC_DEFINE(HAVE_KRB5_KEYBLOCK_KEYVALUE,1,[Whether the krb5_keyblock struct has a keyvalue property])
fi

AC_CACHE_CHECK([for ENCTYPE_ARCFOUR_HMAC_MD5],samba_cv_HAVE_ENCTYPE_ARCFOUR_HMAC_MD5,[
AC_TRY_COMPILE([#include <krb5.h>],
[krb5_enctype enctype; enctype = ENCTYPE_ARCFOUR_HMAC_MD5;],
samba_cv_HAVE_ENCTYPE_ARCFOUR_HMAC_MD5=yes,samba_cv_HAVE_ENCTYPE_ARCFOUR_HMAC_MD5=no)])
if test x"$samba_cv_HAVE_ENCTYPE_ARCFOUR_HMAC_MD5" = x"yes"; then
    AC_DEFINE(HAVE_ENCTYPE_ARCFOUR_HMAC_MD5,1,[Whether the ENCTYPE_ARCFOUR_HMAC_MD5 key type is available])
fi

  ########################################################
  # now see if we can find the krb5 libs in standard paths
  # or as specified above
  AC_CHECK_LIB(krb5, krb5_mk_req_extended, [LIBS="$LIBS -lkrb5";
        AC_DEFINE(HAVE_KRB5,1,[Whether KRB5 is available])])

  ########################################################
  # now see if we can find the gssapi libs in standard paths
  AC_CHECK_LIB(gssapi_krb5, gss_display_status, [LIBS="$LIBS -lgssapi_krb5";
        AC_DEFINE(HAVE_GSSAPI,1,[Whether GSSAPI is available])])

fi

########################################################
# Compile with LDAP support?

with_ldap_support=yes
AC_MSG_CHECKING([whether to use LDAP])

AC_ARG_WITH(ldap,
[   --with-ldap  LDAP support (default yes)],
[ case "$withval" in
    no)
	with_ldap_support=no
	;;
  esac ])

AC_MSG_RESULT($with_ldap_support)

if test x"$with_ldap_support" = x"yes"; then

  ##################################################################
  # we might need the lber lib on some systems. To avoid link errors
  # this test must be before the libldap test
  AC_CHECK_LIB(lber, ber_scanf, [LIBS="$LIBS -llber"])

  ########################################################
  # now see if we can find the ldap libs in standard paths
  if test x$have_ldap != xyes; then
  AC_CHECK_LIB(ldap, ldap_domain2hostlist, [LIBS="$LIBS -lldap";
	AC_DEFINE(HAVE_LDAP,1,[Whether ldap is available])])

	########################################################
	# If we have LDAP, does it's rebind procedure take 2 or 3 arguments?
	# Check found in pam_ldap 145.
	AC_CHECK_FUNCS(ldap_set_rebind_proc)
	AC_CACHE_CHECK(whether ldap_set_rebind_proc takes 3 arguments, pam_ldap_cv_ldap_set_rebind_proc, [
	AC_TRY_COMPILE([
	#include <lber.h>
	#include <ldap.h>], [ldap_set_rebind_proc(0, 0, 0);], [pam_ldap_cv_ldap_set_rebind_proc=3], [pam_ldap_cv_ldap_set_rebind_proc=2]) ])
	AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS, $pam_ldap_cv_ldap_set_rebind_proc, [Number of arguments to ldap_set_rebind_proc])
  fi
fi

 check for a PAM clear-text auth, accounts, password and session support
with_pam_for_crypt=no
AC_MSG_CHECKING(whether to use PAM)
AC_ARG_WITH(pam,
[  --with-pam              Include PAM support (default=no)],
[ case "$withval" in
  yes)
    AC_MSG_RESULT(yes)
    AC_DEFINE(WITH_PAM,1,[Whether to include PAM support])
    AUTHLIBS="$AUTHLIBS -lpam"
    with_pam_for_crypt=yes
    ;;
  *)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  AC_MSG_RESULT(no)
)
