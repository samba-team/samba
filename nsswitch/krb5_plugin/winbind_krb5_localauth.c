/*
   Unix SMB/CIFS implementation.

   A localauth plugin for MIT Kerberos

   Copyright (C) 2018      Andreas Schneider <asn@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include <krb5/localauth_plugin.h>
#include <wbclient.h>
#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#endif

struct krb5_localauth_moddata_st {
	struct wbcContext *wbc_ctx;
};

/*
 * Initialize the module data.
 *
 * This creates the wbclient context.
 */
static krb5_error_code winbind_init(krb5_context context,
				    krb5_localauth_moddata *data)
{
	krb5_localauth_moddata d;

	*data = NULL;
	d = malloc(sizeof(struct krb5_localauth_moddata_st));
	if (d == NULL) {
		return ENOMEM;
	}

	d->wbc_ctx = wbcCtxCreate();
	if (d->wbc_ctx == NULL) {
		free(d);
		return ENOMEM;
	}

	wbcSetClientProcessName("krb5_localauth_plugin");

	*data = d;

	return 0;
}

/*
 * Release resources used by module data.
 */
static void winbind_fini(krb5_context context, krb5_localauth_moddata data)
{
	wbcCtxFree(data->wbc_ctx);
	free(data);
	data = NULL;
}

/*
 * Determine whether aname is authorized to log in as the local account lname.
 *
 * Return 0 if aname is authorized, EPERM if aname is authoritatively not
 * authorized, KRB5_PLUGIN_NO_HANDLE if the module cannot determine whether
 * aname is authorized, and any other error code for a serious failure to
 * process the request.  aname will be considered authorized if at least one
 * module returns 0 and all other modules return KRB5_PLUGIN_NO_HANDLE.
 */
static krb5_error_code winbind_userok(krb5_context context,
				      krb5_localauth_moddata data,
				      krb5_const_principal aname,
				      const char *lname)
{
	krb5_error_code code = 0;
	char *princ_str = NULL;
	struct passwd *pwd = NULL;
	uid_t princ_uid = (uid_t)-1;
	uid_t lname_uid = (uid_t)-1;
	wbcErr wbc_status;
	int cmp;

	code = krb5_unparse_name(context, aname, &princ_str);
	if (code != 0) {
		return code;
	}

	cmp = strcasecmp(princ_str, lname);
	if (cmp == 0) {
		goto out;
	}

	wbc_status = wbcCtxGetpwnam(data->wbc_ctx,
				    princ_str,
				    &pwd);
	switch (wbc_status) {
	case WBC_ERR_SUCCESS:
		princ_uid = pwd->pw_uid;
		code = 0;
		break;
	case WBC_ERR_UNKNOWN_USER:
	/* match other insane libwbclient return codes */
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
	case WBC_ERR_DOMAIN_NOT_FOUND:
		code = KRB5_PLUGIN_NO_HANDLE;
		break;
	default:
		code = EIO;
		break;
	}
	wbcFreeMemory(pwd);
	if (code != 0) {
		goto out;
	}

	wbc_status = wbcCtxGetpwnam(data->wbc_ctx,
				    lname,
				    &pwd);
	switch (wbc_status) {
	case WBC_ERR_SUCCESS:
		lname_uid = pwd->pw_uid;
		break;
	case WBC_ERR_UNKNOWN_USER:
	/* match other insane libwbclient return codes */
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
	case WBC_ERR_DOMAIN_NOT_FOUND:
		code = KRB5_PLUGIN_NO_HANDLE;
		break;
	default:
		code = EIO;
		break;
	}
	wbcFreeMemory(pwd);
	if (code != 0) {
		goto out;
	}

	if (princ_uid != lname_uid) {
		code = EPERM;
	}

	com_err("winbind_localauth",
		code,
		"Access %s: %s (uid=%u) %sequal to %s (uid=%u)",
		code == 0 ? "granted" : "denied",
		princ_str,
		(unsigned int)princ_uid,
		code == 0 ? "" : "not ",
		lname,
		(unsigned int)lname_uid);

out:
	krb5_free_unparsed_name(context, princ_str);

	return code;
}

/*
 * Determine the local account name corresponding to aname.
 *
 * Return 0 and set *lname_out if a mapping can be determined; the contents of
 * *lname_out will later be released with a call to the module's free_string
 * method.  Return KRB5_LNAME_NOTRANS if no mapping can be determined.  Return
 * any other error code for a serious failure to process the request; this will
 * halt the krb5_aname_to_localname operation.
 *
 * If the module's an2ln_types field is set, this method will only be invoked
 * when a profile "auth_to_local" value references one of the module's types.
 * type and residual will be set to the type and residual of the auth_to_local
 * value.
 *
 * If the module's an2ln_types field is not set but the an2ln method is
 * implemented, this method will be invoked independently of the profile's
 * auth_to_local settings, with type and residual set to NULL.  If multiple
 * modules are registered with an2ln methods but no an2ln_types field, the
 * order of invocation is not defined, but all such modules will be consulted
 * before the built-in mechanisms are tried.
 */
static krb5_error_code winbind_an2ln(krb5_context context,
				     krb5_localauth_moddata data,
				     const char *type,
				     const char *residual,
				     krb5_const_principal aname,
				     char **lname_out)
{
	krb5_error_code code = 0;
	char *princ_str = NULL;
	char *name = NULL;
	struct passwd *pwd = NULL;
	wbcErr wbc_status;

	code = krb5_unparse_name(context, aname, &princ_str);
	if (code != 0) {
		return code;
	}

	wbc_status = wbcCtxGetpwnam(data->wbc_ctx,
				    princ_str,
				    &pwd);
	krb5_free_unparsed_name(context, princ_str);
	switch (wbc_status) {
	case WBC_ERR_SUCCESS:
		name = strdup(pwd->pw_name);
		code = 0;
		break;
	case WBC_ERR_UNKNOWN_USER:
	/* match other insane libwbclient return codes */
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
	case WBC_ERR_DOMAIN_NOT_FOUND:
		code = KRB5_LNAME_NOTRANS;
		break;
	default:
		code = EIO;
		break;
	}
	wbcFreeMemory(pwd);
	if (code != 0) {
		return code;
	}

	if (name == NULL) {
		return ENOMEM;
	}

	*lname_out = name;

	return code;
}

/*
 * Release the memory returned by an invocation of an2ln.
 */
static void winbind_free_string(krb5_context context,
				krb5_localauth_moddata data,
				char *str)
{
	free(str);
}

krb5_error_code
localauth_winbind_initvt(krb5_context context,
			 int maj_ver,
			 int min_ver,
			 krb5_plugin_vtable vtable);

krb5_error_code
localauth_winbind_initvt(krb5_context context,
			 int maj_ver,
			 int min_ver,
			 krb5_plugin_vtable vtable)
{
	krb5_localauth_vtable vt = (krb5_localauth_vtable)vtable;

	if (maj_ver != 1) {
		com_err("winbind_localauth",
			EINVAL,
			"Failed to load, plugin API changed.");
		return KRB5_PLUGIN_VER_NOTSUPP;
	}

	vt->init = winbind_init;
	vt->fini = winbind_fini;
	vt->name = "winbind";
	vt->an2ln = winbind_an2ln;
	vt->userok = winbind_userok;
	vt->free_string = winbind_free_string;

	return 0;
}
