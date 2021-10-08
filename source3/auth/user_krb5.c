/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Simo Sorce 2010

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

#include "includes.h"
#include "auth.h"
#include "librpc/gen_ndr/krb5pac.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "passdb.h"
#include "lib/param/loadparm.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#ifdef HAVE_KRB5
NTSTATUS get_user_from_kerberos_info(TALLOC_CTX *mem_ctx,
				     const char *cli_name,
				     const char *princ_name,
				     struct PAC_LOGON_INFO *logon_info,
				     bool *is_mapped,
				     bool *mapped_to_guest,
				     char **ntuser,
				     char **ntdomain,
				     char **username,
				     struct passwd **_pw)
{
	NTSTATUS status;
	char *domain = NULL;
	char *realm = NULL;
	char *user = NULL;
	char *p;
	char *fuser = NULL;
	char *unixuser = NULL;
	struct passwd *pw = NULL;

	DEBUG(3, ("Kerberos ticket principal name is [%s]\n", princ_name));

	p = strchr_m(princ_name, '@');
	if (!p) {
		DEBUG(3, ("[%s] Doesn't look like a valid principal\n",
			  princ_name));
		return NT_STATUS_LOGON_FAILURE;
	}

	user = talloc_strndup(mem_ctx, princ_name, p - princ_name);
	if (!user) {
		return NT_STATUS_NO_MEMORY;
	}

	realm = talloc_strdup(talloc_tos(), p + 1);
	if (!realm) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!strequal(realm, lp_realm())) {
		DEBUG(3, ("Ticket for foreign realm %s@%s\n", user, realm));
		if (!lp_allow_trusted_domains()) {
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (logon_info && logon_info->info3.base.logon_domain.string) {
		domain = talloc_strdup(mem_ctx,
					logon_info->info3.base.logon_domain.string);
		if (!domain) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(10, ("Domain is [%s] (using PAC)\n", domain));
	} else {

		/* If we have winbind running, we can (and must) shorten the
		   username by using the short netbios name. Otherwise we will
		   have inconsistent user names. With Kerberos, we get the
		   fully qualified realm, with ntlmssp we get the short
		   name. And even w2k3 does use ntlmssp if you for example
		   connect to an ip address. */

		wbcErr wbc_status;
		struct wbcDomainInfo *info = NULL;

		DEBUG(10, ("Mapping [%s] to short name using winbindd\n",
			   realm));

		wbc_status = wbcDomainInfo(realm, &info);

		if (WBC_ERROR_IS_OK(wbc_status)) {
			domain = talloc_strdup(mem_ctx,
						info->short_name);
			wbcFreeMemory(info);
		} else {
			DEBUG(3, ("Could not find short name: %s\n",
				  wbcErrorString(wbc_status)));
			domain = talloc_strdup(mem_ctx, realm);
		}
		if (!domain) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(10, ("Domain is [%s] (using Winbind)\n", domain));
	}

	fuser = talloc_asprintf(mem_ctx,
				"%s%c%s",
				domain,
				*lp_winbind_separator(),
				user);
	if (!fuser) {
		return NT_STATUS_NO_MEMORY;
	}

	*is_mapped = map_username(mem_ctx, fuser, &fuser);
	if (!fuser) {
		return NT_STATUS_NO_MEMORY;
	}
	*mapped_to_guest = false;

	pw = smb_getpwnam(mem_ctx, fuser, &unixuser, true);
	if (pw) {
		if (!unixuser) {
			return NT_STATUS_NO_MEMORY;
		}
		/* if a real user check pam account restrictions */
		/* only really performed if "obey pam restriction" is true */
		/* do this before an eventual mapping to guest occurs */
		status = smb_pam_accountcheck(pw->pw_name, cli_name);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("PAM account restrictions prevent user "
				  "[%s] login\n", unixuser));
			return status;
		}
	}
	if (!pw) {

		/* this was originally the behavior of Samba 2.2, if a user
		   did not have a local uid but has been authenticated, then
		   map them to a guest account */

		if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_UID) {
			*mapped_to_guest = true;
			fuser = talloc_strdup(mem_ctx, lp_guest_account());
			if (!fuser) {
				return NT_STATUS_NO_MEMORY;
			}
			pw = smb_getpwnam(mem_ctx, fuser, &unixuser, false);
		}

		/* extra sanity check that the guest account is valid */
		if (!pw) {
			DBG_NOTICE("Username %s is invalid on this system\n",
				  fuser);
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (!unixuser) {
		return NT_STATUS_NO_MEMORY;
	}

	*username = talloc_strdup(mem_ctx, unixuser);
	if (!*username) {
		return NT_STATUS_NO_MEMORY;
	}
	*ntuser = user;
	*ntdomain = domain;
	*_pw = pw;

	return NT_STATUS_OK;
}

NTSTATUS make_session_info_krb5(TALLOC_CTX *mem_ctx,
				char *ntuser,
				char *ntdomain,
				char *username,
				struct passwd *pw,
				const struct netr_SamInfo3 *info3,
				bool mapped_to_guest, bool username_was_mapped,
				DATA_BLOB *session_key,
				struct auth_session_info **session_info)
{
	NTSTATUS status;
	struct auth_serversupplied_info *server_info;

	if (mapped_to_guest) {
		status = make_server_info_guest(mem_ctx, &server_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("make_server_info_guest failed: %s!\n",
				  nt_errstr(status)));
			return status;
		}

	} else if (info3) {
		/* pass the unmapped username here since map_username()
		   will be called again in make_server_info_info3() */

		status = make_server_info_info3(mem_ctx,
						ntuser, ntdomain,
						&server_info,
						info3);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("make_server_info_info3 failed: %s!\n",
				  nt_errstr(status)));
			return status;
		}

	} else {
		/*
		 * We didn't get a PAC, we have to make up the user
		 * ourselves. Try to ask the pdb backend to provide
		 * SID consistency with ntlmssp session setup
		 */
		struct samu *sampass;

		sampass = samu_new(talloc_tos());
		if (sampass == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		if (pdb_getsampwnam(sampass, username)) {
			DEBUG(10, ("found user %s in passdb, calling "
				   "make_server_info_sam\n", username));
			status = make_server_info_sam(mem_ctx,
						      sampass,
						      &server_info);
		} else {
			/*
			 * User not in passdb, make it up artificially
			 */
			DEBUG(10, ("didn't find user %s in passdb, calling "
				   "make_server_info_pw\n", username));
			status = make_server_info_pw(mem_ctx,
						     username,
						     pw,
						     &server_info);
		}

		TALLOC_FREE(sampass);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("make_server_info_[sam|pw] failed: %s!\n",
				  nt_errstr(status)));
			return status;
                }

		/* make_server_info_pw does not set the domain. Without this
		 * we end up with the local netbios name in substitutions for
		 * %D. */

		if (server_info->info3 != NULL) {
			server_info->info3->base.logon_domain.string =
				talloc_strdup(server_info->info3, ntdomain);
		}
	}

	server_info->nss_token |= username_was_mapped;

	status = create_local_token(mem_ctx, server_info, session_key, ntuser, session_info);
	talloc_free(server_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("failed to create local token: %s\n",
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

#else /* HAVE_KRB5 */
NTSTATUS get_user_from_kerberos_info(TALLOC_CTX *mem_ctx,
				     const char *cli_name,
				     const char *princ_name,
				     struct PAC_LOGON_INFO *logon_info,
				     bool *is_mapped,
				     bool *mapped_to_guest,
				     char **ntuser,
				     char **ntdomain,
				     char **username,
				     struct passwd **_pw)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS make_session_info_krb5(TALLOC_CTX *mem_ctx,
				char *ntuser,
				char *ntdomain,
				char *username,
				struct passwd *pw,
				const struct netr_SamInfo3 *info3,
				bool mapped_to_guest, bool username_was_mapped,
				DATA_BLOB *session_key,
				struct auth_session_info **session_info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

#endif /* HAVE_KRB5 */
