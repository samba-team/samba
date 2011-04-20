/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   Copyright (C) Stefan Metzmacher 2004-2005
   Copyright (C) Guenther Deschner 2005,2007,2008

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
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "smb_krb5.h"
#include "libads/kerberos_proto.h"

#ifdef HAVE_KRB5

/****************************************************************
Given a username, password and other details, return the
PAC_LOGON_INFO (the structure containing the important user
information such as groups).
****************************************************************/

NTSTATUS kerberos_return_pac(TALLOC_CTX *mem_ctx,
			     const char *name,
			     const char *pass,
			     time_t time_offset,
			     time_t *expire_time,
			     time_t *renew_till_time,
			     const char *cache_name,
			     bool request_pac,
			     bool add_netbios_addr,
			     time_t renewable_time,
			     const char *impersonate_princ_s,
			     struct PAC_LOGON_INFO **logon_info)
{
	krb5_error_code ret;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	DATA_BLOB tkt, ap_rep, sesskey1, sesskey2;
	char *client_princ_out = NULL;
	const char *auth_princ = NULL;
	const char *local_service = NULL;
	const char *cc = "MEMORY:kerberos_return_pac";

	ZERO_STRUCT(tkt);
	ZERO_STRUCT(ap_rep);
	ZERO_STRUCT(sesskey1);
	ZERO_STRUCT(sesskey2);

	if (!name || !pass) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cache_name) {
		cc = cache_name;
	}

	if (!strchr_m(name, '@')) {
		auth_princ = talloc_asprintf(mem_ctx, "%s@%s", name,
			lp_realm());
	} else {
		auth_princ = name;
	}
	NT_STATUS_HAVE_NO_MEMORY(auth_princ);

	local_service = talloc_asprintf(mem_ctx, "%s$@%s",
					global_myname(), lp_realm());
	NT_STATUS_HAVE_NO_MEMORY(local_service);

	ret = kerberos_kinit_password_ext(auth_princ,
					  pass,
					  time_offset,
					  expire_time,
					  renew_till_time,
					  cc,
					  request_pac,
					  add_netbios_addr,
					  renewable_time,
					  &status);
	if (ret) {
		DEBUG(1,("kinit failed for '%s' with: %s (%d)\n",
			auth_princ, error_message(ret), ret));
		/* status already set */
		goto out;
	}

	DEBUG(10,("got TGT for %s in %s\n", auth_princ, cc));
	if (expire_time) {
		DEBUGADD(10,("\tvalid until: %s (%d)\n",
			http_timestring(talloc_tos(), *expire_time),
			(int)*expire_time));
	}
	if (renew_till_time) {
		DEBUGADD(10,("\trenewable till: %s (%d)\n",
			http_timestring(talloc_tos(), *renew_till_time),
			(int)*renew_till_time));
	}

	/* we cannot continue with krb5 when UF_DONT_REQUIRE_PREAUTH is set,
	 * in that case fallback to NTLM - gd */

	if (expire_time && renew_till_time &&
	    (*expire_time == 0) && (*renew_till_time == 0)) {
		return NT_STATUS_INVALID_LOGON_TYPE;
	}

	ret = cli_krb5_get_ticket(mem_ctx,
				  local_service,
				  time_offset,
				  &tkt,
				  &sesskey1,
				  0,
				  cc,
				  NULL,
				  impersonate_princ_s);
	if (ret) {
		DEBUG(1,("failed to get ticket for %s: %s\n",
			local_service, error_message(ret)));
		if (impersonate_princ_s) {
			DEBUGADD(1,("tried S4U2SELF impersonation as: %s\n",
				impersonate_princ_s));
		}
		status = krb5_to_nt_status(ret);
		goto out;
	}
	status = ads_verify_ticket(mem_ctx,
				   lp_realm(),
				   time_offset,
				   &tkt,
				   &client_princ_out,
				   logon_info,
				   &ap_rep,
				   &sesskey2,
				   False);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("ads_verify_ticket failed: %s\n",
			nt_errstr(status)));
		goto out;
	}

	if (!*logon_info) {
		DEBUG(1,("no PAC\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

out:
	if (cc != cache_name) {
		ads_kdestroy(cc);
	}

	data_blob_free(&tkt);
	data_blob_free(&ap_rep);
	data_blob_free(&sesskey1);
	data_blob_free(&sesskey2);

	TALLOC_FREE(client_princ_out);

	return status;
}

#endif
