/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2011
   Copyright (C) Simo Sorce 2010.

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
#ifdef HAVE_KRB5

#include "libcli/auth/krb5_wrap.h"

/* The Heimdal OID for getting the PAC */
#define EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH 8
/*					                EXTRACTION OID		   AUTHZ ID */
#define EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID "\x2a\x85\x70\x2b\x0d\x03" "\x81\x00"

static gss_OID_desc pac_data_oid = {
	EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH,
	(void *)EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID
};

NTSTATUS gssapi_obtain_pac_blob(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				gss_name_t gss_client_name,
				DATA_BLOB *pac_blob)
{
	NTSTATUS status;
	OM_uint32 gss_maj, gss_min;
#ifdef HAVE_GSS_GET_NAME_ATTRIBUTE
	gss_buffer_desc pac_buffer;
	gss_buffer_desc pac_display_buffer;
	gss_buffer_desc pac_name = {
		.value = "urn:mspac:",
		.length = sizeof("urn:mspac:")-1
	};
	int more = -1;
	int authenticated = false;
	int complete = false;

	gss_maj = gss_get_name_attribute(
		&gss_min, gss_client_name, &pac_name,
		&authenticated, &complete,
		&pac_buffer, &pac_display_buffer, &more);

	if (gss_maj != 0) {
		DEBUG(0, ("obtaining PAC via GSSAPI gss_get_name_attribute failed: %s\n",
			  gssapi_error_string(mem_ctx, gss_maj, gss_min, gss_mech_krb5)));
		return NT_STATUS_ACCESS_DENIED;
	} else if (authenticated && complete) {
		/* The PAC blob is returned directly */
		*pac_blob = data_blob_talloc(mem_ctx, pac_buffer.value,
					    pac_buffer.length);

		if (!pac_blob->data) {
			status = NT_STATUS_NO_MEMORY;
		} else {
			status = NT_STATUS_OK;
		}

		gss_maj = gss_release_buffer(&gss_min, &pac_buffer);
		gss_maj = gss_release_buffer(&gss_min, &pac_display_buffer);
		return status;
	} else {
		DEBUG(0, ("obtaining PAC via GSSAPI failed: authenticated: %s, complete: %s, more: %s\n",
			  authenticated ? "true" : "false",
			  complete ? "true" : "false",
			  more ? "true" : "false"));
		return NT_STATUS_ACCESS_DENIED;
	}

#elif defined(HAVE_GSS_INQUIRE_SEC_CONTEXT_BY_OID)

	gss_buffer_set_t set = GSS_C_NO_BUFFER_SET;

	/* If we didn't have the routine to get a verified, validated
	 * PAC (supplied only by MIT at the time of writing), then try
	 * with the Heimdal OID (fetches the PAC directly and always
	 * validates) */
	gss_maj = gss_inquire_sec_context_by_oid(
				&gss_min, gssapi_context,
				&pac_data_oid, &set);

	/* First check for the error MIT gives for an unknown OID */
	if (gss_maj == GSS_S_UNAVAILABLE) {
		DEBUG(1, ("unable to obtain a PAC against this GSSAPI library.  "
			  "GSSAPI secured connections are available only with Heimdal or MIT Kerberos >= 1.8\n"));
	} else if (gss_maj != 0) {
		DEBUG(2, ("obtaining PAC via GSSAPI gss_inqiure_sec_context_by_oid (Heimdal OID) failed: %s\n",
			  gssapi_error_string(mem_ctx, gss_maj, gss_min, gss_mech_krb5)));
	} else {
		if (set == GSS_C_NO_BUFFER_SET) {
			DEBUG(0, ("gss_inquire_sec_context_by_oid returned unknown "
				  "data in results.\n"));
			return NT_STATUS_INTERNAL_ERROR;
		}

		/* The PAC blob is returned directly */
		*pac_blob = data_blob_talloc(mem_ctx, set->elements[0].value,
					    set->elements[0].length);
		if (!pac_blob->data) {
			status = NT_STATUS_NO_MEMORY;
		} else {
			status = NT_STATUS_OK;
		}

		gss_maj = gss_release_buffer_set(&gss_min, &set);
		return status;
	}
#else
	DEBUG(1, ("unable to obtain a PAC against this GSSAPI library.  "
		  "GSSAPI secured connections are available only with Heimdal or MIT Kerberos >= 1.8\n"));
#endif
	return NT_STATUS_ACCESS_DENIED;
}
#endif
