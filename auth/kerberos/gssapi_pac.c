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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#ifdef HAVE_KRB5

#include "auth/kerberos/pac_utils.h"

#if 0
/* FIXME - need proper configure/waf test
 * to determine if gss_mech_krb5 and friends
 * exist. JRA.
 */
/*
 * These are not exported by Solaris -lkrb5
 * Maybe move to libreplace somewhere?
 */
static const gss_OID_desc krb5_gss_oid_array[] = {
	/* this is the official, rfc-specified OID */
	{ 9, "\052\206\110\206\367\022\001\002\002" },
	/* this is the pre-RFC mech OID */
	{ 5, "\053\005\001\005\002" },
	/* this is the unofficial, incorrect mech OID emitted by MS */
	{ 9, "\052\206\110\202\367\022\001\002\002" },
	{ 0, 0 }
};

const gss_OID_desc * const gss_mech_krb5              = krb5_gss_oid_array+0;
const gss_OID_desc * const gss_mech_krb5_old          = krb5_gss_oid_array+1;
const gss_OID_desc * const gss_mech_krb5_wrong        = krb5_gss_oid_array+2;
#endif

#ifndef GSS_KRB5_INQ_SSPI_SESSION_KEY_OID
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH 11
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"
#endif

gss_OID_desc gse_sesskey_inq_oid = {
	GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH,
	discard_const(GSS_KRB5_INQ_SSPI_SESSION_KEY_OID)
};

#ifndef GSS_KRB5_SESSION_KEY_ENCTYPE_OID
#define GSS_KRB5_SESSION_KEY_ENCTYPE_OID_LENGTH 10
#define GSS_KRB5_SESSION_KEY_ENCTYPE_OID  "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04"
#endif

gss_OID_desc gse_sesskeytype_oid = {
	GSS_KRB5_SESSION_KEY_ENCTYPE_OID_LENGTH,
	discard_const(GSS_KRB5_SESSION_KEY_ENCTYPE_OID)
};

/* The Heimdal OID for getting the PAC */
#define EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH 8
/*					                EXTRACTION OID		   AUTHZ ID */
#define EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID "\x2a\x85\x70\x2b\x0d\x03" "\x81\x00"

NTSTATUS gssapi_obtain_pac_blob(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				gss_name_t gss_client_name,
				DATA_BLOB *pac_blob)
{
	NTSTATUS status;
	OM_uint32 gss_maj, gss_min;
#ifdef HAVE_GSS_GET_NAME_ATTRIBUTE
/*
 * gss_get_name_attribute() in MIT krb5 1.10.0 can return unintialized pac_display_buffer
 * and later gss_release_buffer() will crash on attempting to release it.
 *
 * So always initialize the buffer descriptors.
 *
 * See following links for more details:
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=658514
 * http://krbdev.mit.edu/rt/Ticket/Display.html?user=guest&pass=guest&id=7087
 */
	gss_buffer_desc pac_buffer = {
		.value = NULL,
		.length = 0
	};
	gss_buffer_desc pac_display_buffer = {
		.value = NULL,
		.length = 0
	};
	gss_buffer_desc pac_name = {
		.value = discard_const("urn:mspac:"),
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
		gss_OID oid = discard_const(gss_mech_krb5);
		DBG_NOTICE("obtaining PAC via GSSAPI gss_get_name_attribute "
			   "failed: %s\n", gssapi_error_string(mem_ctx,
							       gss_maj, gss_min,
							       oid));
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
	gss_OID_desc pac_data_oid = {
		.elements = discard_const(EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID),
		.length = EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH
	};

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

NTSTATUS gssapi_get_session_key(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				DATA_BLOB *session_key, 
				uint32_t *keytype)
{
	OM_uint32 gss_min, gss_maj;
	gss_buffer_set_t set = GSS_C_NO_BUFFER_SET;

	gss_maj = gss_inquire_sec_context_by_oid(
				&gss_min, gssapi_context,
				&gse_sesskey_inq_oid, &set);
	if (gss_maj) {
		DEBUG(0, ("gss_inquire_sec_context_by_oid failed [%s]\n",
			  gssapi_error_string(mem_ctx,
					      gss_maj,
					      gss_min,
					      discard_const_p(struct gss_OID_desc_struct,
							      gss_mech_krb5))));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if ((set == GSS_C_NO_BUFFER_SET) ||
	    (set->count == 0)) {
#ifdef HAVE_GSSKRB5_GET_SUBKEY
		krb5_keyblock *subkey;
		gss_maj = gsskrb5_get_subkey(&gss_min,
					     gssapi_context,
					     &subkey);
		if (gss_maj != 0) {
			DEBUG(1, ("NO session key for this mech\n"));
			return NT_STATUS_NO_USER_SESSION_KEY;
		}
		if (session_key) {
			*session_key = data_blob_talloc(mem_ctx,
							KRB5_KEY_DATA(subkey), KRB5_KEY_LENGTH(subkey));
		}
		if (keytype) {
			*keytype = KRB5_KEY_TYPE(subkey);
		}
		krb5_free_keyblock(NULL /* should be krb5_context */, subkey);
		return NT_STATUS_OK;
#else
		DEBUG(0, ("gss_inquire_sec_context_by_oid didn't return any session key (and no alternative method available)\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
#endif
	}

	if (session_key) {
		*session_key = data_blob_talloc(mem_ctx, set->elements[0].value,
						set->elements[0].length);
	}

	if (keytype) {
		int diflen, i;
		const uint8_t *p;

		*keytype = 0;
		if (set->count < 2) {

#ifdef HAVE_GSSKRB5_GET_SUBKEY
			krb5_keyblock *subkey;
			gss_maj = gsskrb5_get_subkey(&gss_min,
						     gssapi_context,
						     &subkey);
			if (gss_maj == 0) {
				*keytype = KRB5_KEY_TYPE(subkey);
				krb5_free_keyblock(NULL /* should be krb5_context */, subkey);
			}
#endif
			gss_maj = gss_release_buffer_set(&gss_min, &set);
	
			return NT_STATUS_OK;

		} else if (memcmp(set->elements[1].value,
				  gse_sesskeytype_oid.elements,
				  gse_sesskeytype_oid.length) != 0) {
			/* Perhaps a non-krb5 session key */
			gss_maj = gss_release_buffer_set(&gss_min, &set);
			return NT_STATUS_OK;
		}
		p = (const uint8_t *)set->elements[1].value + gse_sesskeytype_oid.length;
		diflen = set->elements[1].length - gse_sesskeytype_oid.length;
		if (diflen <= 0) {
			gss_maj = gss_release_buffer_set(&gss_min, &set);
			return NT_STATUS_INVALID_PARAMETER;
		}
		for (i = 0; i < diflen; i++) {
			*keytype = (*keytype << 7) | (p[i] & 0x7f);
			if (i + 1 != diflen && (p[i] & 0x80) == 0) {
				gss_maj = gss_release_buffer_set(&gss_min, &set);
				return NT_STATUS_INVALID_PARAMETER;
			}
		}
	}

	gss_maj = gss_release_buffer_set(&gss_min, &set);
	return NT_STATUS_OK;
}


char *gssapi_error_string(TALLOC_CTX *mem_ctx,
			  OM_uint32 maj_stat, OM_uint32 min_stat,
			  const gss_OID mech)
{
	OM_uint32 disp_min_stat, disp_maj_stat;
	gss_buffer_desc maj_error_message;
	gss_buffer_desc min_error_message;
	char *maj_error_string, *min_error_string;
	OM_uint32 msg_ctx = 0;

	char *ret;

	maj_error_message.value = NULL;
	min_error_message.value = NULL;
	maj_error_message.length = 0;
	min_error_message.length = 0;

	disp_maj_stat = gss_display_status(&disp_min_stat, maj_stat,
					   GSS_C_GSS_CODE, mech,
					   &msg_ctx, &maj_error_message);
	if (disp_maj_stat != 0) {
		maj_error_message.value = NULL;
		maj_error_message.length = 0;
	}
	disp_maj_stat = gss_display_status(&disp_min_stat, min_stat,
					   GSS_C_MECH_CODE, mech,
					   &msg_ctx, &min_error_message);
	if (disp_maj_stat != 0) {
		min_error_message.value = NULL;
		min_error_message.length = 0;
	}

	maj_error_string = talloc_strndup(mem_ctx,
					  (char *)maj_error_message.value,
					  maj_error_message.length);

	min_error_string = talloc_strndup(mem_ctx,
					  (char *)min_error_message.value,
					  min_error_message.length);

	ret = talloc_asprintf(mem_ctx, "%s: %s",
				maj_error_string, min_error_string);

	talloc_free(maj_error_string);
	talloc_free(min_error_string);

	gss_release_buffer(&disp_min_stat, &maj_error_message);
	gss_release_buffer(&disp_min_stat, &min_error_message);

	return ret;
}

#endif /* HAVE_KRB5 */
