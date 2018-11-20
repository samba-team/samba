/*
 *  Unix SMB/CIFS implementation.
 *
 *  Simple GSSAPI wrappers
 *
 *  Copyright (c) 2012      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "gss_samba.h"

#ifdef HAVE_GSSAPI

#if !defined(HAVE_GSS_OID_EQUAL)
int smb_gss_oid_equal(const gss_OID first_oid, const gss_OID second_oid)
{
	if (first_oid == GSS_C_NO_OID || second_oid == GSS_C_NO_OID) {
		return 0;
	}

	if (first_oid == second_oid) {
		return 1;
	}

	if ((first_oid)->length != (second_oid)->length) {
		return 0;
	}

	if (memcmp((first_oid)->elements, (second_oid)->elements,
		   (first_oid)->length) == 0) {
		return 1;
	}

	return 0;
}
#endif /* !HAVE_GSS_OID_EQUAL */


/* wrapper around gss_krb5_import_cred() that prefers to use gss_acquire_cred_from()
 * if this GSSAPI extension is available. gss_acquire_cred_from() is properly
 * interposed by GSSPROXY while gss_krb5_import_cred() is not.
 *
 * This wrapper requires a proper krb5_context to resolve ccache name.
 * All gss_krb5_import_cred() callers in Samba already have krb5_context available. */
uint32_t smb_gss_krb5_import_cred(uint32_t *minor_status, krb5_context ctx,
				  krb5_ccache id, krb5_principal keytab_principal,
				  krb5_keytab keytab, gss_cred_id_t *cred)
{
	uint32_t major_status = 0;

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	uint32_t minor = 0;
	gss_key_value_element_desc ccache_element = {
		.key = "ccache",
		.value = NULL,
	};

	gss_key_value_element_desc keytab_element = {
		.key = "keytab",
		.value = NULL,
	};

	gss_key_value_element_desc elements[2];

	gss_key_value_set_desc cred_store = {
		.elements = &ccache_element,
		.count = 1,
	};

	gss_OID_set mech_set = GSS_C_NO_OID_SET;
	gss_cred_usage_t cred_usage = GSS_C_INITIATE;
	gss_name_t name = NULL;
	gss_buffer_desc pr_name = {
		.value = NULL,
		.length = 0,
	};

	if (id != NULL) {
		major_status = krb5_cc_get_full_name(ctx,
						     id,
						     discard_const(&ccache_element.value));
		if (major_status != 0) {
			return major_status;
		}
	}

	if (keytab != NULL) {
		keytab_element.value = malloc(4096);
		if (!keytab_element.value) {
			return ENOMEM;
		}
		major_status = krb5_kt_get_name(ctx,
						keytab,
						discard_const(keytab_element.value), 4096);
		if (major_status != 0) {
			free(discard_const(keytab_element.value));
			return major_status;
		}
		cred_usage = GSS_C_ACCEPT;
		cred_store.elements = &keytab_element;

		if (keytab_principal != NULL) {
			major_status = krb5_unparse_name(ctx, keytab_principal, (char**)&pr_name.value);
			if (major_status != 0) {
				free(discard_const(keytab_element.value));
				return major_status;
			}
			pr_name.length = strlen(pr_name.value);

			major_status = gss_import_name(minor_status,
						       &pr_name,
						       discard_const(GSS_KRB5_NT_PRINCIPAL_NAME),
						       &name);
			if (major_status != 0) {
				krb5_free_unparsed_name(ctx, pr_name.value);
				free(discard_const(keytab_element.value));
				return major_status;
			}
		}
	}

	if (id != NULL && keytab != NULL) {
		elements[0] = ccache_element;
		elements[1] = keytab_element;

		cred_store.elements = elements;
		cred_store.count = 2;
		cred_usage = GSS_C_BOTH;
	}

	major_status = gss_acquire_cred_from(minor_status,
					     name,
					     0,
					     mech_set,
					     cred_usage,
					     &cred_store,
					     cred,
					     NULL,
					     NULL);

	if (pr_name.value != NULL) {
		(void)gss_release_name(&minor, &name);
		krb5_free_unparsed_name(ctx, pr_name.value);
	}
	if (keytab_element.value != NULL) {
		free(discard_const(keytab_element.value));
	}
	krb5_free_string(ctx, discard_const(ccache_element.value));
#else
	major_status = gss_krb5_import_cred(minor_status,
					    id,
					    keytab_principal,
					    keytab, cred);

	if (major_status == (GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME)) {
		if ((keytab_principal == NULL) && (keytab != NULL)) {
			/* No principal was specified and MIT krb5 1.9 version failed.
			 * We have to fall back to set global acceptor identity */
			gss_OID_set_desc mech_set;
			char *kt_name = NULL;

			kt_name = malloc(4096);
			if (!kt_name) {
				return ENOMEM;
			}

			major_status = krb5_kt_get_name(ctx,
							keytab,
							kt_name, 4096);
			if (major_status != 0) {
				free(kt_name);
				return major_status;
			}

			major_status = gsskrb5_register_acceptor_identity(kt_name);
			if (major_status) {
				free(kt_name);
				return major_status;
			}

			/* We are dealing with krb5 GSSAPI mech in this fallback */
			mech_set.count = 1;
			mech_set.elements =
				discard_const_p(struct gss_OID_desc_struct,
						gss_mech_krb5);
			major_status = gss_acquire_cred(minor_status,
							GSS_C_NO_NAME,
							GSS_C_INDEFINITE,
							&mech_set,
							GSS_C_ACCEPT,
							cred,
							NULL, NULL);
			free(kt_name);
		}
	}
#endif
	return major_status;
}


#endif /* HAVE_GSSAPI */
