/*
 * Copyright (c) 1999-2001, 2003, PADL Software Pty Ltd.
 * Copyright (c) 2004-2009, Andrew Bartlett <abartlet@samba.org>.
 * Copyright (c) 2004, Stefan Metzmacher <metze@samba.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software  nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "includes.h"
#include "kdc/kdc-glue.h"
#include "kdc/db-glue.h"
#include "auth/auth_sam.h"
#include "auth/common_auth.h"
#include <ldb.h>
#include "sdb.h"
#include "sdb_hdb.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "../lib/tsocket/tsocket.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "lib/messaging/irpc.h"
#include "hdb.h"
#include <kdc-audit.h>

static krb5_error_code hdb_samba4_open(krb5_context context, HDB *db, int flags, mode_t mode)
{
	if (db->hdb_master_key_set) {
		krb5_error_code ret = HDB_ERR_NOENTRY;
		krb5_warnx(context, "hdb_samba4_open: use of a master key incompatible with LDB\n");
		krb5_set_error_message(context, ret, "hdb_samba4_open: use of a master key incompatible with LDB\n");
		return ret;
	}

	return 0;
}

static krb5_error_code hdb_samba4_close(krb5_context context, HDB *db)
{
	return 0;
}

static krb5_error_code hdb_samba4_lock(krb5_context context, HDB *db, int operation)
{
	return 0;
}

static krb5_error_code hdb_samba4_unlock(krb5_context context, HDB *db)
{
	return 0;
}

static krb5_error_code hdb_samba4_rename(krb5_context context, HDB *db, const char *new_name)
{
	return HDB_ERR_DB_INUSE;
}

static krb5_error_code hdb_samba4_store(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
	return HDB_ERR_DB_INUSE;
}

/*
 * If we ever want kadmin to work fast, we might try and reopen the
 * ldb with LDB_NOSYNC
 */
static krb5_error_code hdb_samba4_set_sync(krb5_context context, struct HDB *db, int set_sync)
{
	return 0;
}

static void hdb_samba4_free_entry_context(krb5_context context, struct HDB *db, hdb_entry *entry)
{
	/*
	 * This function is now called for every HDB entry, not just those with
	 * 'context' set, so we have to check that the context is not NULL.
	*/
	if (entry->context != NULL) {
		/* this function is called only from hdb_free_entry().
		 * Make sure we neutralize the destructor or we will
		 * get a double free later when hdb_free_entry() will
		 * try to call free_hdb_entry() */
		talloc_set_destructor(entry->context, NULL);

		/* now proceed to free the talloc part */
		talloc_free(entry->context);
	}
}

static int hdb_samba4_fill_fast_cookie(krb5_context context,
				       struct samba_kdc_db_context *kdc_db_ctx)
{
	struct ldb_message *msg = ldb_msg_new(kdc_db_ctx);
	int ldb_ret;

	uint8_t secretbuffer[32];
	struct ldb_val val = data_blob_const(secretbuffer,
					     sizeof(secretbuffer));

	if (msg == NULL) {
		DBG_ERR("Failed to allocate msg for new fast cookie\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Fill in all the keys with the same secret */
	generate_secret_buffer(secretbuffer,
			       sizeof(secretbuffer));

	msg->dn = kdc_db_ctx->fx_cookie_dn;

	ldb_ret = ldb_msg_add_value(msg, "secret", &val, NULL);

	if (ldb_ret != LDB_SUCCESS) {
		return ldb_ret;
	}

	ldb_ret = ldb_add(kdc_db_ctx->secrets_db,
			  msg);
	if (ldb_ret != LDB_SUCCESS) {
		DBG_ERR("Failed to add fast cookie to ldb: %s\n",
			ldb_errstring(kdc_db_ctx->secrets_db));
	}
	return ldb_ret;
}

static krb5_error_code hdb_samba4_fetch_fast_cookie(krb5_context context,
						    struct samba_kdc_db_context *kdc_db_ctx,
						    hdb_entry *entry_ex)
{
	krb5_error_code ret = SDB_ERR_NOENTRY;
	TALLOC_CTX *mem_ctx;
	struct ldb_result *res;
	int ldb_ret;
	struct sdb_entry_ex sdb_entry_ex = {};
	const char *attrs[] = {
		"secret",
		NULL
	};
	const struct ldb_val *val;

	mem_ctx = talloc_named(kdc_db_ctx, 0, "samba_kdc_fetch context");
	if (!mem_ctx) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "samba_kdc_fetch: talloc_named() failed!");
		return ret;
	}

	/* search for CN=FX-COOKIE */
	ldb_ret = ldb_search(kdc_db_ctx->secrets_db,
			     mem_ctx,
			     &res,
			     kdc_db_ctx->fx_cookie_dn,
			     LDB_SCOPE_BASE,
			     attrs, NULL);

	if (ldb_ret == LDB_ERR_NO_SUCH_OBJECT || res->count == 0) {

		ldb_ret = hdb_samba4_fill_fast_cookie(context,
						      kdc_db_ctx);

		if (ldb_ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return HDB_ERR_NO_WRITE_SUPPORT;
		}

		/* search for CN=FX-COOKIE */
		ldb_ret = ldb_search(kdc_db_ctx->secrets_db,
				     mem_ctx,
				     &res,
				     kdc_db_ctx->fx_cookie_dn,
				     LDB_SCOPE_BASE,
				     attrs, NULL);

		if (ldb_ret != LDB_SUCCESS || res->count != 1) {
			TALLOC_FREE(mem_ctx);
			return HDB_ERR_NOENTRY;
		}
	}

	val = ldb_msg_find_ldb_val(res->msgs[0],
				   "secret");
	if (val == NULL || val->length != 32) {
		TALLOC_FREE(mem_ctx);
		return HDB_ERR_NOENTRY;
	}


	ret = krb5_make_principal(context,
				  &sdb_entry_ex.entry.principal,
				  KRB5_WELLKNOWN_ORG_H5L_REALM,
				  KRB5_WELLKNOWN_NAME, "org.h5l.fast-cookie",
				  NULL);
	if (ret) {
		TALLOC_FREE(mem_ctx);
		return ret;
	}

	ret = samba_kdc_set_fixed_keys(context, kdc_db_ctx,
				       val, &sdb_entry_ex);
	if (ret != 0) {
		return ret;
	}

	ret = sdb_entry_ex_to_hdb_entry_ex(context,
					   &sdb_entry_ex,
					   entry_ex);
	sdb_free_entry(&sdb_entry_ex);
	TALLOC_FREE(mem_ctx);

	return ret;
}

static krb5_error_code hdb_samba4_fetch_kvno(krb5_context context, HDB *db,
					     krb5_const_principal principal,
					     unsigned flags,
					     krb5_kvno kvno,
					     hdb_entry *entry_ex)
{
	struct samba_kdc_db_context *kdc_db_ctx;
	struct sdb_entry_ex sdb_entry_ex = {};
	krb5_error_code code, ret;
	uint32_t sflags;

	kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
					   struct samba_kdc_db_context);

	if (flags & HDB_F_GET_FAST_COOKIE) {
		return hdb_samba4_fetch_fast_cookie(context,
						    kdc_db_ctx,
						    entry_ex);
	}

	sflags = (flags & SDB_F_HDB_MASK);

	ret = samba_kdc_fetch(context,
			      kdc_db_ctx,
			      principal,
			      sflags,
			      kvno,
			      &sdb_entry_ex);
	switch (ret) {
	case 0:
		code = 0;
		break;
	case SDB_ERR_WRONG_REALM:
		/*
		 * If SDB_ERR_WRONG_REALM is returned we need to process the
		 * sdb_entry to fill the principal in the HDB entry.
		 */
		code = HDB_ERR_WRONG_REALM;
		break;
	case SDB_ERR_NOENTRY:
		return HDB_ERR_NOENTRY;
	case SDB_ERR_NOT_FOUND_HERE:
		return HDB_ERR_NOT_FOUND_HERE;
	default:
		return ret;
	}

	ret = sdb_entry_ex_to_hdb_entry_ex(context, &sdb_entry_ex, entry_ex);
	sdb_free_entry(&sdb_entry_ex);

	if (code != 0 && ret != 0) {
		code = ret;
	}

	return code;
}

static krb5_error_code hdb_samba4_kpasswd_fetch_kvno(krb5_context context, HDB *db,
						     krb5_const_principal _principal,
						     unsigned flags,
						     krb5_kvno _kvno,
						     hdb_entry *entry)
{
	struct samba_kdc_db_context *kdc_db_ctx = NULL;
	krb5_error_code ret;
	krb5_principal kpasswd_principal = NULL;

	kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
					   struct samba_kdc_db_context);

	ret = smb_krb5_make_principal(context, &kpasswd_principal,
				      lpcfg_realm(kdc_db_ctx->lp_ctx),
				      "kadmin", "changepw",
				      NULL);
	if (ret) {
		return ret;
	}
	smb_krb5_principal_set_type(context, kpasswd_principal, KRB5_NT_SRV_INST);

	/*
	 * For the kpasswd service, always ensure we get the latest kvno. This
	 * also means we (correctly) refuse RODC-issued tickets.
	 */
	flags &= ~HDB_F_KVNO_SPECIFIED;

	/* Don't bother looking up a client or krbtgt. */
	flags &= ~(SDB_F_GET_CLIENT|SDB_F_GET_KRBTGT);

	ret = hdb_samba4_fetch_kvno(context, db,
				    kpasswd_principal,
				    flags,
				    0,
				    entry);

	krb5_free_principal(context, kpasswd_principal);
	return ret;
}

static krb5_error_code hdb_samba4_firstkey(krb5_context context, HDB *db, unsigned flags,
					hdb_entry *entry)
{
	struct samba_kdc_db_context *kdc_db_ctx;
	struct sdb_entry_ex sdb_entry_ex = {};
	krb5_error_code ret;

	kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
					   struct samba_kdc_db_context);

	ret = samba_kdc_firstkey(context, kdc_db_ctx, &sdb_entry_ex);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_WRONG_REALM:
		return HDB_ERR_WRONG_REALM;
	case SDB_ERR_NOENTRY:
		return HDB_ERR_NOENTRY;
	case SDB_ERR_NOT_FOUND_HERE:
		return HDB_ERR_NOT_FOUND_HERE;
	default:
		return ret;
	}

	ret = sdb_entry_ex_to_hdb_entry_ex(context, &sdb_entry_ex, entry);
	sdb_free_entry(&sdb_entry_ex);
	return ret;
}

static krb5_error_code hdb_samba4_nextkey(krb5_context context, HDB *db, unsigned flags,
				   hdb_entry *entry)
{
	struct samba_kdc_db_context *kdc_db_ctx;
	struct sdb_entry_ex sdb_entry_ex = {};
	krb5_error_code ret;

	kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
					   struct samba_kdc_db_context);

	ret = samba_kdc_nextkey(context, kdc_db_ctx, &sdb_entry_ex);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_WRONG_REALM:
		return HDB_ERR_WRONG_REALM;
	case SDB_ERR_NOENTRY:
		return HDB_ERR_NOENTRY;
	case SDB_ERR_NOT_FOUND_HERE:
		return HDB_ERR_NOT_FOUND_HERE;
	default:
		return ret;
	}

	ret = sdb_entry_ex_to_hdb_entry_ex(context, &sdb_entry_ex, entry);
	sdb_free_entry(&sdb_entry_ex);
	return ret;
}

static krb5_error_code hdb_samba4_nextkey_panic(krb5_context context, HDB *db,
						unsigned flags,
						hdb_entry *entry)
{
	DBG_ERR("Attempt to iterate kpasswd keytab => PANIC\n");
	smb_panic("hdb_samba4_nextkey_panic: Attempt to iterate kpasswd keytab");
}

static krb5_error_code hdb_samba4_destroy(krb5_context context, HDB *db)
{
	talloc_free(db);
	return 0;
}

static krb5_error_code
hdb_samba4_check_constrained_delegation(krb5_context context, HDB *db,
					hdb_entry *entry,
					krb5_const_principal target_principal)
{
	struct samba_kdc_db_context *kdc_db_ctx;
	struct samba_kdc_entry *skdc_entry;
	krb5_error_code ret;

	kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
					   struct samba_kdc_db_context);
	skdc_entry = talloc_get_type_abort(entry->context,
					   struct samba_kdc_entry);

	ret = samba_kdc_check_s4u2proxy(context, kdc_db_ctx,
					skdc_entry,
					target_principal);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_WRONG_REALM:
		ret = HDB_ERR_WRONG_REALM;
		break;
	case SDB_ERR_NOENTRY:
		ret = HDB_ERR_NOENTRY;
		break;
	case SDB_ERR_NOT_FOUND_HERE:
		ret = HDB_ERR_NOT_FOUND_HERE;
		break;
	default:
		break;
	}

	return ret;
}

static krb5_error_code
hdb_samba4_check_pkinit_ms_upn_match(krb5_context context, HDB *db,
				     hdb_entry *entry,
				     krb5_const_principal certificate_principal)
{
	struct samba_kdc_db_context *kdc_db_ctx;
	struct samba_kdc_entry *skdc_entry;
	krb5_error_code ret;

	kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
					   struct samba_kdc_db_context);
	skdc_entry = talloc_get_type_abort(entry->context,
					   struct samba_kdc_entry);

	ret = samba_kdc_check_pkinit_ms_upn_match(context, kdc_db_ctx,
						  skdc_entry,
						  certificate_principal);
	switch (ret) {
	case 0:
		break;
	case SDB_ERR_WRONG_REALM:
		ret = HDB_ERR_WRONG_REALM;
		break;
	case SDB_ERR_NOENTRY:
		ret = HDB_ERR_NOENTRY;
		break;
	case SDB_ERR_NOT_FOUND_HERE:
		ret = HDB_ERR_NOT_FOUND_HERE;
		break;
	default:
		break;
	}

	return ret;
}

static krb5_error_code
hdb_samba4_check_client_matches_target_service(krb5_context context, HDB *db,
			  hdb_entry *client_entry,
			  hdb_entry *server_target_entry)
{
	struct samba_kdc_entry *skdc_client_entry
		= talloc_get_type_abort(client_entry->context,
					struct samba_kdc_entry);
	struct samba_kdc_entry *skdc_server_target_entry
		= talloc_get_type_abort(server_target_entry->context,
					struct samba_kdc_entry);

	return samba_kdc_check_client_matches_target_service(context,
							     skdc_client_entry,
							     skdc_server_target_entry);
}

static void reset_bad_password_netlogon(TALLOC_CTX *mem_ctx,
					struct samba_kdc_db_context *kdc_db_ctx,
					struct netr_SendToSamBase *send_to_sam)
{
	struct dcerpc_binding_handle *irpc_handle;
	struct winbind_SendToSam req;

	irpc_handle = irpc_binding_handle_by_name(mem_ctx, kdc_db_ctx->msg_ctx,
						  "winbind_server",
						  &ndr_table_winbind);

	if (irpc_handle == NULL) {
		DEBUG(0, ("No winbind_server running!\n"));
		return;
	}

	req.in.message = *send_to_sam;

	dcerpc_winbind_SendToSam_r_send(mem_ctx, kdc_db_ctx->ev_ctx,
					irpc_handle, &req);
}

static krb5_error_code hdb_samba4_audit(krb5_context context,
					HDB *db,
					hdb_entry *entry,
					hdb_request_t r)
{
	struct samba_kdc_db_context *kdc_db_ctx = talloc_get_type_abort(db->hdb_db,
									struct samba_kdc_db_context);
	struct ldb_dn *domain_dn = ldb_get_default_basedn(kdc_db_ctx->samdb);
	uint64_t logon_id = generate_random_u64();
	heim_object_t auth_details_obj = NULL;
	const char *auth_details = NULL;
	char *etype_str = NULL;
	heim_object_t hdb_auth_status_obj = NULL;
	int hdb_auth_status;
	heim_object_t pa_type_obj = NULL;
	const char *pa_type = NULL;
	struct auth_usersupplied_info ui;
	size_t sa_socklen = 0;
	int final_ret = 0;

	hdb_auth_status_obj = heim_audit_getkv((heim_svc_req_desc)r, KDC_REQUEST_KV_AUTH_EVENT);
	if (hdb_auth_status_obj == NULL) {
		/* No status code found, so just return. */
		return 0;
	}

	hdb_auth_status = heim_number_get_int(hdb_auth_status_obj);

	pa_type_obj = heim_audit_getkv((heim_svc_req_desc)r, "pa");
	if (pa_type_obj != NULL) {
		pa_type = heim_string_get_utf8(pa_type_obj);
	}

	auth_details_obj = heim_audit_getkv((heim_svc_req_desc)r, KDC_REQUEST_KV_PKINIT_CLIENT_CERT);
	if (auth_details_obj != NULL) {
		auth_details = heim_string_get_utf8(auth_details_obj);
	} else {
		auth_details_obj = heim_audit_getkv((heim_svc_req_desc)r, KDC_REQUEST_KV_GSS_INITIATOR);
		if (auth_details_obj != NULL) {
			auth_details = heim_string_get_utf8(auth_details_obj);
		} else {
			heim_object_t etype_obj = heim_audit_getkv((heim_svc_req_desc)r, KDC_REQUEST_KV_PA_ETYPE);
			if (etype_obj != NULL) {
				int etype = heim_number_get_int(etype_obj);

				krb5_error_code ret = krb5_enctype_to_string(r->context, etype, &etype_str);
				if (ret == 0) {
					auth_details = etype_str;
				} else {
					auth_details = "unknown enctype";
				}
			}
		}
	}

	/*
	 * Forcing this via the NTLM auth structure is not ideal, but
	 * it is the most practical option right now, and ensures the
	 * logs are consistent, even if some elements are always NULL.
	 */
	ui = (struct auth_usersupplied_info) {
		.was_mapped = true,
		.client = {
			.account_name = r->cname,
			.domain_name = NULL,
		},
		.service_description = "Kerberos KDC",
		.auth_description = "Unknown Auth Description",
		.password_type = auth_details,
		.logon_id = logon_id
	};

	switch (r->addr->sa_family) {
	case AF_INET:
		sa_socklen = sizeof(struct sockaddr_in);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		sa_socklen = sizeof(struct sockaddr_in6);
		break;
#endif
	}

	switch (hdb_auth_status) {
	default:
	{
		TALLOC_CTX *frame = talloc_stackframe();
		struct samba_kdc_entry *p = talloc_get_type(entry->context,
							    struct samba_kdc_entry);
		struct dom_sid *sid
			= samdb_result_dom_sid(frame, p->msg, "objectSid");
		const char *account_name
			= ldb_msg_find_attr_as_string(p->msg, "sAMAccountName", NULL);
		const char *domain_name = lpcfg_sam_name(p->kdc_db_ctx->lp_ctx);
		struct tsocket_address *remote_host;
		const char *auth_description = NULL;
		NTSTATUS status;
		int ret;
		bool rwdc_fallback = false;

		ret = tsocket_address_bsd_from_sockaddr(frame, r->addr,
							sa_socklen,
							&remote_host);
		if (ret != 0) {
			ui.remote_host = NULL;
		} else {
			ui.remote_host = remote_host;
		}

		ui.mapped.account_name = account_name;
		ui.mapped.domain_name = domain_name;

		if (pa_type != NULL) {
			auth_description = talloc_asprintf(frame,
							   "%s Pre-authentication",
							   pa_type);
			if (auth_description == NULL) {
				auth_description = pa_type;
			}
		} else {
			auth_description = "Unknown Pre-authentication";
		}
		ui.auth_description = auth_description;

		if (hdb_auth_status == KDC_AUTH_EVENT_CLIENT_AUTHORIZED) {
			struct netr_SendToSamBase *send_to_sam = NULL;

			/*
			 * TODO: We could log the AS-REQ authorization success here as
			 * well.  However before we do that, we need to pass
			 * in the PAC here or re-calculate it.
			 */
			status = authsam_logon_success_accounting(kdc_db_ctx->samdb, p->msg,
								  domain_dn, true, frame, &send_to_sam);
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
				final_ret = KRB5KDC_ERR_CLIENT_REVOKED;
				r->error_code = final_ret;
				rwdc_fallback = kdc_db_ctx->rodc;
			} else if (!NT_STATUS_IS_OK(status)) {
				final_ret = KRB5KRB_ERR_GENERIC;
				r->error_code = final_ret;
				rwdc_fallback = kdc_db_ctx->rodc;
			} else if (kdc_db_ctx->rodc && send_to_sam != NULL) {
				reset_bad_password_netlogon(frame, kdc_db_ctx, send_to_sam);
			}

			/* This is the final sucess */
		} else if (hdb_auth_status == KDC_AUTH_EVENT_VALIDATED_LONG_TERM_KEY) {
			/*
			 * This was only a pre-authentication success,
			 * but we didn't reach the final
			 * KDC_AUTH_EVENT_CLIENT_AUTHORIZED,
			 * so consult the error code.
			 */
			if (r->error_code == 0) {
				DBG_ERR("ERROR: VALIDATED_LONG_TERM_KEY "
					"with error=0 => INTERNAL_ERROR\n");
				status = NT_STATUS_INTERNAL_ERROR;
				final_ret = KRB5KRB_ERR_GENERIC;
				r->error_code = final_ret;
			} else if (!NT_STATUS_IS_OK(p->reject_status)) {
				status = p->reject_status;
			} else {
				status = krb5_to_nt_status(r->error_code);
			}
		} else if (hdb_auth_status == KDC_AUTH_EVENT_PREAUTH_SUCCEEDED) {
			/*
			 * This was only a pre-authentication success,
			 * but we didn't reach the final
			 * KDC_AUTH_EVENT_CLIENT_AUTHORIZED,
			 * so consult the error code.
			 */
			if (r->error_code == 0) {
				DBG_ERR("ERROR: PREAUTH_SUCCEEDED "
					"with error=0 => INTERNAL_ERROR\n");
				status = NT_STATUS_INTERNAL_ERROR;
				final_ret = KRB5KRB_ERR_GENERIC;
				r->error_code = final_ret;
			} else if (!NT_STATUS_IS_OK(p->reject_status)) {
				status = p->reject_status;
			} else {
				status = krb5_to_nt_status(r->error_code);
			}
		} else if (hdb_auth_status == KDC_AUTH_EVENT_CLIENT_TIME_SKEW) {
			status = NT_STATUS_TIME_DIFFERENCE_AT_DC;
		} else if (hdb_auth_status == KDC_AUTH_EVENT_WRONG_LONG_TERM_KEY) {
			status = authsam_update_bad_pwd_count(kdc_db_ctx->samdb, p->msg, domain_dn);
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
				final_ret = KRB5KDC_ERR_CLIENT_REVOKED;
				r->error_code = final_ret;
			} else {
				status = NT_STATUS_WRONG_PASSWORD;
			}
			rwdc_fallback = kdc_db_ctx->rodc;
		} else if (hdb_auth_status == KDC_AUTH_EVENT_CLIENT_LOCKED_OUT) {
			status = NT_STATUS_ACCOUNT_LOCKED_OUT;
			rwdc_fallback = kdc_db_ctx->rodc;
		} else if (hdb_auth_status == KDC_AUTH_EVENT_CLIENT_NAME_UNAUTHORIZED) {
			if (pa_type != NULL && strncmp(pa_type, "PK-INIT", strlen("PK-INIT")) == 0) {
				status = NT_STATUS_PKINIT_NAME_MISMATCH;
			} else {
				status = NT_STATUS_ACCOUNT_RESTRICTION;
			}
			rwdc_fallback = kdc_db_ctx->rodc;
		} else if (hdb_auth_status == KDC_AUTH_EVENT_PREAUTH_FAILED) {
			if (pa_type != NULL && strncmp(pa_type, "PK-INIT", strlen("PK-INIT")) == 0) {
				status = NT_STATUS_PKINIT_FAILURE;
			} else {
				status = NT_STATUS_GENERIC_COMMAND_FAILED;
			}
			rwdc_fallback = kdc_db_ctx->rodc;
		} else {
			DBG_ERR("Unhandled hdb_auth_status=%d => INTERNAL_ERROR\n",
				hdb_auth_status);
			status = NT_STATUS_INTERNAL_ERROR;
			final_ret = KRB5KRB_ERR_GENERIC;
			r->error_code = final_ret;
		}

		if (rwdc_fallback) {
			/*
			 * Forward the request to an RWDC in order
			 * to give an authoritative answer to the client.
			 */
			auth_description = talloc_asprintf(frame,
							   "%s,Forward-To-RWDC",
							   ui.auth_description);
			if (auth_description != NULL) {
				ui.auth_description = auth_description;
			}
			final_ret = HDB_ERR_NOT_FOUND_HERE;
		}

		log_authentication_event(kdc_db_ctx->msg_ctx,
					 kdc_db_ctx->lp_ctx,
					 &r->tv_start,
					 &ui,
					 status,
					 domain_name,
					 account_name,
					 sid);
		if (final_ret == KRB5KRB_ERR_GENERIC && socket_wrapper_enabled()) {
			/*
			 * If we're running under make test
			 * just panic
			 */
			DBG_ERR("Unexpected situation => PANIC\n");
			smb_panic("hdb_samba4_audit: Unexpected situation");
		}
		TALLOC_FREE(frame);
		break;
	}
	case KDC_AUTH_EVENT_CLIENT_UNKNOWN:
	{
		struct tsocket_address *remote_host;
		int ret;
		TALLOC_CTX *frame = talloc_stackframe();
		ret = tsocket_address_bsd_from_sockaddr(frame, r->addr,
							sa_socklen,
							&remote_host);
		if (ret != 0) {
			ui.remote_host = NULL;
		} else {
			ui.remote_host = remote_host;
		}

		if (pa_type == NULL) {
			pa_type = "AS-REQ";
		}

		ui.auth_description = pa_type;

		/* Note this is not forwarded to an RWDC */

		log_authentication_event(kdc_db_ctx->msg_ctx,
					 kdc_db_ctx->lp_ctx,
					 &r->tv_start,
					 &ui,
					 NT_STATUS_NO_SUCH_USER,
					 NULL, NULL,
					 NULL);
		TALLOC_FREE(frame);
		break;
	}
	}

	free(etype_str);

	return final_ret;
}

/* This interface is to be called by the KDC and libnet_keytab_dump,
 * which is expecting Samba calling conventions.
 * It is also called by a wrapper (hdb_samba4_create) from the
 * kpasswdd -> krb5 -> keytab_hdb -> hdb code */

NTSTATUS hdb_samba4_create_kdc(struct samba_kdc_base_context *base_ctx,
			       krb5_context context, struct HDB **db)
{
	struct samba_kdc_db_context *kdc_db_ctx;
	NTSTATUS nt_status;

	if (hdb_interface_version != HDB_INTERFACE_VERSION) {
		krb5_set_error_message(context, EINVAL, "Heimdal HDB interface version mismatch between build-time and run-time libraries!");
		return NT_STATUS_ERROR_DS_INCOMPATIBLE_VERSION;
	}

	*db = talloc_zero(base_ctx, HDB);
	if (!*db) {
		krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
		return NT_STATUS_NO_MEMORY;
	}

	(*db)->hdb_master_key_set = 0;
	(*db)->hdb_db = NULL;
	(*db)->hdb_capability_flags = HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL;

	nt_status = samba_kdc_setup_db_ctx(*db, base_ctx, &kdc_db_ctx);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(*db);
		return nt_status;
	}
	(*db)->hdb_db = kdc_db_ctx;

	(*db)->hdb_dbc = NULL;
	(*db)->hdb_open = hdb_samba4_open;
	(*db)->hdb_close = hdb_samba4_close;
	(*db)->hdb_free_entry_context = hdb_samba4_free_entry_context;
	(*db)->hdb_fetch_kvno = hdb_samba4_fetch_kvno;
	(*db)->hdb_store = hdb_samba4_store;
	(*db)->hdb_firstkey = hdb_samba4_firstkey;
	(*db)->hdb_nextkey = hdb_samba4_nextkey;
	(*db)->hdb_lock = hdb_samba4_lock;
	(*db)->hdb_unlock = hdb_samba4_unlock;
	(*db)->hdb_set_sync = hdb_samba4_set_sync;
	(*db)->hdb_rename = hdb_samba4_rename;
	/* we don't implement these, as we are not a lockable database */
	(*db)->hdb__get = NULL;
	(*db)->hdb__put = NULL;
	/* kadmin should not be used for deletes - use other tools instead */
	(*db)->hdb__del = NULL;
	(*db)->hdb_destroy = hdb_samba4_destroy;

	(*db)->hdb_audit = hdb_samba4_audit;
	(*db)->hdb_check_constrained_delegation = hdb_samba4_check_constrained_delegation;
	(*db)->hdb_check_pkinit_ms_upn_match = hdb_samba4_check_pkinit_ms_upn_match;
	(*db)->hdb_check_client_matches_target_service = hdb_samba4_check_client_matches_target_service;

	return NT_STATUS_OK;
}

NTSTATUS hdb_samba4_kpasswd_create_kdc(struct samba_kdc_base_context *base_ctx,
				       krb5_context context, struct HDB **db)
{
	NTSTATUS nt_status;

	nt_status = hdb_samba4_create_kdc(base_ctx, context, db);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	(*db)->hdb_fetch_kvno = hdb_samba4_kpasswd_fetch_kvno;
	(*db)->hdb_firstkey = hdb_samba4_nextkey_panic;
	(*db)->hdb_nextkey = hdb_samba4_nextkey_panic;

	return NT_STATUS_OK;
}
