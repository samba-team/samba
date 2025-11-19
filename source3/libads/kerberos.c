/*
   Unix SMB/CIFS implementation.
   kerberos utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Nalin Dahyabhai <nalin@redhat.com> 2004.
   Copyright (C) Jeremy Allison 2004.
   Copyright (C) Gerald Carter 2006.

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
#include "libsmb/namequery.h"
#include "system/filesys.h"
#include "smb_krb5.h"
#include "../librpc/gen_ndr/ndr_misc.h"
#include "../librpc/gen_ndr/samr.h"
#include "libads/kerberos_proto.h"
#include "libads/netlogon_ping.h"
#include "secrets.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/util/tstream.h"
#include "../lib/util/tevent_ntstatus.h"
#include "lib/util/asn1.h"
#include "librpc/gen_ndr/netlogon.h"

#ifdef HAVE_KRB5

/*
  we use a prompter to avoid a crash bug in the kerberos libs when
  dealing with empty passwords
  this prompter is just a string copy ...
*/
static krb5_error_code
kerb_prompter(krb5_context ctx, void *data,
	       const char *name,
	       const char *banner,
	       int num_prompts,
	       krb5_prompt prompts[])
{
	if (num_prompts == 0) return 0;
	if (num_prompts == 2) {
		/*
		 * only heimdal has a prompt type and we need to deal with it here to
		 * avoid loops.
		 *
		 * removing the prompter completely is not an option as at least these
		 * versions would crash: heimdal-1.0.2 and heimdal-1.1. Later heimdal
		 * version have looping detection and return with a proper error code.
		 */

#if defined(HAVE_KRB5_PROMPT_TYPE) /* Heimdal */
		 if (prompts[0].type == KRB5_PROMPT_TYPE_NEW_PASSWORD &&
		     prompts[1].type == KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN) {
			/*
			 * We don't want to change passwords here. We're
			 * called from heimdal when the KDC returns
			 * KRB5KDC_ERR_KEY_EXPIRED, but at this point we don't
			 * have the chance to ask the user for a new
			 * password. If we return 0 (i.e. success), we will be
			 * spinning in the endless for-loop in
			 * change_password() in
			 * third_party/heimdal/lib/krb5/init_creds_pw.c
			 */
			return KRB5KDC_ERR_KEY_EXPIRED;
		}
#elif defined(HAVE_KRB5_GET_PROMPT_TYPES) /* MIT */
		krb5_prompt_type *prompt_types = NULL;

		prompt_types = krb5_get_prompt_types(ctx);
		if (prompt_types != NULL) {
			if (prompt_types[0] == KRB5_PROMPT_TYPE_NEW_PASSWORD &&
			    prompt_types[1] == KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN) {
				return KRB5KDC_ERR_KEY_EXP;
			}
		}
#endif
	}

	memset(prompts[0].reply->data, '\0', prompts[0].reply->length);
	if (prompts[0].reply->length > 0) {
		if (data) {
			strncpy((char *)prompts[0].reply->data, (const char *)data,
				prompts[0].reply->length-1);
			prompts[0].reply->length = strlen((const char *)prompts[0].reply->data);
		} else {
			prompts[0].reply->length = 0;
		}
	}
	return 0;
}

typedef krb5_error_code (*get_init_creds_fn_t)(krb5_context context,
					       krb5_creds *creds,
					       krb5_principal client,
					       krb5_get_init_creds_opt *options,
					       void *private_data);

/*
  simulate a kinit, putting the tgt in the given cache location.
  cache_name == NULL is not allowed.
*/
static int kerberos_kinit_generic_once(const char *given_principal,
				       get_init_creds_fn_t get_init_creds_fn,
				       void *get_init_creds_private,
				       int time_offset,
				       time_t *expire_time,
				       time_t *renew_till_time,
				       const char *cache_name,
				       bool request_pac,
				       bool add_netbios_addr,
				       time_t renewable_time,
				       TALLOC_CTX *mem_ctx,
				       char **_canon_principal,
				       char **_canon_realm,
				       NTSTATUS *ntstatus)
{
	TALLOC_CTX *frame = talloc_stackframe();
	krb5_context ctx = NULL;
	krb5_error_code code = 0;
	krb5_ccache cc = NULL;
	krb5_principal me = NULL;
	krb5_principal canon_princ = NULL;
	krb5_creds my_creds;
	krb5_get_init_creds_opt *opt = NULL;
	smb_krb5_addresses *addr = NULL;
	char *canon_principal = NULL;
	char *canon_realm = NULL;

	ZERO_STRUCT(my_creds);

	if (ntstatus) {
		*ntstatus = NT_STATUS_INTERNAL_ERROR;
	}

	if (cache_name == NULL) {
		DBG_DEBUG("Missing ccache for [%s] and config [%s]\n",
			  given_principal,
			  getenv("KRB5_CONFIG"));
		TALLOC_FREE(frame);
		return EINVAL;
	}

	code = smb_krb5_init_context_common(&ctx);
	if (code != 0) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(code));
		TALLOC_FREE(frame);
		return code;
	}

	if (time_offset != 0) {
		krb5_set_real_time(ctx, time(NULL) + time_offset, 0);
	}

	DBG_DEBUG("as %s using [%s] as ccache and config [%s]\n",
		  given_principal,
		  cache_name,
		  getenv("KRB5_CONFIG"));

	if ((code = krb5_cc_resolve(ctx, cache_name, &cc))) {
		goto out;
	}

	if ((code = smb_krb5_parse_name(ctx, given_principal, &me))) {
		goto out;
	}

	if ((code = krb5_get_init_creds_opt_alloc(ctx, &opt))) {
		goto out;
	}

	krb5_get_init_creds_opt_set_renew_life(opt, renewable_time);
	krb5_get_init_creds_opt_set_forwardable(opt, True);

	/* Turn on canonicalization for lower case realm support */
#ifdef SAMBA4_USES_HEIMDAL
	krb5_get_init_creds_opt_set_win2k(ctx, opt, true);
	krb5_get_init_creds_opt_set_canonicalize(ctx, opt, true);
#else /* MIT */
	krb5_get_init_creds_opt_set_canonicalize(opt, true);
#endif /* MIT */
#if 0
	/* insane testing */
	krb5_get_init_creds_opt_set_tkt_life(opt, 60);
#endif

#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_PAC_REQUEST
	if (request_pac) {
		if ((code = krb5_get_init_creds_opt_set_pac_request(ctx, opt, (krb5_boolean)request_pac))) {
			goto out;
		}
	}
#endif
	if (add_netbios_addr) {
		if ((code = smb_krb5_gen_netbios_krb5_address(&addr,
							lp_netbios_name()))) {
			goto out;
		}
		krb5_get_init_creds_opt_set_address_list(opt, addr->addrs);
	}

	code = get_init_creds_fn(ctx, &my_creds, me, opt, get_init_creds_private);
	if (code != 0) {
		goto out;
	}

	canon_princ = my_creds.client;

	code = smb_krb5_unparse_name(frame,
				     ctx,
				     canon_princ,
				     &canon_principal);
	if (code != 0) {
		goto out;
	}

	DBG_DEBUG("%s mapped to %s\n", given_principal, canon_principal);

	canon_realm = smb_krb5_principal_get_realm(frame, ctx, canon_princ);
	if (canon_realm == NULL) {
		code = ENOMEM;
		goto out;
	}

	if ((code = krb5_cc_initialize(ctx, cc, canon_princ))) {
		goto out;
	}

	if ((code = krb5_cc_store_cred(ctx, cc, &my_creds))) {
		goto out;
	}

	if (expire_time) {
		*expire_time = (time_t) my_creds.times.endtime;
	}

	if (renew_till_time) {
		*renew_till_time = (time_t) my_creds.times.renew_till;
	}

	if (_canon_principal != NULL) {
		*_canon_principal = talloc_move(mem_ctx, &canon_principal);
	}
	if (_canon_realm != NULL) {
		*_canon_realm = talloc_move(mem_ctx, &canon_realm);
	}
 out:
	if (ntstatus) {
		/* fast path */
		if (code == 0) {
			*ntstatus = NT_STATUS_OK;
			goto cleanup;
		}

		/* fall back to self-made-mapping */
		*ntstatus = krb5_to_nt_status(code);
	}

 cleanup:
	krb5_free_cred_contents(ctx, &my_creds);
	if (me) {
		krb5_free_principal(ctx, me);
	}
	if (addr) {
		smb_krb5_free_addresses(ctx, addr);
	}
	if (opt) {
		krb5_get_init_creds_opt_free(ctx, opt);
	}
	if (cc) {
		krb5_cc_close(ctx, cc);
	}
	if (ctx) {
		krb5_free_context(ctx);
	}
	TALLOC_FREE(frame);
	return code;
}

struct kerberos_kinit_password_ext_private {
	const char *password;
};

static krb5_error_code kerberos_kinit_password_ext_cb(krb5_context context,
						      krb5_creds *creds,
						      krb5_principal client,
						      krb5_get_init_creds_opt *options,
						      void *private_data)
{
	struct kerberos_kinit_password_ext_private *ep =
		(struct kerberos_kinit_password_ext_private *)private_data;
	krb5_deltat start_time = 0;
	const char *in_tkt_service = NULL;

	return krb5_get_init_creds_password(context, creds, client,
					    discard_const_p(char, ep->password),
					    kerb_prompter,
					    discard_const_p(char, ep->password),
					    start_time,
					    in_tkt_service,
					    options);
}

/*
  simulate a kinit, putting the tgt in the given cache location.
  cache_name == NULL is not allowed.
*/
int kerberos_kinit_password_ext(const char *given_principal,
				const char *password,
				int time_offset,
				time_t *expire_time,
				time_t *renew_till_time,
				const char *cache_name,
				bool request_pac,
				bool add_netbios_addr,
				time_t renewable_time,
				TALLOC_CTX *mem_ctx,
				char **_canon_principal,
				char **_canon_realm,
				NTSTATUS *ntstatus)
{
	struct kerberos_kinit_password_ext_private ep = {
		.password = password,
	};

	return kerberos_kinit_generic_once(given_principal,
					   kerberos_kinit_password_ext_cb,
					   &ep,
					   time_offset,
					   expire_time,
					   renew_till_time,
					   cache_name,
					   request_pac,
					   add_netbios_addr,
					   renewable_time,
					   mem_ctx,
					   _canon_principal,
					   _canon_realm,
					   ntstatus);
}

struct kerberos_transaction_cache {
	struct tsocket_address *local_addr;
	struct tsocket_address *kdc_addr;
	uint32_t timeout_msec;
};

static NTSTATUS kerberos_transaction_cache_create(
	const char *explicit_kdc,
	uint32_t timeout_msec,
	TALLOC_CTX *mem_ctx,
	struct kerberos_transaction_cache **_kc)
{
	struct kerberos_transaction_cache *kc = NULL;
	int ret;

	kc = talloc_zero(mem_ctx, struct kerberos_transaction_cache);
	if (kc == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	kc->timeout_msec = timeout_msec;

	/* parse the address of explicit kdc */
	ret = tsocket_address_inet_from_strings(kc,
						"ip",
						explicit_kdc,
						DEFAULT_KRB5_PORT,
						&kc->kdc_addr);
	if (ret != 0) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(kc);
		return status;
	}

	/* get an address for us to use locally */
	ret = tsocket_address_inet_from_strings(kc,
						"ip",
						NULL,
						0,
						&kc->local_addr);
	if (ret != 0) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(kc);
		return status;
	}

	*_kc = kc;
	return NT_STATUS_OK;
}

#ifdef HAVE_KRB5_INIT_CREDS_STEP

struct kerberos_transaction_state {
	struct tevent_context *ev;
	struct kerberos_transaction_cache *kc;
	struct tstream_context *stream;
	uint8_t in_hdr[4];
	struct iovec in_iov[2];
	DATA_BLOB rep_blob;
};

static void kerberos_transaction_connect_done(struct tevent_req *subreq);

static struct tevent_req *kerberos_transaction_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct kerberos_transaction_cache *kc,
	const char *realm,
	const DATA_BLOB req_blob)
{
	struct tevent_req *req = NULL;
	struct kerberos_transaction_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct timeval end;

	req = tevent_req_create(mem_ctx, &state,
				struct kerberos_transaction_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->kc = kc;

	PUSH_BE_U32(state->in_hdr, 0, req_blob.length);
	state->in_iov[0].iov_base = (char *)state->in_hdr;
	state->in_iov[0].iov_len = 4;
	state->in_iov[1].iov_base = (char *)req_blob.data;
	state->in_iov[1].iov_len = req_blob.length;

	end = timeval_current_ofs_msec(state->kc->timeout_msec);
	if (!tevent_req_set_endtime(req, state->ev, end)) {
		return tevent_req_post(req, state->ev);
	}

	subreq = tstream_inet_tcp_connect_send(state,
					       state->ev,
					       state->kc->local_addr,
					       state->kc->kdc_addr);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, state->ev);
	}
	tevent_req_set_callback(subreq, kerberos_transaction_connect_done, req);

	return req;
}

static void kerberos_transaction_writev_done(struct tevent_req *subreq);
static void kerberos_transaction_read_pdu_done(struct tevent_req *subreq);

static void kerberos_transaction_connect_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct kerberos_transaction_state *state =
		tevent_req_data(req,
		struct kerberos_transaction_state);
	int ret, sys_errno;

	ret = tstream_inet_tcp_connect_recv(subreq,
					    &sys_errno,
					    state,
					    &state->stream,
					    NULL);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		NTSTATUS status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}

	subreq = tstream_writev_send(state,
				     state->ev,
				     state->stream,
				     state->in_iov, 2);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, kerberos_transaction_writev_done, req);

	subreq = tstream_read_pdu_blob_send(state,
					    state->ev,
					    state->stream,
					    4, /* initial_read_size */
					    tstream_full_request_u32,
					    req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, kerberos_transaction_read_pdu_done, req);
}

static void kerberos_transaction_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	int ret, sys_errno;

	ret = tstream_writev_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}
}

static void kerberos_transaction_read_pdu_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct kerberos_transaction_state *state =
		tevent_req_data(req,
		struct kerberos_transaction_state);
	NTSTATUS status;

	status = tstream_read_pdu_blob_recv(subreq, state, &state->rep_blob);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * raw blob has the length in the first 4 bytes,
	 * which we do not need here.
	 */
	memmove(state->rep_blob.data,
		state->rep_blob.data + 4,
		state->rep_blob.length - 4);
	state->rep_blob.length -= 4;

	tevent_req_done(req);
}

static NTSTATUS kerberos_transaction_recv(struct tevent_req *req,
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB *rep_blob)
{
	struct kerberos_transaction_state *state =
		tevent_req_data(req,
		struct kerberos_transaction_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	rep_blob->data = talloc_move(mem_ctx, &state->rep_blob.data);
	rep_blob->length = state->rep_blob.length;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS kerberos_transaction(
	struct kerberos_transaction_cache *kc,
	const char *realm,
	const DATA_BLOB req_blob,
	TALLOC_CTX *mem_ctx,
	DATA_BLOB *rep_blob)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = kerberos_transaction_send(frame, ev, kc, realm, req_blob);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = kerberos_transaction_recv(req, mem_ctx, rep_blob);
 fail:
	TALLOC_FREE(frame);
	return status;
}

#endif /* HAVE_KRB5_INIT_CREDS_STEP */

struct kerberos_kinit_passwords_ext_private {
	const char *explicit_kdc;
	uint32_t timeout_msec;
	struct kerberos_transaction_cache *kc;
	const char *password;
	const struct samr_Password *nt_hash;
};

static krb5_error_code kerberos_kinit_passwords_ext_cb(krb5_context context,
						       krb5_creds *creds,
						       krb5_principal client,
						       krb5_get_init_creds_opt *options,
						       void *private_data)
{
	struct kerberos_kinit_passwords_ext_private *ep =
		(struct kerberos_kinit_passwords_ext_private *)private_data;
	TALLOC_CTX *frame = talloc_stackframe();
	krb5_deltat start_time = 0;
	krb5_init_creds_context ctx = NULL;
	krb5_keytab keytab = NULL;
	krb5_error_code ret;
#ifdef HAVE_KRB5_INIT_CREDS_STEP
	DATA_BLOB rep_blob = { .length = 0, };
#endif /* HAVE_KRB5_INIT_CREDS_STEP */

	ZERO_STRUCTP(creds);

	ret = krb5_init_creds_init(context,
				   client,
				   NULL, /* prompter */
				   NULL, /* prompter_data */
				   start_time,
				   options,
				   &ctx);
	if (ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	if (ep->password != NULL) {
		ret = krb5_init_creds_set_password(context, ctx, ep->password);
		if (ret) {
			krb5_init_creds_free(context, ctx);
			TALLOC_FREE(frame);
			return ret;
		}
	} else if (ep->nt_hash != NULL) {
		const char *keytab_name = "MEMORY:kerberos_kinit_passwords_ext_cb";
		krb5_keytab_entry entry = { .principal = client, };

		ret = krb5_kt_resolve(context, keytab_name, &keytab);
		if (ret) {
			krb5_init_creds_free(context, ctx);
			TALLOC_FREE(frame);
			return ret;
		}

		ret = smb_krb5_keyblock_init_contents(context,
						      ENCTYPE_ARCFOUR_HMAC,
						      ep->nt_hash->hash,
						      ARRAY_SIZE(ep->nt_hash->hash),
						      KRB5_KT_KEY(&entry));
		if (ret) {
			krb5_init_creds_free(context, ctx);
			krb5_kt_close(context, keytab);
			TALLOC_FREE(frame);
			return ret;
		}

		ret = krb5_kt_add_entry(context, keytab, &entry);
		krb5_free_keyblock_contents(context, KRB5_KT_KEY(&entry));
		if (ret) {
			krb5_init_creds_free(context, ctx);
			krb5_kt_close(context, keytab);
			TALLOC_FREE(frame);
			return ret;
		}

		ret = krb5_init_creds_set_keytab(context, ctx, keytab);
		if (ret) {
			krb5_init_creds_free(context, ctx);
			krb5_kt_close(context, keytab);
			TALLOC_FREE(frame);
			return ret;
		}
	} else {
		ret = EINVAL;
		krb5_init_creds_free(context, ctx);
		TALLOC_FREE(frame);
		return ret;
	}

	if (ep->kc == NULL) {
		/*
		 * Use the logic from the krb5 libraries
		 * to find the KDC
		 */
		ret = krb5_init_creds_get(context, ctx);
		if (ret) {
			krb5_init_creds_free(context, ctx);
			if (keytab != NULL) {
				krb5_kt_close(context, keytab);
			}
			TALLOC_FREE(frame);
			return ret;
		}

		goto got_creds;
	}

#ifdef HAVE_KRB5_INIT_CREDS_STEP
	while (true) {
#if defined(HAVE_KRB5_REALM_TYPE)
		/* Heimdal. */
		krb5_realm krealm = NULL;
#else
		/* MIT */
		krb5_data krealm = { .length = 0, };
#endif
		unsigned int flags = 0;
		const char *realm = NULL;
		krb5_data in = { .length = 0, };
		krb5_data out = { .length = 0, };
		DATA_BLOB req_blob = { .length = 0, };
		NTSTATUS status;

		in.data = (void *)rep_blob.data;
		in.length = rep_blob.length;

		flags = 0;
		ret = krb5_init_creds_step(context,
					   ctx,
					   &in,
					   &out,
					   &krealm,
					   &flags);
		data_blob_free(&rep_blob);
		in = (krb5_data) { .length = 0, };
		if (ret) {
			krb5_init_creds_free(context, ctx);
			if (keytab != NULL) {
				krb5_kt_close(context, keytab);
			}
			TALLOC_FREE(frame);
			return ret;
		}

		if ((flags & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE) == 0) {
			smb_krb5_free_data_contents(context, &out);
#if defined(HAVE_KRB5_REALM_TYPE)
			/* Heimdal. */
			SAFE_FREE(krealm);
#else
			/* MIT */
			smb_krb5_free_data_contents(context, &krealm);
#endif
			break;
		}

#if defined(HAVE_KRB5_REALM_TYPE)
		/* Heimdal. */
		realm = talloc_strdup(frame, krealm);
		SAFE_FREE(krealm);
#else
		/* MIT */
		realm = talloc_strndup(frame, krealm.data, krealm.length);
		smb_krb5_free_data_contents(context, &krealm);
#endif
		if (realm == NULL) {
			smb_krb5_free_data_contents(context, &out);
			krb5_init_creds_free(context, ctx);
			if (keytab != NULL) {
				krb5_kt_close(context, keytab);
			}
			TALLOC_FREE(frame);
			return ENOMEM;
		}

		req_blob.data = (uint8_t *)out.data;
		req_blob.length = out.length;

		status = kerberos_transaction(ep->kc,
					      realm,
					      req_blob,
					      frame,
					      &rep_blob);
		smb_krb5_free_data_contents(context, &out);
		req_blob = (DATA_BLOB) { .length = 0, };
		if (!NT_STATUS_IS_OK(status)) {
			ret = map_errno_from_nt_status(status);
			krb5_init_creds_free(context, ctx);
			if (keytab != NULL) {
				krb5_kt_close(context, keytab);
			}
			TALLOC_FREE(frame);
			return ret;
		}
	}
#else /* HAVE_KRB5_INIT_CREDS_STEP */
#ifdef USING_EMBEDDED_HEIMDAL
#error missing HAVE_KRB5_INIT_CREDS_STEP
#endif /* USING_EMBEDDED_HEIMDAL */
	/* Caller should already check! */
	smb_panic("krb5_init_creds_step not available");
#endif /* HAVE_KRB5_INIT_CREDS_STEP */

got_creds:
	ret = krb5_init_creds_get_creds(context, ctx, creds);
	if (ret) {
		krb5_init_creds_free(context, ctx);
		if (keytab != NULL) {
			krb5_kt_close(context, keytab);
		}
		TALLOC_FREE(frame);
		return ret;
	}

	krb5_init_creds_free(context, ctx);
	if (keytab != NULL) {
		krb5_kt_close(context, keytab);
	}
	TALLOC_FREE(frame);
	return 0;
}

/*
  simulate a kinit, putting the tgt in the given cache location.
  cache_name == NULL is not allowed.
  This tries all given passwords until we don't get
  KDC_ERR_PREAUTH_FAILED.
  If passwords[i] is NULL it falls back to nt_hashes[i]
*/
int kerberos_kinit_passwords_ext(const char *given_principal,
				 uint8_t num_passwords,
				 const char * const *passwords,
				 const struct samr_Password * const *nt_hashes,
				 uint8_t *used_idx,
				 const char *explicit_kdc,
				 const char *cache_name,
				 TALLOC_CTX *mem_ctx,
				 char **_canon_principal,
				 char **_canon_realm,
				 NTSTATUS *ntstatus)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct kerberos_kinit_passwords_ext_private ep = {
		.explicit_kdc = explicit_kdc,
		.timeout_msec = 15*1000,
	};
	NTSTATUS status;
	krb5_error_code ret;
	uint8_t i;
	krb5_error_code first_ret = EINVAL;
	NTSTATUS first_status = NT_STATUS_UNSUCCESSFUL;

	if (num_passwords == 0) {
		TALLOC_FREE(frame);
		return EINVAL;
	}
	if (num_passwords >= INT8_MAX) {
		TALLOC_FREE(frame);
		return EINVAL;
	}

#ifndef HAVE_KRB5_INIT_CREDS_STEP
	if (ep.explicit_kdc != NULL) {
		DBG_ERR("Using explicit_kdc requires krb5_init_creds_step!\n");
		TALLOC_FREE(frame);
		return EINVAL;
	}
#endif /* ! HAVE_KRB5_INIT_CREDS_STEP */

	DBG_DEBUG("explicit_kdc[%s] given_principal[%s] "
		  "num_passwords[%u] cache_name[%s]\n",
		  ep.explicit_kdc,
		  given_principal,
		  num_passwords,
		  cache_name);

	if (ep.explicit_kdc != NULL) {
		status = kerberos_transaction_cache_create(ep.explicit_kdc,
							   ep.timeout_msec,
							   frame,
							   &ep.kc);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return map_errno_from_nt_status(status);
		}
	}

	for (i = 0; i < num_passwords; i++) {
		ep.password = passwords[i];
		ep.nt_hash = nt_hashes[i];

		ret = kerberos_kinit_generic_once(given_principal,
						  kerberos_kinit_passwords_ext_cb,
						  &ep,
						  0, /* time_offset */
						  0, /* expire_time */
						  0, /* renew_till_time */
						  cache_name,
						  true, /* request_pac */
						  NULL, /* add_netbios_addr */
						  0,    /* renewable_time */
						  mem_ctx,
						  _canon_principal,
						  _canon_realm,
						  ntstatus);
		if (ret == 0) {
			*used_idx = i;
			TALLOC_FREE(frame);
			return 0;
		}
		if (i == 0) {
			first_ret = ret;
			first_status = *ntstatus;
		}
		if (ret != KRB5KDC_ERR_PREAUTH_FAILED) {
			*used_idx = i;
			TALLOC_FREE(frame);
			return ret;
		}
	}

	*used_idx = 0;
	*ntstatus = first_status;
	TALLOC_FREE(frame);
	return first_ret;
}

int ads_kdestroy(const char *cc_name)
{
	krb5_error_code code;
	krb5_context ctx = NULL;
	krb5_ccache cc = NULL;

	code = smb_krb5_init_context_common(&ctx);
	if (code != 0) {
		DBG_ERR("kerberos init context failed (%s)\n",
			error_message(code));
		return code;
	}

	/*
	 * This should not happen, if
	 * we need that behaviour we
	 * should add an ads_kdestroy_default()
	 */
	SMB_ASSERT(cc_name != NULL);

	code = krb5_cc_resolve(ctx, cc_name, &cc);
	if (code != 0) {
		DBG_NOTICE("krb5_cc_resolve(%s) failed: %s\n",
			   cc_name, error_message(code));
		krb5_free_context(ctx);
		return code;
	}

	code = krb5_cc_destroy(ctx, cc);
	if (code != 0) {
		DBG_ERR("krb5_cc_destroy(%s) failed: %s\n",
			cc_name, error_message(code));
	}

	krb5_free_context (ctx);
	return code;
}

int create_kerberos_key_from_string(krb5_context context,
					krb5_principal host_princ,
					krb5_principal salt_princ,
					krb5_data *password,
					krb5_keyblock *key,
					krb5_enctype enctype,
					bool no_salt)
{
	int ret;
	/*
	 * Check if we've determined that the KDC is salting keys for this
	 * principal/enctype in a non-obvious way.  If it is, try to match
	 * its behavior.
	 */
	if (no_salt) {
		KRB5_KEY_DATA(key) = (KRB5_KEY_DATA_CAST *)SMB_MALLOC(password->length);
		if (!KRB5_KEY_DATA(key)) {
			return ENOMEM;
		}
		memcpy(KRB5_KEY_DATA(key), password->data, password->length);
		KRB5_KEY_LENGTH(key) = password->length;
		KRB5_KEY_TYPE(key) = enctype;
		return 0;
	}
	ret = smb_krb5_create_key_from_string(context,
					      salt_princ ? salt_princ : host_princ,
					      NULL,
					      password,
					      enctype,
					      key);
	return ret;
}

/************************************************************************
************************************************************************/

int kerberos_kinit_password(const char *principal,
			    const char *password,
			    const char *cache_name)
{
	return kerberos_kinit_password_ext(principal,
					   password,
					   0,
					   NULL,
					   NULL,
					   cache_name,
					   False,
					   False,
					   0,
					   NULL,
					   NULL,
					   NULL,
					   NULL);
}

/************************************************************************
************************************************************************/

/************************************************************************
 Create a string list of available kdc's, possibly searching by sitename.
 Does DNS queries.

 If "sitename" is given, the DC's in that site are listed first.

************************************************************************/

static void add_sockaddr_unique(struct sockaddr_storage *addrs, size_t *num_addrs,
				const struct sockaddr_storage *addr)
{
	size_t i;

	for (i=0; i<*num_addrs; i++) {
		if (sockaddr_equal((const struct sockaddr *)&addrs[i],
				   (const struct sockaddr *)addr)) {
			return;
		}
	}
	addrs[i] = *addr;
	*num_addrs += 1;
}

/* print_canonical_sockaddr prints an ipv6 addr in the form of
* [ipv6.addr]. This string, when put in a generated krb5.conf file is not
* always properly dealt with by some older krb5 libraries. Adding the hard-coded
* portnumber workarounds the issue. - gd */

static char *print_canonical_sockaddr_with_port(TALLOC_CTX *mem_ctx,
						const struct sockaddr_storage *pss)
{
	char *str = NULL;

	str = print_canonical_sockaddr(mem_ctx, pss);
	if (str == NULL) {
		return NULL;
	}

	if (pss->ss_family != AF_INET6) {
		return str;
	}

#if defined(HAVE_IPV6)
	str = talloc_asprintf_append(str, ":88");
#endif
	return str;
}

static char *get_kdc_ip_string(char *mem_ctx,
		const char *realm,
		const char *sitename,
		const struct sockaddr_storage *pss)
{
	TALLOC_CTX *frame = talloc_stackframe();
	size_t i;
	struct samba_sockaddr *ip_sa_site = NULL;
	struct samba_sockaddr *ip_sa_nonsite = NULL;
	struct samba_sockaddr sa = {0};
	size_t count_site = 0;
	size_t count_nonsite;
	size_t num_dcs;
	struct sockaddr_storage *dc_addrs = NULL;
	struct tsocket_address **dc_addrs2 = NULL;
	char *result = NULL;
	struct netlogon_samlogon_response **responses = NULL;
	NTSTATUS status;
	bool ok;
	char *kdc_str = NULL;
	char *canon_sockaddr = NULL;

	kdc_str = talloc_strdup(frame, "");

	if (pss != NULL) {
		canon_sockaddr = print_canonical_sockaddr_with_port(frame, pss);
		if (canon_sockaddr == NULL) {
			goto out;
		}

		talloc_asprintf_addbuf(&kdc_str,
				       "\t\tkdc = %s\n",
				       canon_sockaddr);

		ok = sockaddr_storage_to_samba_sockaddr(&sa, pss);
		if (!ok) {
			goto out;
		}
	}

	/*
	 * First get the KDC's only in this site, the rest will be
	 * appended later
	 */

	if (sitename) {
		status = get_kdc_list(frame,
					realm,
					sitename,
					&ip_sa_site,
					&count_site);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("get_kdc_list fail %s\n",
				nt_errstr(status));
			goto out;
		}
		DBG_DEBUG("got %zu addresses from site %s search\n",
			count_site,
			sitename);
	}

	/* Get all KDC's. */

	status = get_kdc_list(frame,
					realm,
					NULL,
					&ip_sa_nonsite,
					&count_nonsite);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("get_kdc_list (site-less) fail %s\n",
			nt_errstr(status));
		goto out;
	}
	DBG_DEBUG("got %zu addresses from site-less search\n", count_nonsite);

	if (count_site + count_nonsite < count_site) {
		/* Wrap check. */
		DBG_ERR("get_kdc_list_talloc (site-less) fail wrap error\n");
		goto out;
	}


	dc_addrs = talloc_array(talloc_tos(), struct sockaddr_storage,
				count_site + count_nonsite);
	if (dc_addrs == NULL) {
		goto out;
	}

	num_dcs = 0;

	for (i = 0; i < count_site; i++) {
		if (!sockaddr_equal(&sa.u.sa, &ip_sa_site[i].u.sa)) {
			add_sockaddr_unique(dc_addrs, &num_dcs,
					    &ip_sa_site[i].u.ss);
		}
	}

	for (i = 0; i < count_nonsite; i++) {
		if (!sockaddr_equal(&sa.u.sa, &ip_sa_nonsite[i].u.sa)) {
			add_sockaddr_unique(dc_addrs, &num_dcs,
					    &ip_sa_nonsite[i].u.ss);
		}
	}

	DBG_DEBUG("%zu additional KDCs to test\n", num_dcs);
	if (num_dcs == 0) {
		/*
		 * We do not have additional KDCs, but if we have one passed
		 * in via `pss` just use that one, otherwise fail
		 */
		if (pss != NULL) {
			result = talloc_move(mem_ctx, &kdc_str);
		}
		goto out;
	}

	dc_addrs2 = talloc_zero_array(talloc_tos(),
				      struct tsocket_address *,
				      num_dcs);
	if (dc_addrs2 == NULL) {
		goto out;
	}

	for (i=0; i<num_dcs; i++) {
		char addr[INET6_ADDRSTRLEN];
		int ret;

		print_sockaddr(addr, sizeof(addr), &dc_addrs[i]);

		ret = tsocket_address_inet_from_strings(dc_addrs2, "ip",
							addr, LDAP_PORT,
							&dc_addrs2[i]);
		if (ret != 0) {
			status = map_nt_error_from_unix(errno);
			DEBUG(2,("Failed to create tsocket_address for %s - %s\n",
				 addr, nt_errstr(status)));
			goto out;
		}
	}

	status = netlogon_pings(talloc_tos(), /* mem_ctx */
				lp_client_netlogon_ping_protocol(), /* proto */
				dc_addrs2, /* servers */
				num_dcs,   /* num_servers */
				(struct netlogon_ping_filter){
					.ntversion = NETLOGON_NT_VERSION_5 |
						     NETLOGON_NT_VERSION_5EX,
					.domain = realm,
					.hostname = lp_netbios_name(),
					.acct_ctrl = -1,
					.required_flags = DS_KDC_REQUIRED,
				},
				MIN(num_dcs, 3),	   /* wanted_servers */
				timeval_current_ofs(3, 0), /* timeout */
				&responses);
	TALLOC_FREE(dc_addrs2);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("netlogon_pings failed: %s\n", nt_errstr(status));
		/*
		 * netlogon_pings() failed, but if we have one passed
		 * in via `pss` just just use that one, otherwise fail
		 */
		if (pss != NULL) {
			result = talloc_move(mem_ctx, &kdc_str);
		}
		goto out;
	}

	for (i=0; i<num_dcs; i++) {
		struct NETLOGON_SAM_LOGON_RESPONSE_EX *cldap_reply = NULL;
		char addr[INET6_ADDRSTRLEN];

		if (responses[i] == NULL) {
			continue;
		}

		if (responses[i]->ntver != NETLOGON_NT_VERSION_5EX) {
			continue;
		}

		print_sockaddr(addr, sizeof(addr), &dc_addrs[i]);

		cldap_reply = &responses[i]->data.nt5_ex;

		if (cldap_reply->pdc_dns_name != NULL) {
			status = check_negative_conn_cache(
				realm,
				cldap_reply->pdc_dns_name);
			if (!NT_STATUS_IS_OK(status)) {
				/* propagate blacklisting from name to ip */
				add_failed_connection_entry(realm, addr, status);
				continue;
			}
		}

		/* Append to the string - inefficient but not done often. */
		talloc_asprintf_addbuf(&kdc_str,
				       "\t\tkdc = %s\n",
				       print_canonical_sockaddr_with_port(
					       mem_ctx, &dc_addrs[i]));
	}

	result = talloc_move(mem_ctx, &kdc_str);
out:
	if (result != NULL) {
		DBG_DEBUG("Returning\n%s\n", result);
	} else {
		DBG_NOTICE("Failed to get KDC ip address\n");
	}

	TALLOC_FREE(frame);
	return result;
}

/************************************************************************
 Create  a specific krb5.conf file in the private directory pointing
 at a specific kdc for a realm. Keyed off domain name. Sets
 KRB5_CONFIG environment variable to point to this file. Must be
 run as root or will fail (which is a good thing :-).
************************************************************************/

#if !defined(SAMBA4_USES_HEIMDAL) /* MIT version */
static char *get_enctypes(TALLOC_CTX *mem_ctx)
{
	char *aes_enctypes = NULL;
	const char *legacy_enctypes = "";
	char *enctypes = NULL;

	aes_enctypes = talloc_strdup(mem_ctx, "");
	if (aes_enctypes == NULL) {
		goto done;
	}

	if (lp_kerberos_encryption_types() == KERBEROS_ETYPES_ALL ||
	    lp_kerberos_encryption_types() == KERBEROS_ETYPES_STRONG) {
		aes_enctypes = talloc_asprintf_append(
		    aes_enctypes, "%s", "aes256-cts-hmac-sha1-96 ");
		if (aes_enctypes == NULL) {
			goto done;
		}
		aes_enctypes = talloc_asprintf_append(
		    aes_enctypes, "%s", "aes128-cts-hmac-sha1-96");
		if (aes_enctypes == NULL) {
			goto done;
		}
	}

	if (lp_weak_crypto() == SAMBA_WEAK_CRYPTO_ALLOWED &&
	    (lp_kerberos_encryption_types() == KERBEROS_ETYPES_ALL ||
	     lp_kerberos_encryption_types() == KERBEROS_ETYPES_LEGACY)) {
		legacy_enctypes = "RC4-HMAC";
	}

	enctypes =
	    talloc_asprintf(mem_ctx, "\tdefault_tgs_enctypes = %s %s\n"
				     "\tdefault_tkt_enctypes = %s %s\n"
				     "\tpreferred_enctypes = %s %s\n",
			    aes_enctypes, legacy_enctypes, aes_enctypes,
			    legacy_enctypes, aes_enctypes, legacy_enctypes);
done:
	TALLOC_FREE(aes_enctypes);
	return enctypes;
}
#else /* Heimdal version */
static char *get_enctypes(TALLOC_CTX *mem_ctx)
{
	const char *aes_enctypes = "";
	const char *legacy_enctypes = "";
	char *enctypes = NULL;

	if (lp_kerberos_encryption_types() == KERBEROS_ETYPES_ALL ||
	    lp_kerberos_encryption_types() == KERBEROS_ETYPES_STRONG) {
		aes_enctypes =
		    "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96";
	}

	if (lp_kerberos_encryption_types() == KERBEROS_ETYPES_ALL ||
	    lp_kerberos_encryption_types() == KERBEROS_ETYPES_LEGACY) {
		legacy_enctypes = "arcfour-hmac-md5";
	}

	enctypes = talloc_asprintf(mem_ctx, "\tdefault_etypes = %s %s\n",
				   aes_enctypes, legacy_enctypes);

	return enctypes;
}
#endif

bool create_local_private_krb5_conf_for_domain(const char *realm,
						const char *domain,
						const char *sitename,
					        const struct sockaddr_storage *pss)
{
	char *dname;
	char *tmpname = NULL;
	char *fname = NULL;
	char *file_contents = NULL;
	char *kdc_ip_string = NULL;
	size_t flen = 0;
	ssize_t ret;
	int fd;
	char *realm_upper = NULL;
	bool result = false;
	char *enctypes = NULL;
	const char *include_system_krb5 = "";
	mode_t mask;
	/*
	 * The default will be 15 seconds, it can be changed in the smb.conf:
	 * [global]
	 *   krb5:request_timeout = 30
	 */
	int timeout_sec = lp_parm_int(-1,
				      "krb5",
				      "request_timeout",
				      15 /* default */);

	if (!lp_create_krb5_conf()) {
		return false;
	}

	if (realm == NULL) {
		DEBUG(0, ("No realm has been specified! Do you really want to "
			  "join an Active Directory server?\n"));
		return false;
	}

	if (domain == NULL) {
		return false;
	}

	dname = lock_path(talloc_tos(), "smb_krb5");
	if (!dname) {
		return false;
	}
	if ((mkdir(dname, 0755)==-1) && (errno != EEXIST)) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: "
			"failed to create directory %s. Error was %s\n",
			dname, strerror(errno) ));
		goto done;
	}

	tmpname = lock_path(talloc_tos(), "smb_tmp_krb5.XXXXXX");
	if (!tmpname) {
		goto done;
	}

	fname = talloc_asprintf(dname, "%s/krb5.conf.%s", dname, domain);
	if (!fname) {
		goto done;
	}

	DEBUG(10,("create_local_private_krb5_conf_for_domain: fname = %s, realm = %s, domain = %s\n",
		fname, realm, domain ));

	realm_upper = talloc_strdup(fname, realm);
	if (!strupper_m(realm_upper)) {
		goto done;
	}

	kdc_ip_string = get_kdc_ip_string(dname, realm, sitename, pss);
	if (!kdc_ip_string) {
		goto done;
	}

	enctypes = get_enctypes(fname);
	if (enctypes == NULL) {
		goto done;
	}

#if !defined(SAMBA4_USES_HEIMDAL)
	if (lp_include_system_krb5_conf()) {
		include_system_krb5 = "include /etc/krb5.conf";
	}
#endif

	/*
	 * We are setting 'dns_lookup_kdc' to true, because we want to lookup
	 * KDCs which are not configured via DNS SRV records, eg. if we do:
	 *
	 *     net ads join -Uadmin@otherdomain
	 */
	file_contents =
	    talloc_asprintf(fname,
			    "[libdefaults]\n"
#ifdef SAMBA4_USES_HEIMDAL
			    "\tkdc_timeout = %d\n"
#else
			    "\trequest_timeout = %ds\n"
#endif
			    "\tdefault_realm = %s\n"
			    "%s"
			    "\tdns_lookup_realm = false\n"
			    "\tdns_lookup_kdc = true\n\n"
			    "[realms]\n\t%s = {\n"
			    "%s\t}\n"
			    "\t%s = {\n"
			    "%s\t}\n"
			    "%s\n",
			    timeout_sec,
			    realm_upper,
			    enctypes,
			    realm_upper,
			    kdc_ip_string,
			    domain,
			    kdc_ip_string,
			    include_system_krb5);

	if (!file_contents) {
		goto done;
	}

	flen = strlen(file_contents);

	mask = umask(S_IRWXO | S_IRWXG);
	fd = mkstemp(tmpname);
	umask(mask);
	if (fd == -1) {
		DBG_ERR("mkstemp failed, for file %s. Errno %s\n",
			tmpname,
			strerror(errno));
		goto done;
	}

	if (fchmod(fd, 0644)==-1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: fchmod failed for %s."
			" Errno %s\n",
			tmpname, strerror(errno) ));
		unlink(tmpname);
		close(fd);
		goto done;
	}

	ret = write(fd, file_contents, flen);
	if (flen != ret) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: write failed,"
			" returned %d (should be %u). Errno %s\n",
			(int)ret, (unsigned int)flen, strerror(errno) ));
		unlink(tmpname);
		close(fd);
		goto done;
	}
	if (close(fd)==-1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: close failed."
			" Errno %s\n", strerror(errno) ));
		unlink(tmpname);
		goto done;
	}

	if (rename(tmpname, fname) == -1) {
		DEBUG(0,("create_local_private_krb5_conf_for_domain: rename "
			"of %s to %s failed. Errno %s\n",
			tmpname, fname, strerror(errno) ));
		unlink(tmpname);
		goto done;
	}

	DBG_INFO("wrote file %s with realm %s KDC list:\n%s\n",
		 fname, realm_upper, kdc_ip_string);

	/* Set the environment variable to this file. */
	setenv("KRB5_CONFIG", fname, 1);

	result = true;

#if defined(OVERWRITE_SYSTEM_KRB5_CONF)

#define SYSTEM_KRB5_CONF_PATH "/etc/krb5.conf"
	/* Insanity, sheer insanity..... */

	if (strequal(realm, lp_realm())) {
		SMB_STRUCT_STAT sbuf;

		if (sys_lstat(SYSTEM_KRB5_CONF_PATH, &sbuf, false) == 0) {
			if (S_ISLNK(sbuf.st_ex_mode) && sbuf.st_ex_size) {
				int lret;
				size_t alloc_size = sbuf.st_ex_size + 1;
				char *linkpath = talloc_array(talloc_tos(), char,
						alloc_size);
				if (!linkpath) {
					goto done;
				}
				lret = readlink(SYSTEM_KRB5_CONF_PATH, linkpath,
						alloc_size - 1);
				if (lret == -1) {
					TALLOC_FREE(linkpath);
					goto done;
				}
				linkpath[lret] = '\0';

				if (strcmp(linkpath, fname) == 0) {
					/* Symlink already exists. */
					TALLOC_FREE(linkpath);
					goto done;
				}
				TALLOC_FREE(linkpath);
			}
		}

		/* Try and replace with a symlink. */
		if (symlink(fname, SYSTEM_KRB5_CONF_PATH) == -1) {
			const char *newpath = SYSTEM_KRB5_CONF_PATH ".saved";
			if (errno != EEXIST) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: symlink "
					"of %s to %s failed. Errno %s\n",
					fname, SYSTEM_KRB5_CONF_PATH, strerror(errno) ));
				goto done; /* Not a fatal error. */
			}

			/* Yes, this is a race condition... too bad. */
			if (rename(SYSTEM_KRB5_CONF_PATH, newpath) == -1) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: rename "
					"of %s to %s failed. Errno %s\n",
					SYSTEM_KRB5_CONF_PATH, newpath,
					strerror(errno) ));
				goto done; /* Not a fatal error. */
			}

			if (symlink(fname, SYSTEM_KRB5_CONF_PATH) == -1) {
				DEBUG(0,("create_local_private_krb5_conf_for_domain: "
					"forced symlink of %s to /etc/krb5.conf failed. Errno %s\n",
					fname, strerror(errno) ));
				goto done; /* Not a fatal error. */
			}
		}
	}
#endif

done:
	TALLOC_FREE(tmpname);
	TALLOC_FREE(dname);

	return result;
}
#endif
