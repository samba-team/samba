/*
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2006

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
#include "system/network.h"
#define TEVENT_DEPRECATED 1
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "auth/common_auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

_PRIVATE_ NTSTATUS gensec_may_reset_crypto(struct gensec_security *gensec_security,
					   bool full_reset)
{
	if (!gensec_security->ops->may_reset_crypto) {
		return NT_STATUS_OK;
	}

	return gensec_security->ops->may_reset_crypto(gensec_security, full_reset);
}

/*
  wrappers for the gensec function pointers
*/
_PUBLIC_ NTSTATUS gensec_unseal_packet(struct gensec_security *gensec_security,
			      uint8_t *data, size_t length,
			      const uint8_t *whole_pdu, size_t pdu_length,
			      const DATA_BLOB *sig)
{
	if (!gensec_security->ops->unseal_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_DCE_STYLE)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_security->ops->unseal_packet(gensec_security,
						   data, length,
						   whole_pdu, pdu_length,
						   sig);
}

_PUBLIC_ NTSTATUS gensec_check_packet(struct gensec_security *gensec_security,
			     const uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     const DATA_BLOB *sig)
{
	if (!gensec_security->ops->check_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_security->ops->check_packet(gensec_security, data, length, whole_pdu, pdu_length, sig);
}

_PUBLIC_ NTSTATUS gensec_seal_packet(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    DATA_BLOB *sig)
{
	if (!gensec_security->ops->seal_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_DCE_STYLE)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_security->ops->seal_packet(gensec_security, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

_PUBLIC_ NTSTATUS gensec_sign_packet(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    const uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    DATA_BLOB *sig)
{
	if (!gensec_security->ops->sign_packet) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_security->ops->sign_packet(gensec_security, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

_PUBLIC_ size_t gensec_sig_size(struct gensec_security *gensec_security, size_t data_size)
{
	if (!gensec_security->ops->sig_size) {
		return 0;
	}
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		return 0;
	}
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_DCE_STYLE)) {
			return 0;
		}
	}

	return gensec_security->ops->sig_size(gensec_security, data_size);
}

_PUBLIC_ size_t gensec_max_wrapped_size(struct gensec_security *gensec_security)
{
	if (!gensec_security->ops->max_wrapped_size) {
		return (1 << 17);
	}

	return gensec_security->ops->max_wrapped_size(gensec_security);
}

_PUBLIC_ size_t gensec_max_input_size(struct gensec_security *gensec_security)
{
	if (!gensec_security->ops->max_input_size) {
		return (1 << 17) - gensec_sig_size(gensec_security, 1 << 17);
	}

	return gensec_security->ops->max_input_size(gensec_security);
}

_PUBLIC_ NTSTATUS gensec_wrap(struct gensec_security *gensec_security,
		     TALLOC_CTX *mem_ctx,
		     const DATA_BLOB *in,
		     DATA_BLOB *out)
{
	if (!gensec_security->ops->wrap) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return gensec_security->ops->wrap(gensec_security, mem_ctx, in, out);
}

_PUBLIC_ NTSTATUS gensec_unwrap(struct gensec_security *gensec_security,
		       TALLOC_CTX *mem_ctx,
		       const DATA_BLOB *in,
		       DATA_BLOB *out)
{
	if (!gensec_security->ops->unwrap) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return gensec_security->ops->unwrap(gensec_security, mem_ctx, in, out);
}

_PUBLIC_ NTSTATUS gensec_session_key(struct gensec_security *gensec_security,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *session_key)
{
	if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SESSION_KEY)) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (!gensec_security->ops->session_key) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return gensec_security->ops->session_key(gensec_security, mem_ctx, session_key);
}

const char *gensec_final_auth_type(struct gensec_security *gensec_security)
{
	if (!gensec_security->ops->final_auth_type) {
		return gensec_security->ops->name;
	}

	return gensec_security->ops->final_auth_type(gensec_security);
}

/*
 * Log details of a successful GENSEC authorization to a service.
 *
 * Only successful authorizations are logged, as only these call gensec_session_info()
 *
 * The service may later refuse authorization due to an ACL.
 *
 */
static void log_successful_gensec_authz_event(struct gensec_security *gensec_security,
					      struct auth_session_info *session_info)
{
	const struct tsocket_address *remote
		= gensec_get_remote_address(gensec_security);
	const struct tsocket_address *local
		= gensec_get_local_address(gensec_security);
	const char *service_description
		= gensec_get_target_service_description(gensec_security);
	const char *final_auth_type
		= gensec_final_auth_type(gensec_security);
	const char *transport_protection = NULL;
	if (gensec_security->want_features & GENSEC_FEATURE_SMB_TRANSPORT) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_SMB;
	} else if (gensec_security->want_features & GENSEC_FEATURE_LDAPS_TRANSPORT) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_TLS;
	} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_SEAL;
	} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_SIGN;
	} else {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_NONE;
	}
	log_successful_authz_event(gensec_security->auth_context->msg_ctx,
				   gensec_security->auth_context->lp_ctx,
				   remote, local,
				   service_description,
				   final_auth_type,
				   transport_protection,
				   session_info);
}


/**
 * Return the credentials of a logged on user, including session keys
 * etc.
 *
 * Only valid after a successful authentication
 *
 * May only be called once per authentication.  This will also make an
 * authorization log entry, as it is already called by all the
 * callers.
 *
 */

_PUBLIC_ NTSTATUS gensec_session_info(struct gensec_security *gensec_security,
				      TALLOC_CTX *mem_ctx,
				      struct auth_session_info **session_info)
{
	NTSTATUS status;
	if (!gensec_security->ops->session_info) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	status = gensec_security->ops->session_info(gensec_security, mem_ctx, session_info);

	if (NT_STATUS_IS_OK(status) && !gensec_security->subcontext
	    && (gensec_security->want_features & GENSEC_FEATURE_NO_AUTHZ_LOG) == 0) {
		log_successful_gensec_authz_event(gensec_security, *session_info);
	}

	return status;
}

_PUBLIC_ void gensec_set_max_update_size(struct gensec_security *gensec_security,
				uint32_t max_update_size)
{
	gensec_security->max_update_size = max_update_size;
}

_PUBLIC_ size_t gensec_max_update_size(struct gensec_security *gensec_security)
{
	if (gensec_security->max_update_size == 0) {
		return UINT32_MAX;
	}

	return gensec_security->max_update_size;
}

static NTSTATUS gensec_verify_features(struct gensec_security *gensec_security)
{
	bool ok;

	/*
	 * gensec_want_feature(GENSEC_FEATURE_SIGN)
	 * and
	 * gensec_want_feature(GENSEC_FEATURE_SEAL)
	 * require these flags to be available.
	 */
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
			DEBUG(0,("Did not manage to negotiate mandatory feature "
				 "SIGN\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
			DEBUG(0,("Did not manage to negotiate mandatory feature "
				 "SEAL\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
		if (!gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
			DEBUG(0,("Did not manage to negotiate mandatory feature "
				 "SIGN for SEAL\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (gensec_security->dcerpc_auth_level < DCERPC_AUTH_LEVEL_PACKET) {
		return NT_STATUS_OK;
	}

	ok = gensec_have_feature(gensec_security,
				 GENSEC_FEATURE_SIGN_PKT_HEADER);
	if (!ok) {
		DBG_ERR("backend [%s] does not support header signing! "
			"auth_level[0x%x]\n",
			gensec_security->ops->name,
			gensec_security->dcerpc_auth_level);
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

/**
 * Next state function for the GENSEC state machine
 *
 * @param gensec_security GENSEC State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent,
 *                or NT_STATUS_OK if the user is authenticated.
 */
_PUBLIC_ NTSTATUS gensec_update(struct gensec_security *gensec_security,
				TALLOC_CTX *out_mem_ctx,
				const DATA_BLOB in, DATA_BLOB *out)
{
	NTSTATUS status;
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev = NULL;
	struct tevent_req *subreq = NULL;
	bool ok;

	if (gensec_security->subcontext) {
		/*
		 * gensec modules are not allowed to call the sync version.
		 */
		return NT_STATUS_INTERNAL_ERROR;
	}

	frame = talloc_stackframe();

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	/*
	 * TODO: remove this hack once the backends
	 * are fixed.
	 */
	tevent_loop_allow_nesting(ev);

	subreq = gensec_update_send(frame, ev, gensec_security, in);
	if (subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(subreq, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = gensec_update_recv(subreq, out_mem_ctx, out);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct gensec_update_state {
	const struct gensec_security_ops *ops;
	struct gensec_security *gensec_security;
	NTSTATUS status;
	DATA_BLOB out;
};

static void gensec_update_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state);
static void gensec_update_done(struct tevent_req *subreq);

/**
 * Next state function for the GENSEC state machine async version
 *
 * @param mem_ctx The memory context for the request
 * @param ev The event context for the request
 * @param gensec_security GENSEC State
 * @param in The request, as a DATA_BLOB
 *
 * @return The request handle or NULL on no memory failure
 */

_PUBLIC_ struct tevent_req *gensec_update_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct gensec_security *gensec_security,
					       const DATA_BLOB in)
{
	struct tevent_req *req = NULL;
	struct gensec_update_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_update_state);
	if (req == NULL) {
		return NULL;
	}
	state->ops = gensec_security->ops;
	state->gensec_security = gensec_security;

	if (gensec_security->update_busy_ptr != NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	if (gensec_security->child_security != NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	gensec_security->update_busy_ptr = &state->gensec_security;
	tevent_req_set_cleanup_fn(req, gensec_update_cleanup);

	subreq = state->ops->update_send(state, ev, gensec_security, in);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, gensec_update_done, req);

	DBG_DEBUG("%s[%p]: subreq: %p\n", state->ops->name,
		  state->gensec_security, subreq);

	return req;
}

static void gensec_update_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct gensec_update_state *state =
		tevent_req_data(req,
		struct gensec_update_state);

	if (state->gensec_security == NULL) {
		return;
	}

	if (state->gensec_security->update_busy_ptr == &state->gensec_security) {
		state->gensec_security->update_busy_ptr = NULL;
	}

	state->gensec_security = NULL;
}

static void gensec_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct gensec_update_state *state =
		tevent_req_data(req,
		struct gensec_update_state);
	NTSTATUS status;
	const char *debug_subreq = NULL;

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		/*
		 * We need to call tevent_req_print()
		 * before calling the _recv function,
		 * before tevent_req_received() was called.
		 * in order to print the pointer value of
		 * the subreq state.
		 */
		debug_subreq = tevent_req_print(state, subreq);
	}

	status = state->ops->update_recv(subreq, state, &state->out);
	TALLOC_FREE(subreq);
	state->status = status;
	if (GENSEC_UPDATE_IS_NTERROR(status)) {
		NTSTATUS orig_status = status;
		bool force_no_such_user = false;

		/*
		 * callers only expect NT_STATUS_NO_SUCH_USER.
		 */
		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_ACCOUNT_NAME)) {
			force_no_such_user = true;
		} else if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_DOMAIN)) {
			force_no_such_user = true;
		}

		if (state->gensec_security->subcontext) {
			/*
			 * We should only map on the outer
			 * gensec_update exchange, spnego
			 * needs the raw status.
			 */
			force_no_such_user = false;
		}

		if (force_no_such_user) {
			/*
			 * nt_status_squash() may map
			 * to NT_STATUS_LOGON_FAILURE later
			 */
			status = NT_STATUS_NO_SUCH_USER;
		}

		DBG_INFO("%s[%p]: %s%s%s%s%s\n",
			 state->ops->name,
			 state->gensec_security,
			 NT_STATUS_EQUAL(status, orig_status) ?
			 "" : nt_errstr(orig_status),
			 NT_STATUS_EQUAL(status, orig_status) ?
			 "" : " ",
			 nt_errstr(status),
			 debug_subreq ? " " : "",
			 debug_subreq ? debug_subreq : "");
		tevent_req_nterror(req, status);
		return;
	}
	DBG_DEBUG("%s[%p]: %s %s\n", state->ops->name,
		  state->gensec_security, nt_errstr(status),
		  debug_subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_done(req);
		return;
	}

	/*
	 * Because callers using the
	 * gensec_start_mech_by_authtype() never call
	 * gensec_want_feature(), it isn't sensible for them
	 * to have to call gensec_have_feature() manually, and
	 * these are not points of negotiation, but are
	 * asserted by the client
	 */
	status = gensec_verify_features(state->gensec_security);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

/**
 * Next state function for the GENSEC state machine
 *
 * @param req request state
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent,
 *                or NT_STATUS_OK if the user is authenticated.
 */
_PUBLIC_ NTSTATUS gensec_update_recv(struct tevent_req *req,
				     TALLOC_CTX *out_mem_ctx,
				     DATA_BLOB *out)
{
	struct gensec_update_state *state =
		tevent_req_data(req, struct gensec_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out = state->out;
	talloc_steal(out_mem_ctx, out->data);
	status = state->status;
	tevent_req_received(req);
	return status;
}

/**
 * Set the requirement for a certain feature on the connection
 *
 */

_PUBLIC_ void gensec_want_feature(struct gensec_security *gensec_security,
			 uint32_t feature)
{
	if (!gensec_security->ops || !gensec_security->ops->want_feature) {
		gensec_security->want_features |= feature;
		return;
	}
	gensec_security->ops->want_feature(gensec_security, feature);
}

/**
 * Check the requirement for a certain feature on the connection
 *
 */

_PUBLIC_ bool gensec_have_feature(struct gensec_security *gensec_security,
			 uint32_t feature)
{
	if (!gensec_security->ops || !gensec_security->ops->have_feature) {
		return false;
	}

	/* We might 'have' features that we don't 'want', because the
	 * other end demanded them, or we can't neotiate them off */
	return gensec_security->ops->have_feature(gensec_security, feature);
}

_PUBLIC_ NTTIME gensec_expire_time(struct gensec_security *gensec_security)
{
	if (!gensec_security->ops->expire_time) {
		return GENSEC_EXPIRE_TIME_INFINITY;
	}

	return gensec_security->ops->expire_time(gensec_security);
}
/**
 * Return the credentials structure associated with a GENSEC context
 *
 */

_PUBLIC_ struct cli_credentials *gensec_get_credentials(struct gensec_security *gensec_security)
{
	if (!gensec_security) {
		return NULL;
	}
	return gensec_security->credentials;
}

/**
 * Set the target service (such as 'http' or 'host') on a GENSEC context - ensures it is talloc()ed
 *
 * This is used for Kerberos service principal name resolution.
 */

_PUBLIC_ NTSTATUS gensec_set_target_service(struct gensec_security *gensec_security, const char *service)
{
	gensec_security->target.service = talloc_strdup(gensec_security, service);
	if (!gensec_security->target.service) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

_PUBLIC_ const char *gensec_get_target_service(struct gensec_security *gensec_security)
{
	if (gensec_security->target.service) {
		return gensec_security->target.service;
	}

	return "host";
}

/**
 * Set the target service (such as 'samr') on an GENSEC context - ensures it is talloc()ed.
 *
 * This is not the Kerberos service principal, instead this is a
 * constant value that can be logged as part of authentication and
 * authorization logging
 */
_PUBLIC_ NTSTATUS gensec_set_target_service_description(struct gensec_security *gensec_security,
							const char *service)
{
	gensec_security->target.service_description = talloc_strdup(gensec_security, service);
	if (!gensec_security->target.service_description) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

_PUBLIC_ const char *gensec_get_target_service_description(struct gensec_security *gensec_security)
{
	if (gensec_security->target.service_description) {
		return gensec_security->target.service_description;
	} else if (gensec_security->target.service) {
		return gensec_security->target.service;
	}

	return NULL;
}

/**
 * Set the target hostname (suitable for kerberos resolutation) on a GENSEC context - ensures it is talloc()ed
 *
 */

_PUBLIC_ NTSTATUS gensec_set_target_hostname(struct gensec_security *gensec_security, const char *hostname)
{
	gensec_security->target.hostname = talloc_strdup(gensec_security, hostname);
	if (hostname && !gensec_security->target.hostname) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

_PUBLIC_ const char *gensec_get_target_hostname(struct gensec_security *gensec_security)
{
	/* We allow the target hostname to be overridden for testing purposes */
	if (gensec_security->settings->target_hostname) {
		return gensec_security->settings->target_hostname;
	}

	if (gensec_security->target.hostname) {
		return gensec_security->target.hostname;
	}

	/* We could add use the 'set sockaddr' call, and do a reverse
	 * lookup, but this would be both insecure (compromising the
	 * way kerberos works) and add DNS timeouts */
	return NULL;
}

/**
 * Set (and copy) local and peer socket addresses onto a socket
 * context on the GENSEC context.
 *
 * This is so that kerberos can include these addresses in
 * cryptographic tokens, to avoid certain attacks.
 */

/**
 * @brief Set the local gensec address.
 *
 * @param  gensec_security   The gensec security context to use.
 *
 * @param  remote       The local address to set.
 *
 * @return              On success NT_STATUS_OK is returned or an NT_STATUS
 *                      error.
 */
_PUBLIC_ NTSTATUS gensec_set_local_address(struct gensec_security *gensec_security,
		const struct tsocket_address *local)
{
	TALLOC_FREE(gensec_security->local_addr);

	if (local == NULL) {
		return NT_STATUS_OK;
	}

	gensec_security->local_addr = tsocket_address_copy(local, gensec_security);
	if (gensec_security->local_addr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/**
 * @brief Set the remote gensec address.
 *
 * @param  gensec_security   The gensec security context to use.
 *
 * @param  remote       The remote address to set.
 *
 * @return              On success NT_STATUS_OK is returned or an NT_STATUS
 *                      error.
 */
_PUBLIC_ NTSTATUS gensec_set_remote_address(struct gensec_security *gensec_security,
		const struct tsocket_address *remote)
{
	TALLOC_FREE(gensec_security->remote_addr);

	if (remote == NULL) {
		return NT_STATUS_OK;
	}

	gensec_security->remote_addr = tsocket_address_copy(remote, gensec_security);
	if (gensec_security->remote_addr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/**
 * @brief Get the local address from a gensec security context.
 *
 * @param  gensec_security   The security context to get the address from.
 *
 * @return              The address as tsocket_address which could be NULL if
 *                      no address is set.
 */
_PUBLIC_ const struct tsocket_address *gensec_get_local_address(struct gensec_security *gensec_security)
{
	if (gensec_security == NULL) {
		return NULL;
	}
	return gensec_security->local_addr;
}

/**
 * @brief Get the remote address from a gensec security context.
 *
 * @param  gensec_security   The security context to get the address from.
 *
 * @return              The address as tsocket_address which could be NULL if
 *                      no address is set.
 */
_PUBLIC_ const struct tsocket_address *gensec_get_remote_address(struct gensec_security *gensec_security)
{
	if (gensec_security == NULL) {
		return NULL;
	}
	return gensec_security->remote_addr;
}

/**
 * Set the target principal (assuming it it known, say from the SPNEGO reply)
 *  - ensures it is talloc()ed
 *
 */

_PUBLIC_ NTSTATUS gensec_set_target_principal(struct gensec_security *gensec_security, const char *principal)
{
	gensec_security->target.principal = talloc_strdup(gensec_security, principal);
	if (!gensec_security->target.principal) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

_PUBLIC_ const char *gensec_get_target_principal(struct gensec_security *gensec_security)
{
	if (gensec_security->target.principal) {
		return gensec_security->target.principal;
	}

	return NULL;
}
