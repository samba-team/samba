/* 
   Unix SMB/CIFS implementation.

   dcerpc authentication operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

struct gensec_ntlmssp_state {
	struct auth_context *auth_context;
	struct auth_serversupplied_info *server_info;
	struct ntlmssp_state *ntlmssp_state;
};


/**
 * Return the challenge as determined by the authentication subsystem 
 * @return an 8 byte random challenge
 */

static const uint8_t *auth_ntlmssp_get_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = ntlmssp_state->auth_context;

	return gensec_ntlmssp_state->auth_context->get_ntlm_challenge(gensec_ntlmssp_state->auth_context);
}

/**
 * Some authentication methods 'fix' the challenge, so we may not be able to set it
 *
 * @return If the effective challenge used by the auth subsystem may be modified
 */
static BOOL auth_ntlmssp_may_set_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = ntlmssp_state->auth_context;

	return gensec_ntlmssp_state->auth_context->challenge_may_be_modified;
}

/**
 * NTLM2 authentication modifies the effective challenge, 
 * @param challenge The new challenge value
 */
static NTSTATUS auth_ntlmssp_set_challenge(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *challenge)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = ntlmssp_state->auth_context;
	struct auth_context *auth_context = gensec_ntlmssp_state->auth_context;

	SMB_ASSERT(challenge->length == 8);

	auth_context->challenge = data_blob_talloc(auth_context, 
						   challenge->data, challenge->length);

	auth_context->challenge_set_by = "NTLMSSP callback (NTLM2)";

	DEBUG(5, ("auth_context challenge set by %s\n", auth_context->challenge_set_by));
	DEBUG(5, ("challenge is: \n"));
	dump_data(5, (const char *)auth_context->challenge.data, auth_context->challenge.length);
	return NT_STATUS_OK;
}

/**
 * Check the password on an NTLMSSP login.  
 *
 * Return the session keys used on the connection.
 */

static NTSTATUS auth_ntlmssp_check_password(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *user_session_key, DATA_BLOB *lm_session_key) 
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = ntlmssp_state->auth_context;
	struct auth_usersupplied_info *user_info = NULL;
	NTSTATUS nt_status;

#if 0
	/* the client has given us its machine name (which we otherwise would not get on port 445).
	   we need to possibly reload smb.conf if smb.conf includes depend on the machine name */

	set_remote_machine_name(gensec_ntlmssp_state->ntlmssp_state->workstation, True);

	/* setup the string used by %U */
	/* sub_set_smb_name checks for weird internally */
	sub_set_smb_name(gensec_ntlmssp_state->ntlmssp_state->user);

	reload_services(True);

#endif
	nt_status = make_user_info_map(ntlmssp_state,
				       &user_info, 
				       gensec_ntlmssp_state->ntlmssp_state->user, 
				       gensec_ntlmssp_state->ntlmssp_state->domain, 
				       gensec_ntlmssp_state->ntlmssp_state->workstation, 
	                               gensec_ntlmssp_state->ntlmssp_state->lm_resp.data ? &gensec_ntlmssp_state->ntlmssp_state->lm_resp : NULL, 
	                               gensec_ntlmssp_state->ntlmssp_state->nt_resp.data ? &gensec_ntlmssp_state->ntlmssp_state->nt_resp : NULL, 
				       NULL, NULL, NULL,
				       True);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = gensec_ntlmssp_state->auth_context->check_ntlm_password(gensec_ntlmssp_state->auth_context, 
									  user_info, &gensec_ntlmssp_state->server_info); 

	free_user_info(&user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	if (gensec_ntlmssp_state->server_info->user_session_key.length) {
		DEBUG(10, ("Got NT session key of length %u\n", gensec_ntlmssp_state->server_info->user_session_key.length));
		*user_session_key = data_blob_talloc(ntlmssp_state, 
						   gensec_ntlmssp_state->server_info->user_session_key.data,
						   gensec_ntlmssp_state->server_info->user_session_key.length);
	}
	if (gensec_ntlmssp_state->server_info->lm_session_key.length) {
		DEBUG(10, ("Got LM session key of length %u\n", gensec_ntlmssp_state->server_info->lm_session_key.length));
		*lm_session_key = data_blob_talloc(ntlmssp_state, 
						   gensec_ntlmssp_state->server_info->lm_session_key.data,
						   gensec_ntlmssp_state->server_info->lm_session_key.length);
	}
	return nt_status;
}

static NTSTATUS gensec_ntlmssp_start(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state;
	
	gensec_ntlmssp_state = talloc_p(gensec_security, struct gensec_ntlmssp_state);
	if (!gensec_ntlmssp_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_ntlmssp_state->ntlmssp_state = NULL;
	gensec_ntlmssp_state->auth_context = NULL;
	gensec_ntlmssp_state->server_info = NULL;

	gensec_security->private_data = gensec_ntlmssp_state;
	return NT_STATUS_OK;
}

static NTSTATUS gensec_ntlmssp_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	NTSTATUS status;
	struct ntlmssp_state *ntlmssp_state;
	struct gensec_ntlmssp_state *gensec_ntlmssp_state;

	status = gensec_ntlmssp_start(gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	gensec_ntlmssp_state = gensec_security->private_data;

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_server_start(gensec_security,
							      &gensec_ntlmssp_state->ntlmssp_state))) {
		return nt_status;
	}

	if (gensec_security->want_features & GENSEC_WANT_SIGN) {
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_WANT_SEAL) {
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	/* IF we are not doing Signing or Sealing, we can actually do
	 * NTLM2.  When we crack the crypto puzzle, then we can enable
	 * this always, in the constant flags */

	if (!(gensec_security->want_features & GENSEC_WANT_SIGN) && !(gensec_security->want_features & GENSEC_WANT_SEAL)) {
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	ntlmssp_state = gensec_ntlmssp_state->ntlmssp_state;
	nt_status = make_auth_context_subsystem(gensec_security, &gensec_ntlmssp_state->auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	ntlmssp_state->auth_context = gensec_ntlmssp_state;
	ntlmssp_state->get_challenge = auth_ntlmssp_get_challenge;
	ntlmssp_state->may_set_challenge = auth_ntlmssp_may_set_challenge;
	ntlmssp_state->set_challenge = auth_ntlmssp_set_challenge;
	ntlmssp_state->check_password = auth_ntlmssp_check_password;
	ntlmssp_state->server_role = lp_server_role();
	
	return NT_STATUS_OK;
}

static NTSTATUS gensec_ntlmssp_client_start(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state;
	char *password = NULL;
	
	NTSTATUS status;
	status = gensec_ntlmssp_start(gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	gensec_ntlmssp_state = gensec_security->private_data;
	status = ntlmssp_client_start(gensec_security, 
				      &gensec_ntlmssp_state->ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (gensec_security->want_features & GENSEC_WANT_SESSION_KEY) {
		/*
		 * We need to set this to allow a later SetPassword
		 * via the SAMR pipe to succeed. Strange.... We could
		 * also add  NTLMSSP_NEGOTIATE_SEAL here. JRA.
		 * 
		 * Without this, Windows will not create the master key
		 * that it thinks is only used for NTLMSSP signing and 
		 * sealing.  (It is actually pulled out and used directly) 
		 */
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_WANT_SIGN) {
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_WANT_SEAL) {
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	/* IF we are not doing Signing or Sealing, we can actually do
	 * NTLM2.  When we crack the crypto puzzle, then we can enable
	 * this always, in the constant flags */

	if (!(gensec_security->want_features & GENSEC_WANT_SIGN) && !(gensec_security->want_features & GENSEC_WANT_SEAL)) {
		gensec_ntlmssp_state->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	status = ntlmssp_set_domain(gensec_ntlmssp_state->ntlmssp_state, 
				    gensec_security->user.domain);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	status = ntlmssp_set_username(gensec_ntlmssp_state->ntlmssp_state, 
				      gensec_security->user.name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_get_password(gensec_security, gensec_ntlmssp_state, &password);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (password) {
		status = ntlmssp_set_password(gensec_ntlmssp_state->ntlmssp_state, 
					      password);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	gensec_security->private_data = gensec_ntlmssp_state;

	return status;
}

/*
  wrappers for the ntlmssp_*() functions
*/
static NTSTATUS gensec_ntlmssp_unseal_packet(struct gensec_security *gensec_security, 
					     TALLOC_CTX *mem_ctx, 
					     uint8_t *data, size_t length, 
					     const uint8_t *whole_pdu, size_t pdu_length, 
					     DATA_BLOB *sig)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	return ntlmssp_unseal_packet(gensec_ntlmssp_state->ntlmssp_state, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

static NTSTATUS gensec_ntlmssp_check_packet(struct gensec_security *gensec_security, 
					    TALLOC_CTX *mem_ctx, 
					    const uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length, 
					    const DATA_BLOB *sig)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	return ntlmssp_check_packet(gensec_ntlmssp_state->ntlmssp_state, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

static NTSTATUS gensec_ntlmssp_seal_packet(struct gensec_security *gensec_security, 
					   TALLOC_CTX *mem_ctx, 
					   uint8_t *data, size_t length, 
					   const uint8_t *whole_pdu, size_t pdu_length, 
					   DATA_BLOB *sig)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	return ntlmssp_seal_packet(gensec_ntlmssp_state->ntlmssp_state, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

static NTSTATUS gensec_ntlmssp_sign_packet(struct gensec_security *gensec_security, 
					   TALLOC_CTX *mem_ctx, 
					   const uint8_t *data, size_t length, 
					   const uint8_t *whole_pdu, size_t pdu_length, 
					   DATA_BLOB *sig)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	return ntlmssp_sign_packet(gensec_ntlmssp_state->ntlmssp_state, mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

static size_t gensec_ntlmssp_sig_size(struct gensec_security *gensec_security) 
{
	return NTLMSSP_SIG_SIZE;
}

static NTSTATUS gensec_ntlmssp_session_key(struct gensec_security *gensec_security, 
					   DATA_BLOB *session_key)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	return ntlmssp_session_key(gensec_ntlmssp_state->ntlmssp_state, session_key);
}

/**
 * Next state function for the wrapped NTLMSSP state machine
 * 
 * @param gensec_security GENSEC state, initialised to NTLMSSP
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent, 
 *                or NT_STATUS_OK if the user is authenticated. 
 */

static NTSTATUS gensec_ntlmssp_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
				      const DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	return ntlmssp_update(gensec_ntlmssp_state->ntlmssp_state, out_mem_ctx, in, out);
}

/** 
 * Return the credentials of a logged on user, including session keys
 * etc.
 *
 * Only valid after a successful authentication
 *
 * May only be called once per authentication.
 *
 */

static NTSTATUS gensec_ntlmssp_session_info(struct gensec_security *gensec_security,
				     struct auth_session_info **session_info) 
{
	NTSTATUS nt_status;
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;
	nt_status = make_session_info(gensec_ntlmssp_state->server_info, session_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	/* the session_info owns this now */
	gensec_ntlmssp_state->server_info = NULL;

	(*session_info)->session_key = data_blob_talloc(*session_info, 
							gensec_ntlmssp_state->ntlmssp_state->session_key.data,
							gensec_ntlmssp_state->ntlmssp_state->session_key.length);

	(*session_info)->workstation = talloc_strdup(*session_info, 
						     gensec_ntlmssp_state->ntlmssp_state->workstation);

	return NT_STATUS_OK;
}

static void gensec_ntlmssp_end(struct gensec_security *gensec_security)
{
	struct gensec_ntlmssp_state *gensec_ntlmssp_state = gensec_security->private_data;

	if (gensec_ntlmssp_state->ntlmssp_state) {
		ntlmssp_end(&gensec_ntlmssp_state->ntlmssp_state);
	}

	if (gensec_ntlmssp_state->auth_context) {
		free_auth_context(&gensec_ntlmssp_state->auth_context);
	}
	if (gensec_ntlmssp_state->server_info) {
		free_server_info(&gensec_ntlmssp_state->server_info);
	}
	talloc_free(gensec_ntlmssp_state);
	gensec_security->private_data = NULL;
}

static const struct gensec_security_ops gensec_ntlmssp_security_ops = {
	.name		= "ntlmssp",
	.sasl_name	= "NTLM",
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.oid            = OID_NTLMSSP,
	.client_start   = gensec_ntlmssp_client_start,
	.server_start   = gensec_ntlmssp_server_start,
	.update 	= gensec_ntlmssp_update,
	.seal_packet	= gensec_ntlmssp_seal_packet,
	.sig_size	= gensec_ntlmssp_sig_size,
	.sign_packet	= gensec_ntlmssp_sign_packet,
	.check_packet	= gensec_ntlmssp_check_packet,
	.unseal_packet	= gensec_ntlmssp_unseal_packet,
	.session_key	= gensec_ntlmssp_session_key,
	.session_info   = gensec_ntlmssp_session_info,
	.end		= gensec_ntlmssp_end
};


NTSTATUS gensec_ntlmssp_init(void)
{
	NTSTATUS ret;
	ret = register_backend("gensec", &gensec_ntlmssp_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_ntlmssp_security_ops.name));
		return ret;
	}

	/* ugly cludge, but we need the auth subsystem for this to work */
	auth_init();

	return ret;
}
