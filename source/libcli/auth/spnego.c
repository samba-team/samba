/* 
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation
   
   Copyright (C) Jim McDonough <jmcd@us.ibm.com>      2003
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

enum spnego_state_position {
	SPNEGO_SERVER_START,
	SPNEGO_CLIENT_START,
	SPNEGO_SERVER_TARG,
	SPNEGO_CLIENT_TARG,
	SPNEGO_FALLBACK,
	SPNEGO_DONE
};

struct spnego_state {
	TALLOC_CTX *mem_ctx;
	uint_t ref_count;
	enum spnego_message_type expected_packet;
	enum spnego_message_type state_position;
	enum spnego_negResult result;
	struct gensec_security *sub_sec_security;
};

static NTSTATUS gensec_spnego_client_start(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state;
	TALLOC_CTX *mem_ctx = talloc_init("gensec_spengo_client_start");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	spnego_state = talloc_p(mem_ctx, struct spnego_state);
		
	if (!spnego_state) {
		return NT_STATUS_NO_MEMORY;
	}

	spnego_state->expected_packet = SPNEGO_NEG_TOKEN_INIT;
	spnego_state->state_position = SPNEGO_CLIENT_START;
	spnego_state->result = SPNEGO_ACCEPT_INCOMPLETE;
	spnego_state->mem_ctx = mem_ctx;
	spnego_state->sub_sec_security = NULL;

	gensec_security->private_data = spnego_state;
	return NT_STATUS_OK;
}

/*
  wrappers for the spnego_*() functions
*/
static NTSTATUS gensec_spnego_unseal_packet(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_unseal_packet(spnego_state->sub_sec_security, 
				    mem_ctx, data, length, sig); 
}

static NTSTATUS gensec_spnego_check_packet(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const uint8_t *data, size_t length, 
				     const DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = gensec_security->private_data;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_check_packet(spnego_state->sub_sec_security, 
				mem_ctx, data, length, sig);
}

static NTSTATUS gensec_spnego_seal_packet(struct gensec_security *gensec_security, 
				    TALLOC_CTX *mem_ctx, 
				    uint8_t *data, size_t length, 
				    DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = gensec_security->private_data;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_seal_packet(spnego_state->sub_sec_security, 
				  mem_ctx, data, length, sig);
}

static NTSTATUS gensec_spnego_sign_packet(struct gensec_security *gensec_security, 
				    TALLOC_CTX *mem_ctx, 
				    const uint8_t *data, size_t length, 
				    DATA_BLOB *sig)
{
	struct spnego_state *spnego_state = gensec_security->private_data;

	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_sign_packet(spnego_state->sub_sec_security, 
				  mem_ctx, data, length, sig);
}

static NTSTATUS gensec_spnego_session_key(struct gensec_security *gensec_security, 
				    DATA_BLOB *session_key)
{
	struct spnego_state *spnego_state = gensec_security->private_data;
	if (spnego_state->state_position != SPNEGO_DONE 
	    && spnego_state->state_position != SPNEGO_FALLBACK) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	return gensec_session_key(spnego_state->sub_sec_security, 
				  session_key);
}

/** Fallback to another GENSEC mechanism, based on magic strings 
 *
 * This is the 'fallback' case, where we don't get SPENGO, and have to
 * try all the other options (and hope they all have a magic string
 * they check)
*/

static NTSTATUS gensec_spengo_server_try_fallback(struct gensec_security *gensec_security, 
						  struct spnego_state *spnego_state,
						  TALLOC_CTX *out_mem_ctx, 
						  const DATA_BLOB in, DATA_BLOB *out) 
{
	int i;
	int num_ops;
	const struct gensec_security_ops **all_ops = gensec_security_all(&num_ops);
	for (i=0; i < num_ops; i++) {
		NTSTATUS nt_status;
		if (!all_ops[i]->oid) {
			continue;
		}
		nt_status = gensec_subcontext_start(gensec_security, 
						    &spnego_state->sub_sec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
		/* select the sub context */
		nt_status = gensec_start_mech_by_oid(spnego_state->sub_sec_security,
						     all_ops[i]->oid);
		if (!NT_STATUS_IS_OK(nt_status)) {
			gensec_end(&spnego_state->sub_sec_security);
					continue;
		}
		nt_status = gensec_update(spnego_state->sub_sec_security,
							  out_mem_ctx, in, out);
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			spnego_state->state_position = SPNEGO_FALLBACK;
			return nt_status;
		}
		gensec_end(&spnego_state->sub_sec_security);
	}
	DEBUG(1, ("Failed to parse SPENGO request\n"));
	return NT_STATUS_INVALID_PARAMETER;
	
}

/** create a client netTokenInit 
 *
 * This is the case, where the client is the first one who sends data
*/

static NTSTATUS gensec_spengo_client_netTokenInit(struct gensec_security *gensec_security, 
						  struct spnego_state *spnego_state,
						  TALLOC_CTX *out_mem_ctx, 
						  const DATA_BLOB in, DATA_BLOB *out) 
{
	NTSTATUS nt_status;
	int i;
	int num_ops;
	char **mechTypes = NULL;
	const struct gensec_security_ops **all_ops = gensec_security_all(&num_ops);
	DATA_BLOB null_data_blob = data_blob(NULL,0);
	DATA_BLOB unwrapped_out = data_blob(NULL,0);

	if (num_ops < 1) {
		DEBUG(1, ("no GENSEC backends available\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* build a mechTypes list we want to offer */
	for (i=0; i < num_ops; i++) {
		if (!all_ops[i]->oid) {
			continue;
		}

		/* skip SPNEGO itself */
		if (strcmp(OID_SPNEGO,all_ops[i]->oid)==0) {
			continue;
		}

		mechTypes = talloc_realloc_p(out_mem_ctx, mechTypes, char *, i+2);
		if (!mechTypes) {
			DEBUG(1, ("talloc_realloc_p(out_mem_ctx, mechTypes, char *, i+1) failed\n"));
			return NT_STATUS_NO_MEMORY;
		}

		mechTypes[i] = all_ops[i]->oid;
		mechTypes[i+1] = NULL;
	}

	if (!mechTypes) {
		DEBUG(1, ("no GENSEC OID backends available\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	nt_status = gensec_subcontext_start(gensec_security, 
					    &spnego_state->sub_sec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	/* select our preferred mech */
	nt_status = gensec_start_mech_by_oid(spnego_state->sub_sec_security,
					     mechTypes[0]);
	if (!NT_STATUS_IS_OK(nt_status)) {
		gensec_end(&spnego_state->sub_sec_security);
			return nt_status;
	}
	nt_status = gensec_update(spnego_state->sub_sec_security,
						  out_mem_ctx, in, &unwrapped_out);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		struct spnego_data spnego_out;
		spnego_out.type = SPNEGO_NEG_TOKEN_INIT;
		spnego_out.negTokenInit.mechTypes = mechTypes;
		spnego_out.negTokenInit.reqFlags = 0;
		spnego_out.negTokenInit.mechListMIC = null_data_blob;
		spnego_out.negTokenInit.mechToken = unwrapped_out;
		
		if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
			DEBUG(1, ("Failed to write SPENGO reply to NEG_TOKEN_INIT\n"));
				return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* set next state */
		spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
		spnego_state->state_position = SPNEGO_CLIENT_TARG;
		return nt_status;
	}
	gensec_end(&spnego_state->sub_sec_security);

	DEBUG(1, ("Failed to setup SPENGO netTokenInit request\n"));
	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_spnego_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
			       const DATA_BLOB in, DATA_BLOB *out) 
{
	struct spnego_state *spnego_state = gensec_security->private_data;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);
	DATA_BLOB unwrapped_out;
	struct spnego_data spnego_out;
	struct spnego_data spnego;

	ssize_t len;

	if (!out_mem_ctx) {
		out_mem_ctx = spnego_state->mem_ctx;
	}

	/* and switch into the state machine */

	switch (spnego_state->state_position) {
	case SPNEGO_FALLBACK:
		return gensec_update(spnego_state->sub_sec_security,
				     out_mem_ctx, in, out);
	case SPNEGO_SERVER_START:
	{
		if (in.length) {
			len = spnego_read_data(in, &spnego);
			if (len == -1) {
				return gensec_spengo_server_try_fallback(gensec_security, spnego_state, out_mem_ctx, in, out);
			} else {
				/* client sent NegTargetInit */
			}
		} else {
			/* server needs to send NegTargetInit */
		}
	}

	case SPNEGO_CLIENT_START:
	{
		/* The server offers a list of mechanisms */
		
		char **mechType;
		char *my_mechs[] = {NULL, NULL};
		int i;
		NTSTATUS nt_status;

		if (!in.length) {
			/* client to produce negTokenInit */
			return gensec_spengo_client_netTokenInit(gensec_security, spnego_state, out_mem_ctx, in, out);
		}
		
		len = spnego_read_data(in, &spnego);
		
		if (len == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (spnego.type != spnego_state->expected_packet) {
			spnego_free_data(&spnego);
			DEBUG(1, ("Invalid SPENGO request: %d, expected %d\n", spnego.type, 
				  spnego_state->expected_packet));
			return NT_STATUS_INVALID_PARAMETER;
		}

		mechType = spnego.negTokenInit.mechTypes;
		for (i=0; mechType && mechType[i]; i++) {
			nt_status = gensec_client_start(&spnego_state->sub_sec_security);
			if (!NT_STATUS_IS_OK(nt_status)) {
				break;
			}
			/* select the sub context */
			nt_status = gensec_start_mech_by_oid(spnego_state->sub_sec_security,
							     mechType[i]);
			if (!NT_STATUS_IS_OK(nt_status)) {
				gensec_end(&spnego_state->sub_sec_security);
				continue;
			}
			
			if (i == 0) {
				nt_status = gensec_update(spnego_state->sub_sec_security,
							  out_mem_ctx, 
							  spnego.negTokenInit.mechToken, 
							  &unwrapped_out);
			} else {
				/* only get the helping start blob for the first OID */
				nt_status = gensec_update(spnego_state->sub_sec_security,
							  out_mem_ctx, 
							  null_data_blob, 
							  &unwrapped_out);
			}
			if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
				DEBUG(1, ("SPENGO(%s) NEG_TOKEN_INIT failed: %s\n", 
					  spnego_state->sub_sec_security->ops->name, nt_errstr(nt_status)));
				gensec_end(&spnego_state->sub_sec_security);
			} else {
				break;
			}
		}
		if (!mechType || !mechType[i]) {
			DEBUG(1, ("SPENGO: Could not find a suitable mechtype in NEG_TOKEN_INIT\n"));
		}
		
		spnego_free_data(&spnego);
		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			return nt_status;
		}
		
		/* compose reply */
		my_mechs[0] = spnego_state->sub_sec_security->ops->oid;
		
		spnego_out.type = SPNEGO_NEG_TOKEN_INIT;
		spnego_out.negTokenInit.mechTypes = my_mechs;
		spnego_out.negTokenInit.reqFlags = 0;
		spnego_out.negTokenInit.mechListMIC = null_data_blob;
		spnego_out.negTokenInit.mechToken = unwrapped_out;
		
		if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
			DEBUG(1, ("Failed to write SPENGO reply to NEG_TOKEN_INIT\n"));
				return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* set next state */
		spnego_state->expected_packet = SPNEGO_NEG_TOKEN_TARG;
		spnego_state->state_position = SPNEGO_CLIENT_TARG;
		
		return nt_status;
	}
	case SPNEGO_SERVER_TARG:
	{
		NTSTATUS nt_status;
		if (!in.length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		len = spnego_read_data(in, &spnego);
		
		if (len == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (spnego.type != spnego_state->expected_packet) {
			spnego_free_data(&spnego);
			DEBUG(1, ("Invalid SPENGO request: %d, expected %d\n", spnego.type, 
				  spnego_state->expected_packet));
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		if (spnego.negTokenTarg.responseToken.length) {
			nt_status = gensec_update(spnego_state->sub_sec_security,
						  out_mem_ctx, 
						  spnego.negTokenTarg.responseToken, 
						  &unwrapped_out);
		} else {
			unwrapped_out = data_blob(NULL, 0);
			nt_status = NT_STATUS_OK;
		}
		
		spnego_state->result = spnego.negTokenTarg.negResult;
		spnego_free_data(&spnego);
		
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			/* compose reply */
			spnego_out.type = SPNEGO_NEG_TOKEN_TARG;
			spnego_out.negTokenTarg.negResult = SPNEGO_ACCEPT_INCOMPLETE;
			spnego_out.negTokenTarg.supportedMech 
				= spnego_state->sub_sec_security->ops->oid;
			spnego_out.negTokenTarg.responseToken = unwrapped_out;
			spnego_out.negTokenTarg.mechListMIC = null_data_blob;
			
			if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
				DEBUG(1, ("Failed to write SPENGO reply to NEG_TOKEN_TARG\n"));
				return NT_STATUS_INVALID_PARAMETER;
			}
			spnego_state->state_position = SPNEGO_SERVER_TARG;
		} else if (NT_STATUS_IS_OK(nt_status)) {
			spnego_state->state_position = SPNEGO_DONE;
		} else {
			DEBUG(1, ("SPENGO(%s) login failed: %s\n", 
				  spnego_state->sub_sec_security->ops->name, 
				  nt_errstr(nt_status)));
			return nt_status;
		}
		
		return nt_status;
	}
	case SPNEGO_CLIENT_TARG:
	{
		NTSTATUS nt_status;
		if (!in.length) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		len = spnego_read_data(in, &spnego);
		
		if (len == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* OK, so it's real SPNEGO, check the packet's the one we expect */
		if (spnego.type != spnego_state->expected_packet) {
			spnego_free_data(&spnego);
			DEBUG(1, ("Invalid SPENGO request: %d, expected %d\n", spnego.type, 
				  spnego_state->expected_packet));
			return NT_STATUS_INVALID_PARAMETER;
		}
	
		if (spnego.negTokenTarg.negResult == SPNEGO_REJECT) {
			return NT_STATUS_ACCESS_DENIED;
		}
		
		if (spnego.negTokenTarg.responseToken.length) {
			nt_status = gensec_update(spnego_state->sub_sec_security,
						  out_mem_ctx, 
						  spnego.negTokenTarg.responseToken, 
						  &unwrapped_out);
		} else {
			unwrapped_out = data_blob(NULL, 0);
			nt_status = NT_STATUS_OK;
		}
		
		if (NT_STATUS_IS_OK(nt_status) 
		    && (spnego.negTokenTarg.negResult != SPNEGO_ACCEPT_COMPLETED)) {
			nt_status = NT_STATUS_INVALID_PARAMETER;
		}
		
		spnego_state->result = spnego.negTokenTarg.negResult;
		spnego_free_data(&spnego);
		
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			/* compose reply */
			spnego_out.type = SPNEGO_NEG_TOKEN_TARG;
			spnego_out.negTokenTarg.negResult = SPNEGO_NONE_RESULT;
			spnego_out.negTokenTarg.supportedMech = NULL;
			spnego_out.negTokenTarg.responseToken = unwrapped_out;
			spnego_out.negTokenTarg.mechListMIC = null_data_blob;
			
			if (spnego_write_data(out_mem_ctx, out, &spnego_out) == -1) {
				DEBUG(1, ("Failed to write SPENGO reply to NEG_TOKEN_TARG\n"));
				return NT_STATUS_INVALID_PARAMETER;
			}
			spnego_state->state_position = SPNEGO_CLIENT_TARG;
		} else if (NT_STATUS_IS_OK(nt_status)) {
			spnego_state->state_position = SPNEGO_DONE;
		} else {
			DEBUG(1, ("SPENGO(%s) login failed: %s\n", 
				  spnego_state->sub_sec_security->ops->name, 
				  nt_errstr(nt_status)));
			return nt_status;
		}
		
		return nt_status;
	}
	default:
		spnego_free_data(&spnego);
		DEBUG(1, ("Invalid SPENGO request: %d\n", spnego.type));
		return NT_STATUS_INVALID_PARAMETER;
	}
}

static void gensec_spnego_end(struct gensec_security *gensec_security)
{
	struct spnego_state *spnego_state = gensec_security->private_data;

	if (spnego_state->sub_sec_security) {
		gensec_end(&spnego_state->sub_sec_security);
	}

	talloc_destroy(spnego_state->mem_ctx);

	gensec_security->private_data = NULL;
}

static const struct gensec_security_ops gensec_spnego_security_ops = {
	.name		= "spnego",
	.sasl_name	= "GSS-SPNEGO",
	.auth_type	= DCERPC_AUTH_TYPE_SPNEGO,
	.oid            = OID_SPNEGO,
	.client_start   = gensec_spnego_client_start,
	.update 	= gensec_spnego_update,
	.seal_packet	= gensec_spnego_seal_packet,
	.sign_packet	= gensec_spnego_sign_packet,
	.check_packet	= gensec_spnego_check_packet,
	.unseal_packet	= gensec_spnego_unseal_packet,
	.session_key	= gensec_spnego_session_key,
	.end		= gensec_spnego_end
};

NTSTATUS gensec_spengo_init(void)
{
	NTSTATUS ret;
	ret = register_backend("gensec", &gensec_spnego_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_spnego_security_ops.name));
		return ret;
	}

	return ret;
}
