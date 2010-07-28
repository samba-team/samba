/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Almost completely rewritten by (C) Jeremy Allison 2005 - 2010
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

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 */

#include "includes.h"
#include "srv_pipe_internal.h"
#include "../librpc/gen_ndr/ndr_schannel.h"
#include "../libcli/auth/schannel.h"
#include "../libcli/auth/spnego.h"
#include "../libcli/auth/ntlmssp.h"
#include "ntlmssp_wrap.h"
#include "rpc_server.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/**
 * Dump everything from the start of the end up of the provided data
 * into a file, but only at debug level >= 50
 **/
static void dump_pdu_region(const char *name, int v,
			    DATA_BLOB *data, size_t start, size_t end)
{
	int fd, i;
	char *fname = NULL;
	ssize_t sz;

	if (DEBUGLEVEL < 50) return;

	if (start > data->length || end > data->length || start > end) return;

	for (i = 1; i < 100; i++) {
		if (v != -1) {
			fname = talloc_asprintf(talloc_tos(),
						"/tmp/%s_%d.%d.prs",
						name, v, i);
		} else {
			fname = talloc_asprintf(talloc_tos(),
						"/tmp/%s_%d.prs",
						name, i);
		}
		if (!fname) {
			return;
		}
		fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fd != -1 || errno != EEXIST) break;
	}
	if (fd != -1) {
		sz = write(fd, data->data + start, end - start);
		i = close(fd);
		if ((sz != end - start) || (i != 0) ) {
			DEBUG(0, ("Error writing/closing %s: %ld!=%ld %d\n",
				  fname, (unsigned long)sz,
				  (unsigned long)end - start, i));
		} else {
			DEBUG(0,("created %s\n", fname));
		}
	}
	TALLOC_FREE(fname);
}

static void free_pipe_ntlmssp_auth_data(struct pipe_auth_data *auth)
{
	TALLOC_FREE(auth->a_u.auth_ntlmssp_state);
}

static void free_pipe_schannel_auth_data(struct pipe_auth_data *auth)
{
	TALLOC_FREE(auth->a_u.schannel_auth);
}

static void free_pipe_auth_data(struct pipe_auth_data *auth)
{
	if (auth->auth_data_free_func) {
		(*auth->auth_data_free_func)(auth);
		auth->auth_data_free_func = NULL;
	}
}

static DATA_BLOB generic_session_key(void)
{
	return data_blob("SystemLibraryDTC", 16);
}

/*******************************************************************
 Handle NTLMSSP.
 ********************************************************************/

static bool add_ntlmssp_auth(struct pipes_struct *p)
{
	enum dcerpc_AuthLevel auth_level = p->auth.auth_level;
	DATA_BLOB auth_blob = data_blob_null;
	NTSTATUS status;

	/* FIXME: Is this right ?
	 * Keeping only to avoid changing semantics during refactoring
	 * --simo
	 */
	if (auth_level != DCERPC_AUTH_LEVEL_PRIVACY) {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}

	/* Generate the auth blob. */
	switch (auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		/* Data portion is encrypted. */
		status = auth_ntlmssp_seal_packet(
				p->auth.a_u.auth_ntlmssp_state,
				(TALLOC_CTX *)p->out_data.frag.data,
				&p->out_data.frag.data[DCERPC_RESPONSE_LENGTH],
				p->out_data.frag.length
					- DCERPC_RESPONSE_LENGTH
					- DCERPC_AUTH_TRAILER_LENGTH,
				p->out_data.frag.data,
				p->out_data.frag.length,
				&auth_blob);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		/* Data is signed. */
		status = auth_ntlmssp_sign_packet(
				p->auth.a_u.auth_ntlmssp_state,
				(TALLOC_CTX *)p->out_data.frag.data,
				&p->out_data.frag.data[DCERPC_RESPONSE_LENGTH],
				p->out_data.frag.length
					- DCERPC_RESPONSE_LENGTH
					- DCERPC_AUTH_TRAILER_LENGTH,
				p->out_data.frag.data,
				p->out_data.frag.length,
				&auth_blob);
		break;

	default:
		status = NT_STATUS_INTERNAL_ERROR;
		return false;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to add NTLMSSP auth blob: %s\n",
			nt_errstr(status)));
		data_blob_free(&p->out_data.frag);
		return false;
	}

	/* Finally append the auth blob. */
	if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
				auth_blob.data, auth_blob.length)) {
		DEBUG(0, ("Failed to add %u bytes auth blob.\n",
			  (unsigned int)auth_blob.length));
		data_blob_free(&p->out_data.frag);
		return False;
	}
	data_blob_free(&auth_blob);

	return true;
}

/*******************************************************************
 Append a schannel authenticated fragment.
 ********************************************************************/

static bool add_schannel_auth(struct pipes_struct *p)
{
	DATA_BLOB auth_blob = data_blob_null;
	NTSTATUS status;

	/* Schannel processing. */
	switch (p->auth.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = netsec_outgoing_packet(
				p->auth.a_u.schannel_auth,
				(TALLOC_CTX *)p->out_data.frag.data,
				true,
				&p->out_data.frag.data[DCERPC_RESPONSE_LENGTH],
				p->out_data.frag.length
					- DCERPC_RESPONSE_LENGTH
					- DCERPC_AUTH_TRAILER_LENGTH,
				&auth_blob);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = netsec_outgoing_packet(
				p->auth.a_u.schannel_auth,
				(TALLOC_CTX *)p->out_data.frag.data,
				false,
				&p->out_data.frag.data[DCERPC_RESPONSE_LENGTH],
				p->out_data.frag.length
					- DCERPC_RESPONSE_LENGTH
					- DCERPC_AUTH_TRAILER_LENGTH,
				&auth_blob);
		break;

	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to add SCHANNEL auth blob: %s\n",
			nt_errstr(status)));
		data_blob_free(&p->out_data.frag);
		return false;
	}

	if (DEBUGLEVEL >= 10) {
		dump_NL_AUTH_SIGNATURE(talloc_tos(), &auth_blob);
	}

	if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
				auth_blob.data, auth_blob.length)) {
		DEBUG(0, ("Failed to add %u bytes auth blob.\n",
			  (unsigned int)auth_blob.length));
		data_blob_free(&p->out_data.frag);
		return false;
	}
	data_blob_free(&auth_blob);

	return true;
}

/*******************************************************************
 Generate the next PDU to be returned from the data.
********************************************************************/

static bool create_next_packet(struct pipes_struct *p,
				enum dcerpc_AuthType auth_type,
				enum dcerpc_AuthLevel auth_level,
				size_t auth_length)
{
	union dcerpc_payload u;
	uint8_t pfc_flags;
	size_t data_len_left;
	size_t data_len;
	size_t max_len;
	size_t pad_len = 0;
	NTSTATUS status;

	ZERO_STRUCT(u.response);

	/* Set up rpc packet pfc flags. */
	if (p->out_data.data_sent_length == 0) {
		pfc_flags = DCERPC_PFC_FLAG_FIRST;
	} else {
		pfc_flags = 0;
	}

	/* Work out how much we can fit in a single PDU. */
	data_len_left = p->out_data.rdata.length -
				p->out_data.data_sent_length;

	/* Ensure there really is data left to send. */
	if (!data_len_left) {
		DEBUG(0, ("No data left to send !\n"));
		return false;
	}

	/* Max space available - not including padding. */
	if (auth_length) {
		max_len = RPC_MAX_PDU_FRAG_LEN
				- DCERPC_RESPONSE_LENGTH
				- DCERPC_AUTH_TRAILER_LENGTH
				- auth_length;
	} else {
		max_len = RPC_MAX_PDU_FRAG_LEN - DCERPC_RESPONSE_LENGTH;
	}

	/*
	 * The amount we send is the minimum of the max_len
	 * and the amount left to send.
	 */
	data_len = MIN(data_len_left, max_len);

	if (auth_length) {
		/* Work out any padding alignment requirements. */
		pad_len = (DCERPC_RESPONSE_LENGTH + data_len) %
						SERVER_NDR_PADDING_SIZE;
		if (pad_len) {
			pad_len = SERVER_NDR_PADDING_SIZE - pad_len;
			DEBUG(10, ("Padding size is: %d\n", (int)pad_len));
			/* If we're over filling the packet, we need to make
			 * space for the padding at the end of the data. */
			if (data_len + pad_len > max_len) {
				data_len -= SERVER_NDR_PADDING_SIZE;
			}
		}
	}

	/* Set up the alloc hint. This should be the data left to send. */
	u.response.alloc_hint = data_len_left;

	/* Work out if this PDU will be the last. */
	if (p->out_data.data_sent_length
				+ data_len >= p->out_data.rdata.length) {
		pfc_flags |= DCERPC_PFC_FLAG_LAST;
	}

	/* Prepare data to be NDR encoded. */
	u.response.stub_and_verifier =
		data_blob_const(p->out_data.rdata.data +
				p->out_data.data_sent_length, data_len);

	/* Store the packet in the data stream. */
	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_RESPONSE,
					  pfc_flags,
					  auth_length,
					  p->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall RPC Packet.\n"));
		return false;
	}

	if (auth_length) {
		DATA_BLOB empty = data_blob_null;
		DATA_BLOB auth_hdr;

		/* Set the proper length on the pdu, including padding.
		 * Only needed if an auth trailer will be appended. */
		dcerpc_set_frag_length(&p->out_data.frag,
					p->out_data.frag.length
						+ pad_len
						+ DCERPC_AUTH_TRAILER_LENGTH
						+ auth_length);

		if (pad_len) {
			size_t offset = p->out_data.frag.length;

			if (!data_blob_realloc(p->mem_ctx,
						&p->out_data.frag,
						offset + pad_len)) {
				DEBUG(0, ("Failed to add padding!\n"));
				data_blob_free(&p->out_data.frag);
				return false;
			}
			memset(&p->out_data.frag.data[offset], '\0', pad_len);
		}

		/* auth blob is intentionally empty,
		 * it will be appended later */
		status = dcerpc_push_dcerpc_auth(p->out_data.frag.data,
						 auth_type,
						 auth_level,
						 pad_len,
						 1, /* context id. */
						 &empty,
						 &auth_hdr);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to marshall RPC Auth.\n"));
			return false;
		}

		/* Store auth header in the data stream. */
		if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
					auth_hdr.data, auth_hdr.length)) {
			DEBUG(0, ("Out of memory.\n"));
			data_blob_free(&p->out_data.frag);
			return false;
		}
		data_blob_free(&auth_hdr);
	}

	/* Setup the counts for this PDU. */
	p->out_data.data_sent_length += data_len;
	p->out_data.current_pdu_sent = 0;
	return true;
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
********************************************************************/

bool create_next_pdu(struct pipes_struct *p)
{
	enum dcerpc_AuthType auth_type =
		map_pipe_auth_type_to_rpc_auth_type(p->auth.auth_type);

	/*
	 * If we're in the fault state, keep returning fault PDU's until
	 * the pipe gets closed. JRA.
	 */
	if (p->fault_state) {
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return true;
	}

	switch (p->auth.auth_level) {
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_CONNECT:
		/* This is incorrect for auth level connect. Fixme. JRA */

		/* No authentication done. */
		return create_next_packet(p, auth_type,
					  p->auth.auth_level, 0);

	case DCERPC_AUTH_LEVEL_CALL:
	case DCERPC_AUTH_LEVEL_PACKET:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:

		switch(p->auth.auth_type) {
		case PIPE_AUTH_TYPE_NTLMSSP:
		case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
			if (!create_next_packet(p, auth_type,
						p->auth.auth_level,
						NTLMSSP_SIG_SIZE)) {
				return false;
			}
			return add_ntlmssp_auth(p);

		case PIPE_AUTH_TYPE_SCHANNEL:
			if (!create_next_packet(p, auth_type,
						p->auth.auth_level,
						NL_AUTH_SIGNATURE_SIZE)) {
				return false;
			}
			return add_schannel_auth(p);
		default:
			break;
		}
	default:
		break;
	}

	DEBUG(0, ("Invalid internal auth level %u / type %u\n",
		  (unsigned int)p->auth.auth_level,
		  (unsigned int)p->auth.auth_type));
	return false;
}

/*******************************************************************
 Process an NTLMSSP authentication response.
 If this function succeeds, the user has been authenticated
 and their domain, name and calling workstation stored in
 the pipe struct.
*******************************************************************/

static bool pipe_ntlmssp_verify_final(struct pipes_struct *p,
				      DATA_BLOB *p_resp_blob)
{
	DATA_BLOB session_key, reply;
	NTSTATUS status;
	struct auth_ntlmssp_state *a = p->auth.a_u.auth_ntlmssp_state;
	bool ret;

	DEBUG(5,("pipe_ntlmssp_verify_final: pipe %s checking user details\n",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));

	ZERO_STRUCT(reply);

	/* this has to be done as root in order to verify the password */
	become_root();
	status = auth_ntlmssp_update(a, *p_resp_blob, &reply);
	unbecome_root();

	/* Don't generate a reply. */
	data_blob_free(&reply);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* Finally - if the pipe negotiated integrity (sign) or privacy (seal)
	   ensure the underlying NTLMSSP flags are also set. If not we should
	   refuse the bind. */

	if (p->auth.auth_level == DCERPC_AUTH_LEVEL_INTEGRITY) {
		if (!auth_ntlmssp_negotiated_sign(a)) {
			DEBUG(0,("pipe_ntlmssp_verify_final: pipe %s : packet integrity requested "
				"but client declined signing.\n",
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			return False;
		}
	}
	if (p->auth.auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		if (!auth_ntlmssp_negotiated_seal(a)) {
			DEBUG(0,("pipe_ntlmssp_verify_final: pipe %s : packet privacy requested "
				"but client declined sealing.\n",
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			return False;
		}
	}

	DEBUG(5, ("pipe_ntlmssp_verify_final: OK: user: %s domain: %s "
		  "workstation: %s\n",
		  auth_ntlmssp_get_username(a),
		  auth_ntlmssp_get_domain(a),
		  auth_ntlmssp_get_client(a)));

	TALLOC_FREE(p->server_info);

	status = auth_ntlmssp_steal_server_info(p, a, &p->server_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("auth_ntlmssp_server_info failed to obtain the server info for authenticated user: %s\n",
			  nt_errstr(status)));
		return false;
	}

	if (p->server_info->ptok == NULL) {
		DEBUG(1,("Error: Authmodule failed to provide nt_user_token\n"));
		return False;
	}

	/*
	 * We're an authenticated bind over smb, so the session key needs to
	 * be set to "SystemLibraryDTC". Weird, but this is what Windows
	 * does. See the RPC-SAMBA3SESSIONKEY.
	 */

	session_key = generic_session_key();
	if (session_key.data == NULL) {
		return False;
	}

	ret = server_info_set_session_key(p->server_info, session_key);

	data_blob_free(&session_key);

	return True;
}

/*******************************************************************
 This is the "stage3" NTLMSSP response after a bind request and reply.
*******************************************************************/

bool api_pipe_bind_auth3(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info;
	NTSTATUS status;

	DEBUG(5, ("api_pipe_bind_auth3: decode request. %d\n", __LINE__));

	if (pkt->auth_length == 0) {
		DEBUG(0, ("No auth field sent for bind request!\n"));
		goto err;
	}

	/* Ensure there's enough data for an authenticated request. */
	if (pkt->frag_length < RPC_HEADER_LEN
				+ DCERPC_AUTH_TRAILER_LENGTH
				+ pkt->auth_length) {
			DEBUG(0,("api_pipe_ntlmssp_auth_process: auth_len "
				"%u is too large.\n",
                        (unsigned int)pkt->auth_length));
		goto err;
	}

	/*
	 * Decode the authentication verifier response.
	 */

	status = dcerpc_pull_dcerpc_auth(pkt,
					 &pkt->u.auth3.auth_info,
					 &auth_info, p->endian);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to unmarshall dcerpc_auth.\n"));
		goto err;
	}

	/* We must NEVER look at auth_info->auth_pad_len here,
	 * as old Samba client code gets it wrong and sends it
	 * as zero. JRA.
 	 */

	if (auth_info.auth_type != DCERPC_AUTH_TYPE_NTLMSSP) {
		DEBUG(0,("api_pipe_bind_auth3: incorrect auth type (%u).\n",
			(unsigned int)auth_info.auth_type ));
		return False;
	}

	/*
	 * The following call actually checks the challenge/response data.
	 * for correctness against the given DOMAIN\user name.
	 */

	if (!pipe_ntlmssp_verify_final(p, &auth_info.credentials)) {
		goto err;
	}

	p->pipe_bound = True;

	return True;

 err:

	free_pipe_auth_data(&p->auth);

	return False;
}

static bool pipe_init_outgoing_data(struct pipes_struct *p);

/*******************************************************************
 Marshall a bind_nak pdu.
*******************************************************************/

static bool setup_bind_nak(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	NTSTATUS status;
	union dcerpc_payload u;

	/* Free any memory in the current return data buffer. */
	pipe_init_outgoing_data(p);

	/*
	 * Initialize a bind_nak header.
	 */

	ZERO_STRUCT(u);

	u.bind_nak.reject_reason  = 0;

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_BIND_NAK,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  0,
					  pkt->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	free_pipe_auth_data(&p->auth);
	p->auth.auth_level = DCERPC_AUTH_LEVEL_NONE;
	p->auth.auth_type = PIPE_AUTH_TYPE_NONE;
	p->pipe_bound = False;

	return True;
}

/*******************************************************************
 Marshall a fault pdu.
*******************************************************************/

bool setup_fault_pdu(struct pipes_struct *p, NTSTATUS fault_status)
{
	NTSTATUS status;
	union dcerpc_payload u;

	/* Free any memory in the current return data buffer. */
	pipe_init_outgoing_data(p);

	/*
	 * Initialize a fault header.
	 */

	ZERO_STRUCT(u);

	u.fault.status		= NT_STATUS_V(fault_status);
	u.fault._pad		= data_blob_talloc_zero(p->mem_ctx, 4);

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_FAULT,
					  DCERPC_PFC_FLAG_FIRST |
					   DCERPC_PFC_FLAG_LAST |
					   DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
					  0,
					  p->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	return True;
}

/*******************************************************************
 Ensure a bind request has the correct abstract & transfer interface.
 Used to reject unknown binds from Win2k.
*******************************************************************/

static bool check_bind_req(struct pipes_struct *p,
			   struct ndr_syntax_id* abstract,
			   struct ndr_syntax_id* transfer,
			   uint32 context_id)
{
	struct pipe_rpc_fns *context_fns;

	DEBUG(3,("check_bind_req for %s\n",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));

	/* we have to check all now since win2k introduced a new UUID on the lsaprpc pipe */
	if (rpc_srv_pipe_exists_by_id(abstract) &&
	   ndr_syntax_id_equal(transfer, &ndr_transfer_syntax)) {
		DEBUG(3, ("check_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
			rpc_srv_get_pipe_cli_name(abstract),
			rpc_srv_get_pipe_srv_name(abstract)));
	} else {
		return false;
	}

	context_fns = SMB_MALLOC_P(struct pipe_rpc_fns);
	if (context_fns == NULL) {
		DEBUG(0,("check_bind_req: malloc() failed!\n"));
		return False;
	}

	context_fns->n_cmds = rpc_srv_get_pipe_num_cmds(abstract);
	context_fns->cmds = rpc_srv_get_pipe_cmds(abstract);
	context_fns->context_id = context_id;

	/* add to the list of open contexts */

	DLIST_ADD( p->contexts, context_fns );

	return True;
}

/**
 * Is a named pipe known?
 * @param[in] cli_filename	The pipe name requested by the client
 * @result			Do we want to serve this?
 */
bool is_known_pipename(const char *cli_filename, struct ndr_syntax_id *syntax)
{
	const char *pipename = cli_filename;
	NTSTATUS status;

	if (strnequal(pipename, "\\PIPE\\", 6)) {
		pipename += 5;
	}

	if (*pipename == '\\') {
		pipename += 1;
	}

	if (lp_disable_spoolss() && strequal(pipename, "spoolss")) {
		DEBUG(10, ("refusing spoolss access\n"));
		return false;
	}

	if (rpc_srv_get_pipe_interface_by_cli_name(pipename, syntax)) {
		return true;
	}

	status = smb_probe_module("rpc", pipename);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("is_known_pipename: %s unknown\n", cli_filename));
		return false;
	}
	DEBUG(10, ("is_known_pipename: %s loaded dynamically\n", pipename));

	/*
	 * Scan the list again for the interface id
	 */
	if (rpc_srv_get_pipe_interface_by_cli_name(pipename, syntax)) {
		return true;
	}

	DEBUG(10, ("is_known_pipename: pipe %s did not register itself!\n",
		   pipename));

	return false;
}

/*******************************************************************
 Handle a SPNEGO krb5 bind auth.
*******************************************************************/

static bool pipe_spnego_auth_bind_kerberos(struct pipes_struct *p,
					   TALLOC_CTX *mem_ctx,
					   struct dcerpc_auth *pauth_info,
					   DATA_BLOB *psecblob,
					   DATA_BLOB *response)
{
	return False;
}

/*******************************************************************
 Handle the first part of a SPNEGO bind auth.
*******************************************************************/

static bool pipe_spnego_auth_bind_negotiate(struct pipes_struct *p,
					    TALLOC_CTX *mem_ctx,
					    struct dcerpc_auth *pauth_info,
					    DATA_BLOB *response)
{
	DATA_BLOB secblob;
	DATA_BLOB chal;
	char *OIDs[ASN1_MAX_OIDS];
        int i;
	NTSTATUS status;
        bool got_kerberos_mechanism = false;
	struct auth_ntlmssp_state *a = NULL;

	ZERO_STRUCT(secblob);
	ZERO_STRUCT(chal);

	if (pauth_info->credentials.data[0] != ASN1_APPLICATION(0)) {
		goto err;
	}

	/* parse out the OIDs and the first sec blob */
	if (!spnego_parse_negTokenInit(talloc_tos(),
			pauth_info->credentials, OIDs, NULL, &secblob)) {
		DEBUG(0,("pipe_spnego_auth_bind_negotiate: Failed to parse the security blob.\n"));
		goto err;
        }

	if (strcmp(OID_KERBEROS5, OIDs[0]) == 0 || strcmp(OID_KERBEROS5_OLD, OIDs[0]) == 0) {
		got_kerberos_mechanism = true;
	}

	for (i=0;OIDs[i];i++) {
		DEBUG(3,("pipe_spnego_auth_bind_negotiate: Got OID %s\n", OIDs[i]));
		TALLOC_FREE(OIDs[i]);
	}
	DEBUG(3,("pipe_spnego_auth_bind_negotiate: Got secblob of size %lu\n", (unsigned long)secblob.length));

	if ( got_kerberos_mechanism && ((lp_security()==SEC_ADS) || USE_KERBEROS_KEYTAB) ) {
		bool ret;
		ret = pipe_spnego_auth_bind_kerberos(p, mem_ctx, pauth_info,
						     &secblob, response);
		data_blob_free(&secblob);
		return ret;
	}

	if (p->auth.auth_type == PIPE_AUTH_TYPE_SPNEGO_NTLMSSP && p->auth.a_u.auth_ntlmssp_state) {
		/* Free any previous auth type. */
		free_pipe_auth_data(&p->auth);
	}

	if (!got_kerberos_mechanism) {
		/* Initialize the NTLM engine. */
		status = auth_ntlmssp_start(&a);
		if (!NT_STATUS_IS_OK(status)) {
			goto err;
		}

		switch (pauth_info->auth_level) {
			case DCERPC_AUTH_LEVEL_INTEGRITY:
				auth_ntlmssp_want_sign(a);
				break;
			case DCERPC_AUTH_LEVEL_PRIVACY:
				auth_ntlmssp_want_seal(a);
				break;
			default:
				break;
		}
		/*
		 * Pass the first security blob of data to it.
		 * This can return an error or NT_STATUS_MORE_PROCESSING_REQUIRED
		 * which means we need another packet to complete the bind.
		 */

		status = auth_ntlmssp_update(a, secblob, &chal);

		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			DEBUG(3,("pipe_spnego_auth_bind_negotiate: auth_ntlmssp_update failed.\n"));
			goto err;
		}

		/* Generate the response blob we need for step 2 of the bind. */
		*response = spnego_gen_auth_response(mem_ctx, &chal, status, OID_NTLMSSP);
	} else {
		/*
		 * SPNEGO negotiate down to NTLMSSP. The subsequent
		 * code to process follow-up packets is not complete
		 * yet. JRA.
		 */
		*response = spnego_gen_auth_response(mem_ctx, NULL,
					NT_STATUS_MORE_PROCESSING_REQUIRED,
					OID_NTLMSSP);
	}

	/* auth_pad_len will be handled by the caller */

	p->auth.a_u.auth_ntlmssp_state = a;
	p->auth.auth_data_free_func = &free_pipe_ntlmssp_auth_data;
	p->auth.auth_type = PIPE_AUTH_TYPE_SPNEGO_NTLMSSP;

	data_blob_free(&secblob);
	data_blob_free(&chal);

	/* We can't set pipe_bound True yet - we need an RPC_ALTER_CONTEXT response packet... */
	return True;

 err:

	data_blob_free(&secblob);
	data_blob_free(&chal);

	p->auth.a_u.auth_ntlmssp_state = NULL;

	return False;
}

/*******************************************************************
 Handle the second part of a SPNEGO bind auth.
*******************************************************************/

static bool pipe_spnego_auth_bind_continue(struct pipes_struct *p,
					   TALLOC_CTX *mem_ctx,
					   struct dcerpc_auth *pauth_info,
					   DATA_BLOB *response)
{
	DATA_BLOB auth_blob;
	DATA_BLOB auth_reply;
	struct auth_ntlmssp_state *a = p->auth.a_u.auth_ntlmssp_state;

	ZERO_STRUCT(auth_blob);
	ZERO_STRUCT(auth_reply);

	/*
	 * NB. If we've negotiated down from krb5 to NTLMSSP we'll currently
	 * fail here as 'a' == NULL.
	 */
	if (p->auth.auth_type != PIPE_AUTH_TYPE_SPNEGO_NTLMSSP || !a) {
		DEBUG(0,("pipe_spnego_auth_bind_continue: not in NTLMSSP auth state.\n"));
		goto err;
	}

	if (pauth_info->credentials.data[0] != ASN1_CONTEXT(1)) {
		DEBUG(0,("pipe_spnego_auth_bind_continue: invalid SPNEGO blob type.\n"));
		goto err;
	}

	if (!spnego_parse_auth(talloc_tos(), pauth_info->credentials, &auth_blob)) {
		DEBUG(0,("pipe_spnego_auth_bind_continue: invalid SPNEGO blob.\n"));
		goto err;
	}

	/*
	 * The following call actually checks the challenge/response data.
	 * for correctness against the given DOMAIN\user name.
	 */

	if (!pipe_ntlmssp_verify_final(p, &auth_blob)) {
		goto err;
	}

	data_blob_free(&auth_blob);

	/* Generate the spnego "accept completed" blob - no incoming data. */
	*response = spnego_gen_auth_response(mem_ctx, &auth_reply, NT_STATUS_OK, OID_NTLMSSP);

	data_blob_free(&auth_reply);

	p->pipe_bound = True;

	return True;

 err:

	data_blob_free(&auth_blob);
	data_blob_free(&auth_reply);

	free_pipe_auth_data(&p->auth);

	return False;
}

/*******************************************************************
 Handle an schannel bind auth.
*******************************************************************/

static bool pipe_schannel_auth_bind(struct pipes_struct *p,
				    TALLOC_CTX *mem_ctx,
				    struct dcerpc_auth *auth_info,
				    DATA_BLOB *response)
{
	struct NL_AUTH_MESSAGE neg;
	struct NL_AUTH_MESSAGE reply;
	bool ret;
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds;
	DATA_BLOB session_key;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
			&auth_info->credentials, mem_ctx, &neg,
			(ndr_pull_flags_fn_t)ndr_pull_NL_AUTH_MESSAGE);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,("pipe_schannel_auth_bind: Could not unmarshal SCHANNEL auth neg\n"));
		return false;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(NL_AUTH_MESSAGE, &neg);
	}

	if (!(neg.Flags & NL_FLAG_OEM_NETBIOS_COMPUTER_NAME)) {
		DEBUG(0,("pipe_schannel_auth_bind: Did not receive netbios computer name\n"));
		return false;
	}

	/*
	 * The neg.oem_netbios_computer.a key here must match the remote computer name
	 * given in the DOM_CLNT_SRV.uni_comp_name used on all netlogon pipe
	 * operations that use credentials.
	 */

	become_root();
	status = schannel_get_creds_state(p, lp_private_dir(),
					    neg.oem_netbios_computer.a, &creds);
	unbecome_root();

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("pipe_schannel_auth_bind: Attempt to bind using schannel without successful serverauth2\n"));
		return False;
	}

	p->auth.a_u.schannel_auth = talloc(p, struct schannel_state);
	if (!p->auth.a_u.schannel_auth) {
		TALLOC_FREE(creds);
		return False;
	}

	p->auth.a_u.schannel_auth->state = SCHANNEL_STATE_START;
	p->auth.a_u.schannel_auth->seq_num = 0;
	p->auth.a_u.schannel_auth->initiator = false;
	p->auth.a_u.schannel_auth->creds = creds;

	/*
	 * JRA. Should we also copy the schannel session key into the pipe session key p->session_key
	 * here ? We do that for NTLMSSP, but the session key is already set up from the vuser
	 * struct of the person who opened the pipe. I need to test this further. JRA.
	 *
	 * VL. As we are mapping this to guest set the generic key
	 * "SystemLibraryDTC" key here. It's a bit difficult to test against
	 * W2k3, as it does not allow schannel binds against SAMR and LSA
	 * anymore.
	 */

	session_key = generic_session_key();
	if (session_key.data == NULL) {
		DEBUG(0, ("pipe_schannel_auth_bind: Could not alloc session"
			  " key\n"));
		return false;
	}

	ret = server_info_set_session_key(p->server_info, session_key);

	data_blob_free(&session_key);

	if (!ret) {
		DEBUG(0, ("server_info_set_session_key failed\n"));
		return false;
	}

	/*** SCHANNEL verifier ***/

	reply.MessageType			= NL_NEGOTIATE_RESPONSE;
	reply.Flags				= 0;
	reply.Buffer.dummy			= 5; /* ??? actually I don't think
						      * this has any meaning
						      * here - gd */

	ndr_err = ndr_push_struct_blob(response, mem_ctx, &reply,
		       (ndr_push_flags_fn_t)ndr_push_NL_AUTH_MESSAGE);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,("Failed to marshall NL_AUTH_MESSAGE.\n"));
		return false;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(NL_AUTH_MESSAGE, &reply);
	}

	DEBUG(10,("pipe_schannel_auth_bind: schannel auth: domain [%s] myname [%s]\n",
		neg.oem_netbios_domain.a, neg.oem_netbios_computer.a));

	/* We're finished with this bind - no more packets. */
	p->auth.auth_data_free_func = &free_pipe_schannel_auth_data;
	p->auth.auth_type = PIPE_AUTH_TYPE_SCHANNEL;

	p->pipe_bound = True;

	return True;
}

/*******************************************************************
 Handle an NTLMSSP bind auth.
*******************************************************************/

static bool pipe_ntlmssp_auth_bind(struct pipes_struct *p,
				   TALLOC_CTX *mem_ctx,
				   struct dcerpc_auth *auth_info,
				   DATA_BLOB *response)
{
        NTSTATUS status;
	struct auth_ntlmssp_state *a = NULL;

	if (strncmp((char *)auth_info->credentials.data, "NTLMSSP", 7) != 0) {
		DEBUG(0, ("Failed to read NTLMSSP in blob\n"));
                goto err;
        }

	/* We have an NTLMSSP blob. */
	status = auth_ntlmssp_start(&a);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("pipe_ntlmssp_auth_bind: auth_ntlmssp_start failed: %s\n",
			nt_errstr(status) ));
		goto err;
	}

	switch (auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		auth_ntlmssp_want_sign(a);
		break;
	case DCERPC_AUTH_LEVEL_PRIVACY:
		auth_ntlmssp_want_seal(a);
		break;
	default:
		break;
	}

	status = auth_ntlmssp_update(a, auth_info->credentials, response);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(0,("pipe_ntlmssp_auth_bind: auth_ntlmssp_update failed: %s\n",
			nt_errstr(status) ));
		goto err;
	}

	/* Make sure data is bound to the memctx, to be freed the caller */
	talloc_steal(mem_ctx, response->data);

	p->auth.a_u.auth_ntlmssp_state = a;
	p->auth.auth_data_free_func = &free_pipe_ntlmssp_auth_data;
	p->auth.auth_type = PIPE_AUTH_TYPE_NTLMSSP;

	DEBUG(10,("pipe_ntlmssp_auth_bind: NTLMSSP auth started\n"));

	/* We can't set pipe_bound True yet - we need an DCERPC_PKT_AUTH3 response packet... */
	return True;

  err:

	TALLOC_FREE(a);
	return False;
}

/*******************************************************************
 Respond to a pipe bind request.
*******************************************************************/

bool api_pipe_bind_req(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info;
	uint16 assoc_gid;
	unsigned int auth_type = DCERPC_AUTH_TYPE_NONE;
	NTSTATUS status;
	struct ndr_syntax_id id;
	union dcerpc_payload u;
	struct dcerpc_ack_ctx bind_ack_ctx;
	DATA_BLOB auth_resp = data_blob_null;
	DATA_BLOB auth_blob = data_blob_null;

	/* No rebinds on a bound pipe - use alter context. */
	if (p->pipe_bound) {
		DEBUG(2,("api_pipe_bind_req: rejecting bind request on bound "
			 "pipe %s.\n",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));
		return setup_bind_nak(p, pkt);
	}

	if (pkt->u.bind.num_contexts == 0) {
		DEBUG(0, ("api_pipe_bind_req: no rpc contexts around\n"));
		goto err_exit;
	}

	/*
	 * Try and find the correct pipe name to ensure
	 * that this is a pipe name we support.
	 */
	id = pkt->u.bind.ctx_list[0].abstract_syntax;
	if (rpc_srv_pipe_exists_by_id(&id)) {
		DEBUG(3, ("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
			rpc_srv_get_pipe_cli_name(&id),
			rpc_srv_get_pipe_srv_name(&id)));
	} else {
		status = smb_probe_module(
			"rpc", get_pipe_name_from_syntax(
				talloc_tos(),
				&pkt->u.bind.ctx_list[0].abstract_syntax));

		if (NT_STATUS_IS_ERR(status)) {
                       DEBUG(3,("api_pipe_bind_req: Unknown pipe name %s in bind request.\n",
                                get_pipe_name_from_syntax(
					talloc_tos(),
					&pkt->u.bind.ctx_list[0].abstract_syntax)));

			return setup_bind_nak(p, pkt);
		}

		if (rpc_srv_get_pipe_interface_by_cli_name(
				get_pipe_name_from_syntax(talloc_tos(),
							  &p->syntax),
				&id)) {
			DEBUG(3, ("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
				rpc_srv_get_pipe_cli_name(&id),
				rpc_srv_get_pipe_srv_name(&id)));
		} else {
			DEBUG(0, ("module %s doesn't provide functions for "
				  "pipe %s!\n",
				  get_pipe_name_from_syntax(talloc_tos(),
							    &p->syntax),
				  get_pipe_name_from_syntax(talloc_tos(),
							    &p->syntax)));
			return setup_bind_nak(p, pkt);
		}
	}

	DEBUG(5,("api_pipe_bind_req: make response. %d\n", __LINE__));

	if (pkt->u.bind.assoc_group_id != 0) {
		assoc_gid = pkt->u.bind.assoc_group_id;
	} else {
		assoc_gid = 0x53f0;
	}

	/*
	 * Create the bind response struct.
	 */

	/* If the requested abstract synt uuid doesn't match our client pipe,
		reject the bind_ack & set the transfer interface synt to all 0's,
		ver 0 (observed when NT5 attempts to bind to abstract interfaces
		unknown to NT4)
		Needed when adding entries to a DACL from NT5 - SK */

	if (check_bind_req(p,
			&pkt->u.bind.ctx_list[0].abstract_syntax,
			&pkt->u.bind.ctx_list[0].transfer_syntaxes[0],
			pkt->u.bind.ctx_list[0].context_id)) {

		bind_ack_ctx.result = 0;
		bind_ack_ctx.reason = 0;
		bind_ack_ctx.syntax = pkt->u.bind.ctx_list[0].transfer_syntaxes[0];
	} else {
		p->pipe_bound = False;
		/* Rejection reason: abstract syntax not supported */
		bind_ack_ctx.result = DCERPC_BIND_PROVIDER_REJECT;
		bind_ack_ctx.reason = DCERPC_BIND_REASON_ASYNTAX;
		bind_ack_ctx.syntax = null_ndr_syntax_id;
	}

	/*
	 * Check if this is an authenticated bind request.
	 */
	if (pkt->auth_length) {
		/* Quick length check. Won't catch a bad auth footer,
		 * prevents overrun. */

		if (pkt->frag_length < RPC_HEADER_LEN +
					DCERPC_AUTH_TRAILER_LENGTH +
					pkt->auth_length) {
			DEBUG(0,("api_pipe_bind_req: auth_len (%u) "
				"too long for fragment %u.\n",
				(unsigned int)pkt->auth_length,
				(unsigned int)pkt->frag_length));
			goto err_exit;
		}

		/*
		 * Decode the authentication verifier.
		 */
		status = dcerpc_pull_dcerpc_auth(pkt,
						 &pkt->u.bind.auth_info,
						 &auth_info, p->endian);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to unmarshall dcerpc_auth.\n"));
			goto err_exit;
		}

		auth_type = auth_info.auth_type;

		/* Work out if we have to sign or seal etc. */
		switch (auth_info.auth_level) {
		case DCERPC_AUTH_LEVEL_INTEGRITY:
			p->auth.auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
			break;
		case DCERPC_AUTH_LEVEL_PRIVACY:
			p->auth.auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
			break;
		default:
			DEBUG(0, ("Unexpected auth level (%u).\n",
				(unsigned int)auth_info.auth_level ));
			goto err_exit;
		}

		switch (auth_type) {
		case DCERPC_AUTH_TYPE_NTLMSSP:
			if (!pipe_ntlmssp_auth_bind(p, pkt,
						&auth_info, &auth_resp)) {
				goto err_exit;
			}
			assoc_gid = 0x7a77;
			break;

		case DCERPC_AUTH_TYPE_SCHANNEL:
			if (!pipe_schannel_auth_bind(p, pkt,
						&auth_info, &auth_resp)) {
				goto err_exit;
			}
			break;

		case DCERPC_AUTH_TYPE_SPNEGO:
			if (!pipe_spnego_auth_bind_negotiate(p, pkt,
						&auth_info, &auth_resp)) {
				goto err_exit;
			}
			break;

		case DCERPC_AUTH_TYPE_NONE:
			break;

		default:
			DEBUG(0, ("Unknown auth type %x requested.\n", auth_type));
			goto err_exit;
		}
	}

	if (auth_type == DCERPC_AUTH_TYPE_NONE) {
		/* Unauthenticated bind request. */
		/* We're finished - no more packets. */
		p->auth.auth_type = PIPE_AUTH_TYPE_NONE;
		/* We must set the pipe auth_level here also. */
		p->auth.auth_level = DCERPC_AUTH_LEVEL_NONE;
		p->pipe_bound = True;
		/* The session key was initialized from the SMB
		 * session in make_internal_rpc_pipe_p */
	}

	ZERO_STRUCT(u.bind_ack);
	u.bind_ack.max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;
	u.bind_ack.max_recv_frag = RPC_MAX_PDU_FRAG_LEN;
	u.bind_ack.assoc_group_id = assoc_gid;

	/* name has to be \PIPE\xxxxx */
	u.bind_ack.secondary_address =
			talloc_asprintf(pkt, "\\PIPE\\%s",
					rpc_srv_get_pipe_srv_name(&id));
	if (!u.bind_ack.secondary_address) {
		DEBUG(0, ("Out of memory!\n"));
		goto err_exit;
	}
	u.bind_ack.secondary_address_size =
				strlen(u.bind_ack.secondary_address) + 1;

	u.bind_ack.num_results = 1;
	u.bind_ack.ctx_list = &bind_ack_ctx;

	/* NOTE: We leave the auth_info empty so we can calculate the padding
	 * later and then append the auth_info --simo */

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_BIND_ACK,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  auth_resp.length,
					  pkt->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall bind_ack packet. (%s)\n",
			  nt_errstr(status)));
	}

	if (auth_resp.length) {

		status = dcerpc_push_dcerpc_auth(pkt,
						 auth_type,
						 auth_info.auth_level,
						 0,
						 1, /* auth_context_id */
						 &auth_resp,
						 &auth_blob);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Marshalling of dcerpc_auth failed.\n"));
			goto err_exit;
		}
	}

	/* Now that we have the auth len store it into the right place in
	 * the dcerpc header */
	dcerpc_set_frag_length(&p->out_data.frag,
				p->out_data.frag.length + auth_blob.length);

	if (auth_blob.length) {

		if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
					auth_blob.data, auth_blob.length)) {
			DEBUG(0, ("Append of auth info failed.\n"));
			goto err_exit;
		}
	}

	/*
	 * Setup the lengths for the initial reply.
	 */

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	TALLOC_FREE(auth_blob.data);
	return True;

  err_exit:

	data_blob_free(&p->out_data.frag);
	TALLOC_FREE(auth_blob.data);
	return setup_bind_nak(p, pkt);
}

/****************************************************************************
 Deal with an alter context call. Can be third part of 3 leg auth request for
 SPNEGO calls.
****************************************************************************/

bool api_pipe_alter_context(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info;
	uint16 assoc_gid;
	NTSTATUS status;
	union dcerpc_payload u;
	struct dcerpc_ack_ctx bind_ack_ctx;
	DATA_BLOB auth_resp = data_blob_null;
	DATA_BLOB auth_blob = data_blob_null;
	int pad_len = 0;

	DEBUG(5,("api_pipe_alter_context: make response. %d\n", __LINE__));

	if (pkt->u.bind.assoc_group_id != 0) {
		assoc_gid = pkt->u.bind.assoc_group_id;
	} else {
		assoc_gid = 0x53f0;
	}

	/*
	 * Create the bind response struct.
	 */

	/* If the requested abstract synt uuid doesn't match our client pipe,
		reject the bind_ack & set the transfer interface synt to all 0's,
		ver 0 (observed when NT5 attempts to bind to abstract interfaces
		unknown to NT4)
		Needed when adding entries to a DACL from NT5 - SK */

	if (check_bind_req(p,
			&pkt->u.bind.ctx_list[0].abstract_syntax,
			&pkt->u.bind.ctx_list[0].transfer_syntaxes[0],
			pkt->u.bind.ctx_list[0].context_id)) {

		bind_ack_ctx.result = 0;
		bind_ack_ctx.reason = 0;
		bind_ack_ctx.syntax = pkt->u.bind.ctx_list[0].transfer_syntaxes[0];
	} else {
		p->pipe_bound = False;
		/* Rejection reason: abstract syntax not supported */
		bind_ack_ctx.result = DCERPC_BIND_PROVIDER_REJECT;
		bind_ack_ctx.reason = DCERPC_BIND_REASON_ASYNTAX;
		bind_ack_ctx.syntax = null_ndr_syntax_id;
	}

	/*
	 * Check if this is an authenticated alter context request.
	 */
	if (pkt->auth_length) {
		/* Quick length check. Won't catch a bad auth footer,
		 * prevents overrun. */

		if (pkt->frag_length < RPC_HEADER_LEN +
					DCERPC_AUTH_TRAILER_LENGTH +
					pkt->auth_length) {
			DEBUG(0,("api_pipe_alter_context: auth_len (%u) "
				"too long for fragment %u.\n",
				(unsigned int)pkt->auth_length,
				(unsigned int)pkt->frag_length ));
			goto err_exit;
		}

		status = dcerpc_pull_dcerpc_auth(pkt,
						 &pkt->u.bind.auth_info,
						 &auth_info, p->endian);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Unable to unmarshall dcerpc_auth.\n"));
			goto err_exit;
		}


		/*
		 * Currently only the SPNEGO auth type uses the alter ctx
		 * response in place of the NTLMSSP auth3 type.
		 */

		if (auth_info.auth_type == DCERPC_AUTH_TYPE_SPNEGO) {
			/* We can only finish if the pipe is unbound. */
			if (!p->pipe_bound) {
				if (!pipe_spnego_auth_bind_continue(p, pkt,
						&auth_info, &auth_resp)) {
					goto err_exit;
				}

			} else {
				goto err_exit;
			}
		}
	}

	ZERO_STRUCT(u.alter_resp);
	u.alter_resp.max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;
	u.alter_resp.max_recv_frag = RPC_MAX_PDU_FRAG_LEN;
	u.alter_resp.assoc_group_id = assoc_gid;

	/* secondary address CAN be NULL
	 * as the specs say it's ignored.
	 * It MUST be NULL to have the spoolss working.
	 */
	u.alter_resp.secondary_address = "";
	u.alter_resp.secondary_address_size = 1;

	u.alter_resp.num_results = 1;
	u.alter_resp.ctx_list = &bind_ack_ctx;

	/* NOTE: We leave the auth_info empty so we can calculate the padding
	 * later and then append the auth_info --simo */

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_ALTER_RESP,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  auth_resp.length,
					  pkt->call_id,
					  &u,
					  &p->out_data.frag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall bind_ack packet. (%s)\n",
			  nt_errstr(status)));
	}

	if (auth_resp.length) {

		/* Work out any padding needed before the auth footer. */
		pad_len = p->out_data.frag.length % SERVER_NDR_PADDING_SIZE;
		if (pad_len) {
			pad_len = SERVER_NDR_PADDING_SIZE - pad_len;
			DEBUG(10, ("auth pad_len = %u\n",
				   (unsigned int)pad_len));
		}

		status = dcerpc_push_dcerpc_auth(pkt,
						 auth_info.auth_type,
						 auth_info.auth_level,
						 pad_len,
						 1, /* auth_context_id */
						 &auth_resp,
						 &auth_blob);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Marshalling of dcerpc_auth failed.\n"));
			goto err_exit;
		}
	}

	/* Now that we have the auth len store it into the right place in
	 * the dcerpc header */
	dcerpc_set_frag_length(&p->out_data.frag,
				p->out_data.frag.length +
					pad_len + auth_blob.length);

	if (auth_resp.length) {
		if (pad_len) {
			char pad[SERVER_NDR_PADDING_SIZE];
			memset(pad, '\0', SERVER_NDR_PADDING_SIZE);
			if (!data_blob_append(p->mem_ctx,
						&p->out_data.frag,
						pad, pad_len)) {
				DEBUG(0, ("api_pipe_bind_req: failed to add "
					  "%u bytes of pad data.\n",
					  (unsigned int)pad_len));
				goto err_exit;
			}
		}

		if (!data_blob_append(p->mem_ctx, &p->out_data.frag,
					auth_blob.data, auth_blob.length)) {
			DEBUG(0, ("Append of auth info failed.\n"));
			goto err_exit;
		}
	}

	/*
	 * Setup the lengths for the initial reply.
	 */

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	TALLOC_FREE(auth_blob.data);
	return True;

  err_exit:

	data_blob_free(&p->out_data.frag);
	TALLOC_FREE(auth_blob.data);
	return setup_bind_nak(p, pkt);
}

/****************************************************************************
 Find the set of RPC functions associated with this context_id
****************************************************************************/

static PIPE_RPC_FNS* find_pipe_fns_by_context( PIPE_RPC_FNS *list, uint32 context_id )
{
	PIPE_RPC_FNS *fns = NULL;

	if ( !list ) {
		DEBUG(0,("find_pipe_fns_by_context: ERROR!  No context list for pipe!\n"));
		return NULL;
	}

	for (fns=list; fns; fns=fns->next ) {
		if ( fns->context_id == context_id )
			return fns;
	}
	return NULL;
}

/****************************************************************************
 Memory cleanup.
****************************************************************************/

void free_pipe_rpc_context( PIPE_RPC_FNS *list )
{
	PIPE_RPC_FNS *tmp = list;
	PIPE_RPC_FNS *tmp2;

	while (tmp) {
		tmp2 = tmp->next;
		SAFE_FREE(tmp);
		tmp = tmp2;
	}

	return;	
}

static bool api_rpcTNP(struct pipes_struct *p, struct ncacn_packet *pkt,
		       const struct api_struct *api_rpc_cmds, int n_cmds);

/****************************************************************************
 Find the correct RPC function to call for this request.
 If the pipe is authenticated then become the correct UNIX user
 before doing the call.
****************************************************************************/

bool api_pipe_request(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	bool ret = False;
	bool changed_user = False;
	PIPE_RPC_FNS *pipe_fns;

	if (p->pipe_bound &&
			((p->auth.auth_type == PIPE_AUTH_TYPE_NTLMSSP) ||
			 (p->auth.auth_type == PIPE_AUTH_TYPE_SPNEGO_NTLMSSP))) {
		if(!become_authenticated_pipe_user(p)) {
			data_blob_free(&p->out_data.rdata);
			return False;
		}
		changed_user = True;
	}

	DEBUG(5, ("Requested \\PIPE\\%s\n",
		  get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));

	/* get the set of RPC functions for this context */

	pipe_fns = find_pipe_fns_by_context(p->contexts,
					    pkt->u.request.context_id);

	if ( pipe_fns ) {
		TALLOC_CTX *frame = talloc_stackframe();
		ret = api_rpcTNP(p, pkt, pipe_fns->cmds, pipe_fns->n_cmds);
		TALLOC_FREE(frame);
	}
	else {
		DEBUG(0, ("No rpc function table associated with context "
			  "[%d] on pipe [%s]\n",
			  pkt->u.request.context_id,
			  get_pipe_name_from_syntax(talloc_tos(),
						    &p->syntax)));
	}

	if (changed_user) {
		unbecome_authenticated_pipe_user();
	}

	return ret;
}

/*******************************************************************
 Calls the underlying RPC function for a named pipe.
 ********************************************************************/

static bool api_rpcTNP(struct pipes_struct *p, struct ncacn_packet *pkt,
		       const struct api_struct *api_rpc_cmds, int n_cmds)
{
	int fn_num;
	uint32_t offset1;

	/* interpret the command */
	DEBUG(4,("api_rpcTNP: %s op 0x%x - ",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
		 pkt->u.request.opnum));

	if (DEBUGLEVEL >= 50) {
		fstring name;
		slprintf(name, sizeof(name)-1, "in_%s",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax));
		dump_pdu_region(name, pkt->u.request.opnum,
				&p->in_data.data, 0,
				p->in_data.data.length);
	}

	for (fn_num = 0; fn_num < n_cmds; fn_num++) {
		if (api_rpc_cmds[fn_num].opnum == pkt->u.request.opnum &&
		    api_rpc_cmds[fn_num].fn != NULL) {
			DEBUG(3, ("api_rpcTNP: rpc command: %s\n",
				  api_rpc_cmds[fn_num].name));
			break;
		}
	}

	if (fn_num == n_cmds) {
		/*
		 * For an unknown RPC just return a fault PDU but
		 * return True to allow RPC's on the pipe to continue
		 * and not put the pipe into fault state. JRA.
		 */
		DEBUG(4, ("unknown\n"));
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return True;
	}

	offset1 = p->out_data.rdata.length;

        DEBUG(6, ("api_rpc_cmds[%d].fn == %p\n", 
                fn_num, api_rpc_cmds[fn_num].fn));
	/* do the actual command */
	if(!api_rpc_cmds[fn_num].fn(p)) {
		DEBUG(0,("api_rpcTNP: %s: %s failed.\n",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
			 api_rpc_cmds[fn_num].name));
		data_blob_free(&p->out_data.rdata);
		return False;
	}

	if (p->bad_handle_fault_state) {
		DEBUG(4,("api_rpcTNP: bad handle fault return.\n"));
		p->bad_handle_fault_state = False;
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_CONTEXT_MISMATCH));
		return True;
	}

	if (p->rng_fault_state) {
		DEBUG(4, ("api_rpcTNP: rng fault return\n"));
		p->rng_fault_state = False;
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return True;
	}

	if (DEBUGLEVEL >= 50) {
		fstring name;
		slprintf(name, sizeof(name)-1, "out_%s",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax));
		dump_pdu_region(name, pkt->u.request.opnum,
				&p->out_data.rdata, offset1,
				p->out_data.rdata.length);
	}

	DEBUG(5,("api_rpcTNP: called %s successfully\n",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));

	/* Check for buffer underflow in rpc parsing */
	if ((DEBUGLEVEL >= 10) &&
	    (pkt->frag_length < p->in_data.data.length)) {
		DEBUG(10, ("api_rpcTNP: rpc input buffer underflow (parse error?)\n"));
		dump_data(10, p->in_data.data.data + pkt->frag_length,
			      p->in_data.data.length - pkt->frag_length);
	}

	return True;
}

/****************************************************************************
 Initialise an outgoing packet.
****************************************************************************/

static bool pipe_init_outgoing_data(struct pipes_struct *p)
{
	output_data *o_data = &p->out_data;

	/* Reset the offset counters. */
	o_data->data_sent_length = 0;
	o_data->current_pdu_sent = 0;

	data_blob_free(&o_data->frag);

	/* Free any memory in the current return data buffer. */
	data_blob_free(&o_data->rdata);

	return True;
}

/****************************************************************************
 Sets the fault state on incoming packets.
****************************************************************************/

void set_incoming_fault(struct pipes_struct *p)
{
	data_blob_free(&p->in_data.data);
	p->in_data.pdu_needed_len = 0;
	p->in_data.pdu.length = 0;
	p->fault_state = True;
	DEBUG(10, ("set_incoming_fault: Setting fault state on pipe %s\n",
		   get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));
}

static bool dcesrv_auth_request(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	NTSTATUS status;
	size_t hdr_size = DCERPC_REQUEST_LENGTH;
	struct dcerpc_auth auth;
	uint32_t auth_length;
	DATA_BLOB data;
	DATA_BLOB full_pkt;

	DEBUG(10, ("Checking request auth.\n"));

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		hdr_size += 16;
	}

	switch (p->auth.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		DEBUG(10, ("Requested Privacy.\n"));
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		DEBUG(10, ("Requested Integrity.\n"));
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		if (pkt->auth_length != 0) {
			break;
		}
		return true;
	case DCERPC_AUTH_LEVEL_NONE:
		if (pkt->auth_length != 0) {
			return false;
		}
		return true;

	default:
		return false;
	}

	status = dcerpc_pull_auth_trailer(pkt, pkt,
					  &pkt->u.request.stub_and_verifier,
					  &auth, &auth_length, false);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	pkt->u.request.stub_and_verifier.length -= auth_length;

	data.data = p->in_data.pdu.data + hdr_size;
	data.length = pkt->u.request.stub_and_verifier.length;
	full_pkt.data = p->in_data.pdu.data;
	full_pkt.length = p->in_data.pdu.length - auth.credentials.length;

	switch (p->auth.auth_type) {
	case PIPE_AUTH_TYPE_NONE:
		return true;

	case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
	case PIPE_AUTH_TYPE_NTLMSSP:

		DEBUG(10, ("NTLMSSP auth\n"));

		if (!p->auth.a_u.auth_ntlmssp_state) {
			DEBUG(0, ("Invalid auth level, "
				  "failed to process packet auth.\n"));
			return false;
		}

		switch (p->auth.auth_level) {
		case DCERPC_AUTH_LEVEL_PRIVACY:
			status = auth_ntlmssp_unseal_packet(
					p->auth.a_u.auth_ntlmssp_state,
					data.data, data.length,
					full_pkt.data, full_pkt.length,
					&auth.credentials);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
			memcpy(pkt->u.request.stub_and_verifier.data,
				data.data, data.length);
			break;

		case DCERPC_AUTH_LEVEL_INTEGRITY:
			status = auth_ntlmssp_check_packet(
					p->auth.a_u.auth_ntlmssp_state,
					data.data, data.length,
					full_pkt.data, full_pkt.length,
					&auth.credentials);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
			break;

		default:
			DEBUG(0, ("Invalid auth level, "
				  "failed to process packet auth.\n"));
			return false;
		}
		break;

	case PIPE_AUTH_TYPE_SCHANNEL:

		DEBUG(10, ("SCHANNEL auth\n"));

		switch (p->auth.auth_level) {
		case DCERPC_AUTH_LEVEL_PRIVACY:
			status = netsec_incoming_packet(
					p->auth.a_u.schannel_auth,
					pkt, true,
					data.data, data.length,
					&auth.credentials);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
			memcpy(pkt->u.request.stub_and_verifier.data,
				data.data, data.length);
			break;

		case DCERPC_AUTH_LEVEL_INTEGRITY:
			status = netsec_incoming_packet(
					p->auth.a_u.schannel_auth,
					pkt, false,
					data.data, data.length,
					&auth.credentials);
			if (!NT_STATUS_IS_OK(status)) {
				return false;
			}
			break;

		default:
			DEBUG(0, ("Invalid auth level, "
				  "failed to process packet auth.\n"));
			return false;
		}
		break;

	default:
		DEBUG(0, ("process_request_pdu: "
			  "unknown auth type %u set.\n",
			  (unsigned int)p->auth.auth_type));
		set_incoming_fault(p);
		return false;
	}

	/* remove the indicated amount of padding */
	if (pkt->u.request.stub_and_verifier.length < auth.auth_pad_length) {
		return false;
	}
	pkt->u.request.stub_and_verifier.length -= auth.auth_pad_length;

	return true;
}

/****************************************************************************
 Processes a request pdu. This will do auth processing if needed, and
 appends the data into the complete stream if the LAST flag is not set.
****************************************************************************/

static bool process_request_pdu(struct pipes_struct *p, struct ncacn_packet *pkt)
{
	DATA_BLOB data;

	if (!p->pipe_bound) {
		DEBUG(0,("process_request_pdu: rpc request with no bind.\n"));
		set_incoming_fault(p);
		return False;
	}

	/* Store the opnum */
	p->opnum = pkt->u.request.opnum;

	if (!dcesrv_auth_request(p, pkt)) {
		DEBUG(0,("Failed to check packet auth.\n"));
		set_incoming_fault(p);
		return false;
	}

	data = pkt->u.request.stub_and_verifier;

	/*
	 * Check the data length doesn't go over the 15Mb limit.
	 * increased after observing a bug in the Windows NT 4.0 SP6a
	 * spoolsv.exe when the response to a GETPRINTERDRIVER2 RPC
	 * will not fit in the initial buffer of size 0x1068   --jerry 22/01/2002
	 */

	if (p->in_data.data.length + data.length > MAX_RPC_DATA_SIZE) {
		DEBUG(0, ("process_request_pdu: "
			  "rpc data buffer too large (%u) + (%u)\n",
			  (unsigned int)p->in_data.data.length,
			  (unsigned int)data.length));
		set_incoming_fault(p);
		return False;
	}

	/*
	 * Append the data portion into the buffer and return.
	 */

	if (data.length) {
		if (!data_blob_append(p->mem_ctx, &p->in_data.data,
					  data.data, data.length)) {
			DEBUG(0, ("Unable to append data size %u "
				  "to parse buffer of size %u.\n",
				  (unsigned int)data.length,
				  (unsigned int)p->in_data.data.length));
			set_incoming_fault(p);
			return False;
		}
	}

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_LAST) {
		bool ret = False;
		/*
		 * Ok - we finally have a complete RPC stream.
		 * Call the rpc command to process it.
		 */

		/*
		 * Process the complete data stream here.
		 */
		if (pipe_init_outgoing_data(p)) {
			ret = api_pipe_request(p, pkt);
		}

		return ret;
	}

	return True;
}

/****************************************************************************
 Processes a finished PDU stored in p->in_data.pdu.
****************************************************************************/

void process_complete_pdu(struct pipes_struct *p)
{
	struct ncacn_packet *pkt = NULL;
	NTSTATUS status;
	bool reply = False;

	if(p->fault_state) {
		DEBUG(10,("process_complete_pdu: pipe %s in fault state.\n",
			  get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));
		goto done;
	}

	pkt = talloc(p->mem_ctx, struct ncacn_packet);
	if (!pkt) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	/*
	 * Ensure we're using the corrent endianness for both the
	 * RPC header flags and the raw data we will be reading from.
	 */
	if (dcerpc_get_endian_flag(&p->in_data.pdu) & DCERPC_DREP_LE) {
		p->endian = RPC_LITTLE_ENDIAN;
	} else {
		p->endian = RPC_BIG_ENDIAN;
	}
	DEBUG(10, ("PDU is in %s Endian format!\n", p->endian?"Big":"Little"));

	status = dcerpc_pull_ncacn_packet(pkt, &p->in_data.pdu,
					  pkt, p->endian);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to unmarshal rpc packet: %s!\n",
			  nt_errstr(status)));
		goto done;
	}

	/* Store the call_id */
	p->call_id = pkt->call_id;

	DEBUG(10, ("Processing packet type %d\n", (int)pkt->ptype));

	switch (pkt->ptype) {
	case DCERPC_PKT_REQUEST:
		reply = process_request_pdu(p, pkt);
		break;

	case DCERPC_PKT_PING: /* CL request - ignore... */
		DEBUG(0, ("process_complete_pdu: Error. "
			  "Connectionless packet type %d received on "
			  "pipe %s.\n", (int)pkt->ptype,
			 get_pipe_name_from_syntax(talloc_tos(),
						   &p->syntax)));
		break;

	case DCERPC_PKT_RESPONSE: /* No responses here. */
		DEBUG(0, ("process_complete_pdu: Error. "
			  "DCERPC_PKT_RESPONSE received from client "
			  "on pipe %s.\n",
			 get_pipe_name_from_syntax(talloc_tos(),
						   &p->syntax)));
		break;

	case DCERPC_PKT_FAULT:
	case DCERPC_PKT_WORKING:
		/* CL request - reply to a ping when a call in process. */
	case DCERPC_PKT_NOCALL:
		/* CL - server reply to a ping call. */
	case DCERPC_PKT_REJECT:
	case DCERPC_PKT_ACK:
	case DCERPC_PKT_CL_CANCEL:
	case DCERPC_PKT_FACK:
	case DCERPC_PKT_CANCEL_ACK:
		DEBUG(0, ("process_complete_pdu: Error. "
			  "Connectionless packet type %u received on "
			  "pipe %s.\n", (unsigned int)pkt->ptype,
			 get_pipe_name_from_syntax(talloc_tos(),
						   &p->syntax)));
		break;

	case DCERPC_PKT_BIND:
		/*
		 * We assume that a pipe bind is only in one pdu.
		 */
		if (pipe_init_outgoing_data(p)) {
			reply = api_pipe_bind_req(p, pkt);
		}
		break;

	case DCERPC_PKT_BIND_ACK:
	case DCERPC_PKT_BIND_NAK:
		DEBUG(0, ("process_complete_pdu: Error. "
			  "DCERPC_PKT_BINDACK/DCERPC_PKT_BINDNACK "
			  "packet type %u received on pipe %s.\n",
			  (unsigned int)pkt->ptype,
			 get_pipe_name_from_syntax(talloc_tos(),
						   &p->syntax)));
		break;


	case DCERPC_PKT_ALTER:
		/*
		 * We assume that a pipe bind is only in one pdu.
		 */
		if (pipe_init_outgoing_data(p)) {
			reply = api_pipe_alter_context(p, pkt);
		}
		break;

	case DCERPC_PKT_ALTER_RESP:
		DEBUG(0, ("process_complete_pdu: Error. "
			  "DCERPC_PKT_ALTER_RESP on pipe %s: "
			  "Should only be server -> client.\n",
			 get_pipe_name_from_syntax(talloc_tos(),
						   &p->syntax)));
		break;

	case DCERPC_PKT_AUTH3:
		/*
		 * The third packet in an NTLMSSP auth exchange.
		 */
		if (pipe_init_outgoing_data(p)) {
			reply = api_pipe_bind_auth3(p, pkt);
		}
		break;

	case DCERPC_PKT_SHUTDOWN:
		DEBUG(0, ("process_complete_pdu: Error. "
			  "DCERPC_PKT_SHUTDOWN on pipe %s: "
			  "Should only be server -> client.\n",
			 get_pipe_name_from_syntax(talloc_tos(),
						   &p->syntax)));
		break;

	case DCERPC_PKT_CO_CANCEL:
		/* For now just free all client data and continue
		 * processing. */
		DEBUG(3,("process_complete_pdu: DCERPC_PKT_CO_CANCEL."
			 " Abandoning rpc call.\n"));
		/* As we never do asynchronous RPC serving, we can
		 * never cancel a call (as far as I know).
		 * If we ever did we'd have to send a cancel_ack reply.
		 * For now, just free all client data and continue
		 * processing. */
		reply = True;
		break;

#if 0
		/* Enable this if we're doing async rpc. */
		/* We must check the outstanding callid matches. */
		if (pipe_init_outgoing_data(p)) {
			/* Send a cancel_ack PDU reply. */
			/* We should probably check the auth-verifier here. */
			reply = setup_cancel_ack_reply(p, pkt);
		}
		break;
#endif

	case DCERPC_PKT_ORPHANED:
		/* We should probably check the auth-verifier here.
		 * For now just free all client data and continue
		 * processing. */
		DEBUG(3, ("process_complete_pdu: DCERPC_PKT_ORPHANED."
			  " Abandoning rpc call.\n"));
		reply = True;
		break;

	default:
		DEBUG(0, ("process_complete_pdu: "
			  "Unknown rpc type = %u received.\n",
			  (unsigned int)pkt->ptype));
		break;
	}

done:
	if (!reply) {
		DEBUG(3,("process_complete_pdu: DCE/RPC fault sent on "
			 "pipe %s\n", get_pipe_name_from_syntax(talloc_tos(),
								&p->syntax)));
		set_incoming_fault(p);
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		TALLOC_FREE(pkt);
	} else {
		/*
		 * Reset the lengths. We're ready for a new pdu.
		 */
		TALLOC_FREE(p->in_data.pdu.data);
		p->in_data.pdu_needed_len = 0;
		p->in_data.pdu.length = 0;
	}

	TALLOC_FREE(pkt);
}

