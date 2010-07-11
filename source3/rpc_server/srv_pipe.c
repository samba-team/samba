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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static void free_pipe_ntlmssp_auth_data(struct pipe_auth_data *auth)
{
	struct auth_ntlmssp_state *a = auth->a_u.auth_ntlmssp_state;

	if (a) {
		auth_ntlmssp_end(&a);
	}
	auth->a_u.auth_ntlmssp_state = NULL;
}

static DATA_BLOB generic_session_key(void)
{
	return data_blob("SystemLibraryDTC", 16);
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
 Handle NTLMSSP.
 ********************************************************************/

static bool create_next_pdu_ntlmssp(pipes_struct *p)
{
	DATA_BLOB hdr;
	uint8_t hdr_flags;
	RPC_HDR_RESP hdr_resp;
	uint32 ss_padding_len = 0;
	uint32 data_space_available;
	uint32 data_len_left;
	uint32 data_len;
	NTSTATUS status;
	DATA_BLOB auth_blob;
	RPC_HDR_AUTH auth_info;
	uint8 auth_type, auth_level;
	struct auth_ntlmssp_state *a = p->auth.a_u.auth_ntlmssp_state;
	TALLOC_CTX *frame;

	/*
	 * If we're in the fault state, keep returning fault PDU's until
	 * the pipe gets closed. JRA.
	 */

	if(p->fault_state) {
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return True;
	}

	memset((char *)&hdr_resp, '\0', sizeof(hdr_resp));

	/* Set up rpc header flags. */
	if (p->out_data.data_sent_length == 0) {
		hdr_flags = DCERPC_PFC_FLAG_FIRST;
	} else {
		hdr_flags = 0;
	}

	/*
	 * Work out how much we can fit in a single PDU.
	 */

	data_len_left = prs_offset(&p->out_data.rdata) - p->out_data.data_sent_length;

	/*
	 * Ensure there really is data left to send.
	 */

	if(!data_len_left) {
		DEBUG(0,("create_next_pdu_ntlmssp: no data left to send !\n"));
		return False;
	}

	/* Space available - not including padding. */
	data_space_available = RPC_MAX_PDU_FRAG_LEN - RPC_HEADER_LEN -
		RPC_HDR_RESP_LEN - RPC_HDR_AUTH_LEN - NTLMSSP_SIG_SIZE;

	/*
	 * The amount we send is the minimum of the available
	 * space and the amount left to send.
	 */

	data_len = MIN(data_len_left, data_space_available);

	/* Work out any padding alignment requirements. */
	if ((RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len) % SERVER_NDR_PADDING_SIZE) {
		ss_padding_len = SERVER_NDR_PADDING_SIZE -
			((RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len) % SERVER_NDR_PADDING_SIZE);
		DEBUG(10,("create_next_pdu_ntlmssp: adding sign/seal padding of %u\n",
			ss_padding_len ));
		/* If we're over filling the packet, we need to make space
 		 * for the padding at the end of the data. */
		if (data_len + ss_padding_len > data_space_available) {
			data_len -= SERVER_NDR_PADDING_SIZE;
		}
	}

	/*
	 * Set up the alloc hint. This should be the data left to
	 * send.
	 */

	hdr_resp.alloc_hint = data_len_left;

	/*
	 * Work out if this PDU will be the last.
	 */
	if (p->out_data.data_sent_length + data_len >=
					prs_offset(&p->out_data.rdata)) {
		hdr_flags |= DCERPC_PFC_FLAG_LAST;
	}

	/*
	 * Init the parse struct to point at the outgoing
	 * data.
	 */
	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

	status = dcerpc_push_ncacn_packet_header(
				prs_get_mem_context(&p->out_data.frag),
				DCERPC_PKT_RESPONSE,
				hdr_flags,
				RPC_HEADER_LEN + RPC_HDR_RESP_LEN +
				  data_len + ss_padding_len +
				  RPC_HDR_AUTH_LEN + NTLMSSP_SIG_SIZE,
				NTLMSSP_SIG_SIZE,
				p->call_id,
				&hdr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall RPC Header.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Store the header in the data stream. */
	if (!prs_copy_data_in(&p->out_data.frag,
				(char *)hdr.data, hdr.length)) {
		DEBUG(0, ("Out of memory.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	if(!smb_io_rpc_hdr_resp("resp", &hdr_resp, &p->out_data.frag, 0)) {
		DEBUG(0,("create_next_pdu_ntlmssp: failed to marshall RPC_HDR_RESP.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Copy the data into the PDU. */

	if(!prs_append_some_prs_data(&p->out_data.frag, &p->out_data.rdata,
				     p->out_data.data_sent_length, data_len)) {
		DEBUG(0,("create_next_pdu_ntlmssp: failed to copy %u bytes of data.\n", (unsigned int)data_len));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Copy the sign/seal padding data. */
	if (ss_padding_len) {
		char pad[SERVER_NDR_PADDING_SIZE];

		memset(pad, '\0', SERVER_NDR_PADDING_SIZE);
		if (!prs_copy_data_in(&p->out_data.frag, pad,
				      ss_padding_len)) {
			DEBUG(0,("create_next_pdu_ntlmssp: failed to add %u bytes of pad data.\n",
					(unsigned int)ss_padding_len));
			prs_mem_free(&p->out_data.frag);
			return False;
		}
	}


	/* Now write out the auth header and null blob. */
	if (p->auth.auth_type == PIPE_AUTH_TYPE_NTLMSSP) {
		auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	} else {
		auth_type = DCERPC_AUTH_TYPE_SPNEGO;
	}
	if (p->auth.auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	} else {
		auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}

	init_rpc_hdr_auth(&auth_info, auth_type, auth_level, ss_padding_len, 1 /* context id. */);

	if (!smb_io_rpc_hdr_auth("hdr_auth", &auth_info,
				&p->out_data.frag, 0)) {
		DEBUG(0,("create_next_pdu_ntlmssp: failed to marshall RPC_HDR_AUTH.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Generate the sign blob. */

	frame = talloc_stackframe();
	switch (p->auth.auth_level) {
		case DCERPC_AUTH_LEVEL_PRIVACY:
			/* Data portion is encrypted. */
			status = auth_ntlmssp_seal_packet(
				a, frame,
				(uint8_t *)prs_data_p(&p->out_data.frag)
				+ RPC_HEADER_LEN + RPC_HDR_RESP_LEN,
				data_len + ss_padding_len,
				(unsigned char *)prs_data_p(&p->out_data.frag),
				(size_t)prs_offset(&p->out_data.frag),
				&auth_blob);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(frame);
				prs_mem_free(&p->out_data.frag);
				return False;
			}
			break;
		case DCERPC_AUTH_LEVEL_INTEGRITY:
			/* Data is signed. */
			status = auth_ntlmssp_sign_packet(
				a, frame,
				(unsigned char *)prs_data_p(&p->out_data.frag)
				+ RPC_HEADER_LEN + RPC_HDR_RESP_LEN,
				data_len + ss_padding_len,
				(unsigned char *)prs_data_p(&p->out_data.frag),
				(size_t)prs_offset(&p->out_data.frag),
				&auth_blob);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(frame);
				prs_mem_free(&p->out_data.frag);
				return False;
			}
			break;
		default:
			talloc_free(frame);
			prs_mem_free(&p->out_data.frag);
			return False;
	}

	/* Append the auth blob. */
	if (!prs_copy_data_in(&p->out_data.frag, (char *)auth_blob.data,
			      NTLMSSP_SIG_SIZE)) {
		DEBUG(0,("create_next_pdu_ntlmssp: failed to add %u bytes auth blob.\n",
				(unsigned int)NTLMSSP_SIG_SIZE));
		talloc_free(frame);
		prs_mem_free(&p->out_data.frag);
		return False;
	}
	talloc_free(frame);

	/*
	 * Setup the counts for this PDU.
	 */

	p->out_data.data_sent_length += data_len;
	p->out_data.current_pdu_sent = 0;

	return True;
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
 Return an schannel authenticated fragment.
 ********************************************************************/

static bool create_next_pdu_schannel(pipes_struct *p)
{
	DATA_BLOB hdr;
	uint8_t hdr_flags;
	RPC_HDR_RESP hdr_resp;
	uint32 ss_padding_len = 0;
	uint32 data_len;
	uint32 data_space_available;
	uint32 data_len_left;
	uint32 data_pos;
	NTSTATUS status;

	/*
	 * If we're in the fault state, keep returning fault PDU's until
	 * the pipe gets closed. JRA.
	 */

	if(p->fault_state) {
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return True;
	}

	memset((char *)&hdr_resp, '\0', sizeof(hdr_resp));

	/* Set up rpc header flags. */
	if (p->out_data.data_sent_length == 0) {
		hdr_flags = DCERPC_PFC_FLAG_FIRST;
	} else {
		hdr_flags = 0;
	}

	/*
	 * Work out how much we can fit in a single PDU.
	 */

	data_len_left = prs_offset(&p->out_data.rdata) - p->out_data.data_sent_length;

	/*
	 * Ensure there really is data left to send.
	 */

	if(!data_len_left) {
		DEBUG(0,("create_next_pdu_schannel: no data left to send !\n"));
		return False;
	}

	/* Space available - not including padding. */
	data_space_available = RPC_MAX_PDU_FRAG_LEN - RPC_HEADER_LEN
		- RPC_HDR_RESP_LEN - RPC_HDR_AUTH_LEN
		- RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN;

	/*
	 * The amount we send is the minimum of the available
	 * space and the amount left to send.
	 */

	data_len = MIN(data_len_left, data_space_available);

	/* Work out any padding alignment requirements. */
	if ((RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len) % SERVER_NDR_PADDING_SIZE) {
		ss_padding_len = SERVER_NDR_PADDING_SIZE -
			((RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len) % SERVER_NDR_PADDING_SIZE);
		DEBUG(10,("create_next_pdu_schannel: adding sign/seal padding of %u\n",
			ss_padding_len ));
		/* If we're over filling the packet, we need to make space
 		 * for the padding at the end of the data. */
		if (data_len + ss_padding_len > data_space_available) {
			data_len -= SERVER_NDR_PADDING_SIZE;
		}
	}

	/*
	 * Set up the alloc hint. This should be the data left to
	 * send.
	 */

	hdr_resp.alloc_hint = data_len_left;

	/*
	 * Work out if this PDU will be the last.
	 */
	if (p->out_data.data_sent_length + data_len >=
					prs_offset(&p->out_data.rdata)) {
		hdr_flags |= DCERPC_PFC_FLAG_LAST;
	}

	/*
	 * Init the parse struct to point at the outgoing
	 * data.
	 */
	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

	status = dcerpc_push_ncacn_packet_header(
				prs_get_mem_context(&p->out_data.frag),
				DCERPC_PKT_RESPONSE,
				hdr_flags,
				RPC_HEADER_LEN + RPC_HDR_RESP_LEN +
				  data_len + ss_padding_len +
				  RPC_HDR_AUTH_LEN +
				  RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN,
				RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN,
				p->call_id,
				&hdr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall RPC Header.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Store the header in the data stream. */
	if (!prs_copy_data_in(&p->out_data.frag,
				(char *)hdr.data, hdr.length)) {
		DEBUG(0, ("Out of memory.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	if(!smb_io_rpc_hdr_resp("resp", &hdr_resp, &p->out_data.frag, 0)) {
		DEBUG(0,("create_next_pdu_schannel: failed to marshall RPC_HDR_RESP.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Store the current offset. */
	data_pos = prs_offset(&p->out_data.frag);

	/* Copy the data into the PDU. */

	if(!prs_append_some_prs_data(&p->out_data.frag, &p->out_data.rdata,
				     p->out_data.data_sent_length, data_len)) {
		DEBUG(0,("create_next_pdu_schannel: failed to copy %u bytes of data.\n", (unsigned int)data_len));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Copy the sign/seal padding data. */
	if (ss_padding_len) {
		char pad[SERVER_NDR_PADDING_SIZE];
		memset(pad, '\0', SERVER_NDR_PADDING_SIZE);
		if (!prs_copy_data_in(&p->out_data.frag, pad,
				      ss_padding_len)) {
			DEBUG(0,("create_next_pdu_schannel: failed to add %u bytes of pad data.\n", (unsigned int)ss_padding_len));
			prs_mem_free(&p->out_data.frag);
			return False;
		}
	}

	{
		/*
		 * Schannel processing.
		 */
		RPC_HDR_AUTH auth_info;
		DATA_BLOB blob;
		uint8_t *data;

		/* Check it's the type of reply we were expecting to decode */

		init_rpc_hdr_auth(&auth_info,
				DCERPC_AUTH_TYPE_SCHANNEL,
				p->auth.auth_level == DCERPC_AUTH_LEVEL_PRIVACY ?
					DCERPC_AUTH_LEVEL_PRIVACY : DCERPC_AUTH_LEVEL_INTEGRITY,
				ss_padding_len, 1);

		if (!smb_io_rpc_hdr_auth("hdr_auth", &auth_info,
					&p->out_data.frag, 0)) {
			DEBUG(0,("create_next_pdu_schannel: failed to marshall RPC_HDR_AUTH.\n"));
			prs_mem_free(&p->out_data.frag);
			return False;
		}

		data = (uint8_t *)prs_data_p(&p->out_data.frag) + data_pos;

		switch (p->auth.auth_level) {
		case DCERPC_AUTH_LEVEL_PRIVACY:
			status = netsec_outgoing_packet(p->auth.a_u.schannel_auth,
							talloc_tos(),
							true,
							data,
							data_len + ss_padding_len,
							&blob);
			break;
		case DCERPC_AUTH_LEVEL_INTEGRITY:
			status = netsec_outgoing_packet(p->auth.a_u.schannel_auth,
							talloc_tos(),
							false,
							data,
							data_len + ss_padding_len,
							&blob);
			break;
		default:
			status = NT_STATUS_INTERNAL_ERROR;
			break;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("create_next_pdu_schannel: failed to process packet: %s\n",
				nt_errstr(status)));
			prs_mem_free(&p->out_data.frag);
			return false;
		}

		/* Finally marshall the blob. */

		if (DEBUGLEVEL >= 10) {
			dump_NL_AUTH_SIGNATURE(talloc_tos(), &blob);
		}

		if (!prs_copy_data_in(&p->out_data.frag, (const char *)blob.data, blob.length)) {
			prs_mem_free(&p->out_data.frag);
			return false;
		}
	}

	/*
	 * Setup the counts for this PDU.
	 */

	p->out_data.data_sent_length += data_len;
	p->out_data.current_pdu_sent = 0;

	return True;
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
 No authentication done.
********************************************************************/

static bool create_next_pdu_noauth(pipes_struct *p)
{
	DATA_BLOB hdr;
	uint8_t hdr_flags;
	NTSTATUS status;
	RPC_HDR_RESP hdr_resp;
	uint32 data_len;
	uint32 data_space_available;
	uint32 data_len_left;

	/*
	 * If we're in the fault state, keep returning fault PDU's until
	 * the pipe gets closed. JRA.
	 */

	if(p->fault_state) {
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return True;
	}

	memset((char *)&hdr_resp, '\0', sizeof(hdr_resp));

	/* Set up rpc header flags. */
	if (p->out_data.data_sent_length == 0) {
		hdr_flags = DCERPC_PFC_FLAG_FIRST;
	} else {
		hdr_flags = 0;
	}

	/*
	 * Work out how much we can fit in a single PDU.
	 */

	data_len_left = prs_offset(&p->out_data.rdata) - p->out_data.data_sent_length;

	/*
	 * Ensure there really is data left to send.
	 */

	if(!data_len_left) {
		DEBUG(0,("create_next_pdu_noath: no data left to send !\n"));
		return False;
	}

	data_space_available = RPC_MAX_PDU_FRAG_LEN - RPC_HEADER_LEN
		- RPC_HDR_RESP_LEN;

	/*
	 * The amount we send is the minimum of the available
	 * space and the amount left to send.
	 */

	data_len = MIN(data_len_left, data_space_available);

	/*
	 * Set up the alloc hint. This should be the data left to
	 * send.
	 */

	hdr_resp.alloc_hint = data_len_left;

	/*
	 * Work out if this PDU will be the last.
	 */
	if(p->out_data.data_sent_length + data_len >= prs_offset(&p->out_data.rdata)) {
		hdr_flags |= DCERPC_PFC_FLAG_LAST;
	}

	/*
	 * Init the parse struct to point at the outgoing
	 * data.
	 */
	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

	status = dcerpc_push_ncacn_packet_header(
				prs_get_mem_context(&p->out_data.frag),
				DCERPC_PKT_RESPONSE,
				hdr_flags,
				RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len,
				0,
				p->call_id,
				&hdr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall RPC Header.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Store the header in the data stream. */
	if (!prs_copy_data_in(&p->out_data.frag,
				(char *)hdr.data, hdr.length)) {
		DEBUG(0, ("Out of memory.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	if(!smb_io_rpc_hdr_resp("resp", &hdr_resp, &p->out_data.frag, 0)) {
		DEBUG(0,("create_next_pdu_noath: failed to marshall RPC_HDR_RESP.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/* Copy the data into the PDU. */

	if(!prs_append_some_prs_data(&p->out_data.frag, &p->out_data.rdata,
				     p->out_data.data_sent_length, data_len)) {
		DEBUG(0,("create_next_pdu_noauth: failed to copy %u bytes of data.\n", (unsigned int)data_len));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	/*
	 * Setup the counts for this PDU.
	 */

	p->out_data.data_sent_length += data_len;
	p->out_data.current_pdu_sent = 0;

	return True;
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
********************************************************************/

bool create_next_pdu(pipes_struct *p)
{
	switch(p->auth.auth_level) {
		case DCERPC_AUTH_LEVEL_NONE:
		case DCERPC_AUTH_LEVEL_CONNECT:
			/* This is incorrect for auth level connect. Fixme. JRA */
			return create_next_pdu_noauth(p);

		default:
			switch(p->auth.auth_type) {
				case PIPE_AUTH_TYPE_NTLMSSP:
				case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
					return create_next_pdu_ntlmssp(p);
				case PIPE_AUTH_TYPE_SCHANNEL:
					return create_next_pdu_schannel(p);
				default:
					break;
			}
	}

	DEBUG(0,("create_next_pdu: invalid internal auth level %u / type %u",
			(unsigned int)p->auth.auth_level,
			(unsigned int)p->auth.auth_type));
	return False;
}

/*******************************************************************
 Process an NTLMSSP authentication response.
 If this function succeeds, the user has been authenticated
 and their domain, name and calling workstation stored in
 the pipe struct.
*******************************************************************/

static bool pipe_ntlmssp_verify_final(pipes_struct *p, DATA_BLOB *p_resp_blob)
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

	p->server_info = auth_ntlmssp_server_info(p, a);
	if (p->server_info == NULL) {
		DEBUG(0, ("auth_ntlmssp_server_info failed to obtain the server info for authenticated user\n"));
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

bool api_pipe_bind_auth3(pipes_struct *p, struct ncacn_packet *pkt)
{
	struct dcerpc_auth auth_info;
	uint32_t auth_len = pkt->auth_length;
	NTSTATUS status;

	DEBUG(5,("api_pipe_bind_auth3: decode request. %d\n", __LINE__));

	if (auth_len == 0) {
		DEBUG(0,("api_pipe_bind_auth3: No auth field sent !\n"));
		goto err;
	}

	/* Ensure there's enough data for an authenticated request. */
	if (RPC_HEADER_LEN + RPC_HDR_AUTH_LEN + auth_len >
				pkt->frag_length) {
			DEBUG(0,("api_pipe_ntlmssp_auth_process: auth_len "
				"%u is too large.\n",
                        (unsigned int)auth_len ));
		goto err;
	}

	/*
	 * Decode the authentication verifier response.
	 */

	status = dcerpc_pull_dcerpc_auth(pkt,
					 &pkt->u.auth3.auth_info,
					 &auth_info);
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

	free_pipe_ntlmssp_auth_data(&p->auth);
	p->auth.a_u.auth_ntlmssp_state = NULL;

	return False;
}

/*******************************************************************
 Marshall a bind_nak pdu.
*******************************************************************/

static bool setup_bind_nak(pipes_struct *p, struct ncacn_packet *pkt)
{
	NTSTATUS status;
	union dcerpc_payload u;
	DATA_BLOB blob;

	/* Free any memory in the current return data buffer. */
	prs_mem_free(&p->out_data.rdata);

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

	/*
	 * Initialize a bind_nak header.
	 */

	ZERO_STRUCT(u);

	u.bind_nak.reject_reason  = 0;

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_BIND_NAK,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  0,
					  pkt->call_id,
					  &u,
					  &blob);
	if (!NT_STATUS_IS_OK(status)) {
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	if (!prs_copy_data_in(&p->out_data.frag,
			      (char *)blob.data, blob.length)) {
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	if (p->auth.auth_data_free_func) {
		(*p->auth.auth_data_free_func)(&p->auth);
	}
	p->auth.auth_level = DCERPC_AUTH_LEVEL_NONE;
	p->auth.auth_type = PIPE_AUTH_TYPE_NONE;
	p->pipe_bound = False;

	return True;
}

/*******************************************************************
 Marshall a fault pdu.
*******************************************************************/

bool setup_fault_pdu(pipes_struct *p, NTSTATUS fault_status)
{
	NTSTATUS status;
	union dcerpc_payload u;
	DATA_BLOB blob;

	/* Free any memory in the current return data buffer. */
	prs_mem_free(&p->out_data.rdata);

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

	/*
	 * Initialize a fault header.
	 */

	ZERO_STRUCT(u);

	u.fault.status		= NT_STATUS_V(fault_status);
	u.fault._pad		= data_blob_talloc_zero(p->mem_ctx, 4);

	status = dcerpc_push_ncacn_packet(p->mem_ctx,
					  DCERPC_PKT_FAULT,
					  DCERPC_PFC_FLAG_FIRST |
					   DCERPC_PFC_FLAG_LAST |
					   DCERPC_PFC_FLAG_DID_NOT_EXECUTE,
					  0,
					  p->call_id,
					  &u,
					  &blob);
	if (!NT_STATUS_IS_OK(status)) {
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	if (!prs_copy_data_in(&p->out_data.frag,
			      (char *)blob.data, blob.length)) {
		prs_mem_free(&p->out_data.frag);
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

static bool pipe_spnego_auth_bind_kerberos(pipes_struct *p,
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

static bool pipe_spnego_auth_bind_negotiate(pipes_struct *p,
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
	if (!parse_negTokenTarg(pauth_info->credentials, OIDs, &secblob)) {
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
		free_pipe_ntlmssp_auth_data(&p->auth);
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
		*response = spnego_gen_auth_response(&chal, status, OID_NTLMSSP);
	} else {
		/*
		 * SPNEGO negotiate down to NTLMSSP. The subsequent
		 * code to process follow-up packets is not complete
		 * yet. JRA.
		 */
		*response = spnego_gen_auth_response(NULL,
					NT_STATUS_MORE_PROCESSING_REQUIRED,
					OID_NTLMSSP);
	}

	/* Make sure data is bound to the memctx, to be freed the caller */
	talloc_steal(mem_ctx, response->data);

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

static bool pipe_spnego_auth_bind_continue(pipes_struct *p,
					   uint32_t ss_padding_len,
					   struct dcerpc_auth *pauth_info,
					   prs_struct *pout_auth)
{
	RPC_HDR_AUTH auth_info;
	DATA_BLOB auth_blob;
	DATA_BLOB auth_reply;
	DATA_BLOB response;
	struct auth_ntlmssp_state *a = p->auth.a_u.auth_ntlmssp_state;

	ZERO_STRUCT(auth_blob);
	ZERO_STRUCT(auth_reply);
	ZERO_STRUCT(response);

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

	if (!spnego_parse_auth(pauth_info->credentials, &auth_blob)) {
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
	response = spnego_gen_auth_response(&auth_reply, NT_STATUS_OK, OID_NTLMSSP);

	/* FIXME - add auth_pad_len here ! */

	/* Copy the blob into the pout_auth parse struct */
	init_rpc_hdr_auth(&auth_info, DCERPC_AUTH_TYPE_SPNEGO,
			pauth_info->auth_level, ss_padding_len, 1);
	if(!smb_io_rpc_hdr_auth("", &auth_info, pout_auth, 0)) {
		DEBUG(0,("pipe_spnego_auth_bind_continue: marshalling of RPC_HDR_AUTH failed.\n"));
		goto err;
	}

	if (!prs_copy_data_in(pout_auth, (char *)response.data, response.length)) {
		DEBUG(0,("pipe_spnego_auth_bind_continue: marshalling of data blob failed.\n"));
		goto err;
	}

	data_blob_free(&auth_reply);
	data_blob_free(&response);

	p->pipe_bound = True;

	return True;

 err:

	data_blob_free(&auth_blob);
	data_blob_free(&auth_reply);
	data_blob_free(&response);

	free_pipe_ntlmssp_auth_data(&p->auth);
	p->auth.a_u.auth_ntlmssp_state = NULL;

	return False;
}

/*******************************************************************
 Handle an schannel bind auth.
*******************************************************************/

static bool pipe_schannel_auth_bind(pipes_struct *p,
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
	p->auth.auth_data_free_func = NULL;
	p->auth.auth_type = PIPE_AUTH_TYPE_SCHANNEL;

	p->pipe_bound = True;

	return True;
}

/*******************************************************************
 Handle an NTLMSSP bind auth.
*******************************************************************/

static bool pipe_ntlmssp_auth_bind(pipes_struct *p,
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

	free_pipe_ntlmssp_auth_data(&p->auth);
	p->auth.a_u.auth_ntlmssp_state = NULL;
	return False;
}

/*******************************************************************
 Respond to a pipe bind request.
*******************************************************************/

bool api_pipe_bind_req(pipes_struct *p, struct ncacn_packet *pkt)
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
	DATA_BLOB blob = data_blob_null;
	int pad_len = 0;

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
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

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
					RPC_HDR_AUTH_LEN +
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
						 &auth_info);
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

	status = dcerpc_push_ncacn_packet(pkt, DCERPC_PKT_BIND_ACK,
					  DCERPC_PFC_FLAG_FIRST |
						DCERPC_PFC_FLAG_LAST,
					  auth_resp.length,
					  pkt->call_id,
					  &u, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to marshall bind_ack packet. (%s)\n",
			  nt_errstr(status)));
	}

	if (auth_resp.length) {

		/* Work out any padding needed before the auth footer. */
		pad_len = blob.length % SERVER_NDR_PADDING_SIZE;
		if (pad_len) {
			pad_len = SERVER_NDR_PADDING_SIZE - pad_len;
			DEBUG(10, ("auth pad_len = %u\n",
				   (unsigned int)pad_len));
		}

		status = dcerpc_push_dcerpc_auth(pkt,
						 auth_type,
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
	dcerpc_set_frag_length(&blob, blob.length + pad_len + auth_blob.length);

	/* And finally copy all bits in the output pdu */
	if (!prs_copy_data_in(&p->out_data.frag,
					(char *)blob.data, blob.length)) {
		DEBUG(0, ("Failed to copy data to output buffer.\n"));
		goto err_exit;
	}

	if (auth_blob.length) {
		if (pad_len) {
			char pad[SERVER_NDR_PADDING_SIZE];
			memset(pad, '\0', SERVER_NDR_PADDING_SIZE);
			if (!prs_copy_data_in(&p->out_data.frag, pad, pad_len)) {
				DEBUG(0, ("api_pipe_bind_req: failed to add "
					  "%u bytes of pad data.\n",
				  (unsigned int)pad_len));
				goto err_exit;
			}
		}

		if (!prs_copy_data_in(&p->out_data.frag,
					(char *)auth_blob.data,
					auth_blob.length)) {
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
	TALLOC_FREE(blob.data);
	return True;

  err_exit:

	prs_mem_free(&p->out_data.frag);
	TALLOC_FREE(auth_blob.data);
	TALLOC_FREE(blob.data);
	return setup_bind_nak(p, pkt);
}

/****************************************************************************
 Deal with an alter context call. Can be third part of 3 leg auth request for
 SPNEGO calls.
****************************************************************************/

bool api_pipe_alter_context(pipes_struct *p, struct ncacn_packet *pkt)
{
	RPC_HDR hdr;
	RPC_HDR_BA hdr_ba;
	struct dcerpc_auth auth_info;
	uint16 assoc_gid;
	fstring ack_pipe_name;
	prs_struct out_hdr_ba;
	prs_struct out_auth;
	int auth_len = 0;
	uint32_t ss_padding_len = 0;
	NTSTATUS status;

	prs_init_empty(&p->out_data.frag, p->mem_ctx, MARSHALL);

	/* 
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	/*
	 * Setup the memory to marshall the ba header, and the
	 * auth footers.
	 */

	if(!prs_init(&out_hdr_ba, 1024, p->mem_ctx, MARSHALL)) {
		DEBUG(0,("api_pipe_alter_context: malloc out_hdr_ba failed.\n"));
		prs_mem_free(&p->out_data.frag);
		return False;
	}

	if(!prs_init(&out_auth, 1024, p->mem_ctx, MARSHALL)) {
		DEBUG(0,("api_pipe_alter_context: malloc out_auth failed.\n"));
		prs_mem_free(&p->out_data.frag);
		prs_mem_free(&out_hdr_ba);
		return False;
	}

	/* secondary address CAN be NULL
	 * as the specs say it's ignored.
	 * It MUST be NULL to have the spoolss working.
	 */
	fstrcpy(ack_pipe_name,"");

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
		init_rpc_hdr_ba(&hdr_ba,
	                RPC_MAX_PDU_FRAG_LEN,
	                RPC_MAX_PDU_FRAG_LEN,
	                assoc_gid,
	                ack_pipe_name,
	                0x1, 0x0, 0x0,
	                &pkt->u.bind.ctx_list[0].transfer_syntaxes[0]);
	} else {
		/* Rejection reason: abstract syntax not supported */
		init_rpc_hdr_ba(&hdr_ba, RPC_MAX_PDU_FRAG_LEN,
					RPC_MAX_PDU_FRAG_LEN, assoc_gid,
					ack_pipe_name, 0x1, 0x2, 0x1,
					&null_ndr_syntax_id);
		p->pipe_bound = False;
	}

	/*
	 * and marshall it.
	 */

	if(!smb_io_rpc_hdr_ba("", &hdr_ba, &out_hdr_ba, 0)) {
		DEBUG(0,("api_pipe_alter_context: marshalling of RPC_HDR_BA failed.\n"));
		goto err_exit;
	}


	/*
	 * Check if this is an authenticated alter context request.
	 */

	if (pkt->auth_length != 0) {
		/* 
		 * Decode the authentication verifier.
		 */

		/* Work out any padding needed before the auth footer. */
		if ((RPC_HEADER_LEN + prs_offset(&out_hdr_ba)) % SERVER_NDR_PADDING_SIZE) {
			ss_padding_len = SERVER_NDR_PADDING_SIZE -
				((RPC_HEADER_LEN + prs_offset(&out_hdr_ba)) % SERVER_NDR_PADDING_SIZE);
			DEBUG(10,("api_pipe_alter_context: auth pad_len = %u\n",
				(unsigned int)ss_padding_len ));
		}

		/* Quick length check. Won't catch a bad auth footer,
		 * prevents overrun. */

		if (pkt->frag_length < RPC_HEADER_LEN +
					RPC_HDR_AUTH_LEN +
					pkt->auth_length) {
			DEBUG(0,("api_pipe_alter_context: auth_len (%u) "
				"too long for fragment %u.\n",
				(unsigned int)pkt->auth_length,
				(unsigned int)pkt->frag_length ));
			goto err_exit;
		}

		status = dcerpc_pull_dcerpc_auth(pkt,
						 &pkt->u.bind.auth_info,
						 &auth_info);
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
				if (!pipe_spnego_auth_bind_continue(p,
						    ss_padding_len,
						    &auth_info, &out_auth)) {
					goto err_exit;
				}
			} else {
				goto err_exit;
			}
		}
	} else {
		ZERO_STRUCT(auth_info);
	}
	/*
	 * Create the header, now we know the length.
	 */

	if (prs_offset(&out_auth)) {
		auth_len = prs_offset(&out_auth) - RPC_HDR_AUTH_LEN;
	}

	init_rpc_hdr(&hdr, DCERPC_PKT_ALTER_RESP, DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST,
			pkt->call_id,
			RPC_HEADER_LEN + prs_offset(&out_hdr_ba) + prs_offset(&out_auth),
			auth_len);

	/*
	 * Marshall the header into the outgoing PDU.
	 */

	if(!smb_io_rpc_hdr("", &hdr, &p->out_data.frag, 0)) {
		DEBUG(0,("api_pipe_alter_context: marshalling of RPC_HDR failed.\n"));
		goto err_exit;
	}

	/*
	 * Now add the RPC_HDR_BA and any auth needed.
	 */

	if(!prs_append_prs_data(&p->out_data.frag, &out_hdr_ba)) {
		DEBUG(0,("api_pipe_alter_context: append of RPC_HDR_BA failed.\n"));
		goto err_exit;
	}

	if (auth_len) {
		if (ss_padding_len) {
			char pad[SERVER_NDR_PADDING_SIZE];
			memset(pad, '\0', SERVER_NDR_PADDING_SIZE);
			if (!prs_copy_data_in(&p->out_data.frag, pad,
					ss_padding_len)) {
				DEBUG(0,("api_pipe_alter_context: failed to add %u "
					"bytes of pad data.\n",
					(unsigned int)ss_padding_len));
				goto err_exit;
			}
		}

		if (!prs_append_prs_data( &p->out_data.frag, &out_auth)) {
			DEBUG(0,("api_pipe_alter_context: append of auth info failed.\n"));
			goto err_exit;
		}
	}

	/*
	 * Setup the lengths for the initial reply.
	 */

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_sent = 0;

	prs_mem_free(&out_hdr_ba);
	prs_mem_free(&out_auth);
	return True;

  err_exit:

	prs_mem_free(&p->out_data.frag);
	prs_mem_free(&out_hdr_ba);
	prs_mem_free(&out_auth);
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

static bool api_rpcTNP(pipes_struct *p, struct ncacn_packet *pkt,
		       const struct api_struct *api_rpc_cmds, int n_cmds);

/****************************************************************************
 Find the correct RPC function to call for this request.
 If the pipe is authenticated then become the correct UNIX user
 before doing the call.
****************************************************************************/

bool api_pipe_request(pipes_struct *p, struct ncacn_packet *pkt)
{
	bool ret = False;
	bool changed_user = False;
	PIPE_RPC_FNS *pipe_fns;

	if (p->pipe_bound &&
			((p->auth.auth_type == PIPE_AUTH_TYPE_NTLMSSP) ||
			 (p->auth.auth_type == PIPE_AUTH_TYPE_SPNEGO_NTLMSSP))) {
		if(!become_authenticated_pipe_user(p)) {
			prs_mem_free(&p->out_data.rdata);
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

static bool api_rpcTNP(pipes_struct *p, struct ncacn_packet *pkt,
		       const struct api_struct *api_rpc_cmds, int n_cmds)
{
	int fn_num;
	uint32 offset1, offset2;

	/* interpret the command */
	DEBUG(4,("api_rpcTNP: %s op 0x%x - ",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
		 pkt->u.request.opnum));

	if (DEBUGLEVEL >= 50) {
		fstring name;
		slprintf(name, sizeof(name)-1, "in_%s",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax));
		prs_dump(name, pkt->u.request.opnum, &p->in_data.data);
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

	offset1 = prs_offset(&p->out_data.rdata);

        DEBUG(6, ("api_rpc_cmds[%d].fn == %p\n", 
                fn_num, api_rpc_cmds[fn_num].fn));
	/* do the actual command */
	if(!api_rpc_cmds[fn_num].fn(p)) {
		DEBUG(0,("api_rpcTNP: %s: %s failed.\n",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
			 api_rpc_cmds[fn_num].name));
		prs_mem_free(&p->out_data.rdata);
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

	offset2 = prs_offset(&p->out_data.rdata);
	prs_set_offset(&p->out_data.rdata, offset1);
	if (DEBUGLEVEL >= 50) {
		fstring name;
		slprintf(name, sizeof(name)-1, "out_%s",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax));
		prs_dump(name, pkt->u.request.opnum, &p->out_data.rdata);
	}
	prs_set_offset(&p->out_data.rdata, offset2);

	DEBUG(5,("api_rpcTNP: called %s successfully\n",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));

	/* Check for buffer underflow in rpc parsing */

	if ((DEBUGLEVEL >= 10) && 
	    (prs_offset(&p->in_data.data) != prs_data_size(&p->in_data.data))) {
		size_t data_len = prs_data_size(&p->in_data.data) - prs_offset(&p->in_data.data);
		char *data = (char *)SMB_MALLOC(data_len);

		DEBUG(10, ("api_rpcTNP: rpc input buffer underflow (parse error?)\n"));
		if (data) {
			prs_uint8s(False, "", &p->in_data.data, 0, (unsigned char *)data, (uint32)data_len);
			SAFE_FREE(data);
		}

	}

	return True;
}
