/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998,
 *  Copyright (C) Jeremy Allison                    1999,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 *  in this version, which takes a "let's learn what's going on and
 *  get something running" approach, there is additional network
 *  traffic generated, but the code should be easier to understand...
 *
 *  ... if you read the docs.  or stare at packets for weeks on end.
 *
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*************************************************************
 HACK Alert!
 We need to transfer the session key from one rpc bind to the
 next. This is the way the netlogon schannel works.
**************************************************************/
struct dcinfo last_dcinfo;

static void NTLMSSPcalc_p( pipes_struct *p, unsigned char *data, int len)
{
    unsigned char *hash = p->ntlmssp_hash;
    unsigned char index_i = hash[256];
    unsigned char index_j = hash[257];
    int ind;

    for( ind = 0; ind < len; ind++) {
        unsigned char tc;
        unsigned char t;

        index_i++;
        index_j += hash[index_i];

        tc = hash[index_i];
        hash[index_i] = hash[index_j];
        hash[index_j] = tc;

        t = hash[index_i] + hash[index_j];
        data[ind] = data[ind] ^ hash[t];
    }

    hash[256] = index_i;
    hash[257] = index_j;
}

/*******************************************************************
 Generate the next PDU to be returned from the data in p->rdata. 
 We cheat here as this function doesn't handle the special auth
 footers of the authenticated bind response reply.
 ********************************************************************/

BOOL create_next_pdu(pipes_struct *p)
{
	RPC_HDR_RESP hdr_resp;
	BOOL auth_verify = ((p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SIGN) != 0);
	BOOL auth_seal   = ((p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SEAL) != 0);
	uint32 data_len;
	uint32 data_space_available;
	uint32 data_len_left;
	prs_struct outgoing_pdu;
	uint32 data_pos;

	/*
	 * If we're in the fault state, keep returning fault PDU's until
	 * the pipe gets closed. JRA.
	 */

	if(p->fault_state) {
		setup_fault_pdu(p, NT_STATUS(0x1c010002));
		return True;
	}

	memset((char *)&hdr_resp, '\0', sizeof(hdr_resp));

	/* Change the incoming request header to a response. */
	p->hdr.pkt_type = RPC_RESPONSE;

	/* Set up rpc header flags. */
	if (p->out_data.data_sent_length == 0)
		p->hdr.flags = RPC_FLG_FIRST;
	else
		p->hdr.flags = 0;

	/*
	 * Work out how much we can fit in a single PDU.
	 */

	data_space_available = sizeof(p->out_data.current_pdu) - RPC_HEADER_LEN - RPC_HDR_RESP_LEN;
	if(p->ntlmssp_auth_validated)
		data_space_available -= (RPC_HDR_AUTH_LEN + RPC_AUTH_NTLMSSP_CHK_LEN);

	if(p->netsec_auth_validated)
		data_space_available -= (RPC_HDR_AUTH_LEN + RPC_AUTH_NETSEC_CHK_LEN);

	/*
	 * The amount we send is the minimum of the available
	 * space and the amount left to send.
	 */

	data_len_left = prs_offset(&p->out_data.rdata) - p->out_data.data_sent_length;

	/*
	 * Ensure there really is data left to send.
	 */

	if(!data_len_left) {
		DEBUG(0,("create_next_pdu: no data left to send !\n"));
		return False;
	}

	data_len = MIN(data_len_left, data_space_available);

	/*
	 * Set up the alloc hint. This should be the data left to
	 * send.
	 */

	hdr_resp.alloc_hint = data_len_left;

	/*
	 * Set up the header lengths.
	 */

	if (p->ntlmssp_auth_validated) {
		p->hdr.frag_len = RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len +
					RPC_HDR_AUTH_LEN + RPC_AUTH_NTLMSSP_CHK_LEN;
		p->hdr.auth_len = RPC_AUTH_NTLMSSP_CHK_LEN;
	} else if (p->netsec_auth_validated) {
		p->hdr.frag_len = RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len +
			RPC_HDR_AUTH_LEN + RPC_AUTH_NETSEC_CHK_LEN;
		p->hdr.auth_len = RPC_AUTH_NETSEC_CHK_LEN;
	} else {
		p->hdr.frag_len = RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len;
		p->hdr.auth_len = 0;
	}

	/*
	 * Work out if this PDU will be the last.
	 */

	if(p->out_data.data_sent_length + data_len >= prs_offset(&p->out_data.rdata))
		p->hdr.flags |= RPC_FLG_LAST;

	/*
	 * Init the parse struct to point at the outgoing
	 * data.
	 */

	prs_init( &outgoing_pdu, 0, p->mem_ctx, MARSHALL);
	prs_give_memory( &outgoing_pdu, (char *)p->out_data.current_pdu, sizeof(p->out_data.current_pdu), False);

	/* Store the header in the data stream. */
	if(!smb_io_rpc_hdr("hdr", &p->hdr, &outgoing_pdu, 0)) {
		DEBUG(0,("create_next_pdu: failed to marshall RPC_HDR.\n"));
		prs_mem_free(&outgoing_pdu);
		return False;
	}

	if(!smb_io_rpc_hdr_resp("resp", &hdr_resp, &outgoing_pdu, 0)) {
		DEBUG(0,("create_next_pdu: failed to marshall RPC_HDR_RESP.\n"));
		prs_mem_free(&outgoing_pdu);
		return False;
	}

	/* Store the current offset. */
	data_pos = prs_offset(&outgoing_pdu);

	/* Copy the data into the PDU. */

	if(!prs_append_some_prs_data(&outgoing_pdu, &p->out_data.rdata, p->out_data.data_sent_length, data_len)) {
		DEBUG(0,("create_next_pdu: failed to copy %u bytes of data.\n", (unsigned int)data_len));
		prs_mem_free(&outgoing_pdu);
		return False;
	}

	if (p->ntlmssp_auth_validated) {
		uint32 crc32 = 0;
		char *data;

		DEBUG(5,("create_next_pdu: sign: %s seal: %s data %d auth %d\n",
			 BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, p->hdr.auth_len));

		/*
		 * Set data to point to where we copied the data into.
		 */

		data = prs_data_p(&outgoing_pdu) + data_pos;

		if (auth_seal) {
			crc32 = crc32_calc_buffer(data, data_len);
			NTLMSSPcalc_p(p, (uchar*)data, data_len);
		}

		if (auth_seal || auth_verify) {
			RPC_HDR_AUTH auth_info;

			init_rpc_hdr_auth(&auth_info, NTLMSSP_AUTH_TYPE, auth_info.auth_level,
					(auth_verify ? RPC_HDR_AUTH_LEN : 0), (auth_verify ? 1 : 0));
			if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &outgoing_pdu, 0)) {
				DEBUG(0,("create_next_pdu: failed to marshall RPC_HDR_AUTH.\n"));
				prs_mem_free(&outgoing_pdu);
				return False;
			}
		}

		if (auth_verify) {
			RPC_AUTH_NTLMSSP_CHK ntlmssp_chk;
			char *auth_data = prs_data_p(&outgoing_pdu);

			p->ntlmssp_seq_num++;
			init_rpc_auth_ntlmssp_chk(&ntlmssp_chk, NTLMSSP_SIGN_VERSION,
					crc32, p->ntlmssp_seq_num++);
			auth_data = prs_data_p(&outgoing_pdu) + prs_offset(&outgoing_pdu) + 4;
			if(!smb_io_rpc_auth_ntlmssp_chk("auth_sign", &ntlmssp_chk, &outgoing_pdu, 0)) {
				DEBUG(0,("create_next_pdu: failed to marshall RPC_AUTH_NTLMSSP_CHK.\n"));
				prs_mem_free(&outgoing_pdu);
				return False;
			}
			NTLMSSPcalc_p(p, (uchar*)auth_data, RPC_AUTH_NTLMSSP_CHK_LEN - 4);
		}
	}

	if (p->netsec_auth_validated) {
		int auth_type, auth_level;
		char *data;
		RPC_HDR_AUTH auth_info;

		RPC_AUTH_NETSEC_CHK verf;
		prs_struct rverf;
		prs_struct rauth;

		data = prs_data_p(&outgoing_pdu) + data_pos;
		/* Check it's the type of reply we were expecting to decode */

		get_auth_type_level(p->netsec_auth.auth_flags, &auth_type, &auth_level);
		init_rpc_hdr_auth(&auth_info, auth_type, auth_level, 
				  RPC_HDR_AUTH_LEN, 1);

		if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &outgoing_pdu, 0)) {
			DEBUG(0,("create_next_pdu: failed to marshall RPC_HDR_AUTH.\n"));
			prs_mem_free(&outgoing_pdu);
			return False;
		}

		prs_init(&rverf, 0, p->mem_ctx, MARSHALL);
		prs_init(&rauth, 0, p->mem_ctx, MARSHALL);

		netsec_encode(&p->netsec_auth, 
			      p->netsec_auth.auth_flags,
			      SENDER_IS_ACCEPTOR,
			      &verf, data, data_len);

		smb_io_rpc_auth_netsec_chk("", &verf, &outgoing_pdu, 0);

		p->netsec_auth.seq_num++;
	}

	/*
	 * Setup the counts for this PDU.
	 */

	p->out_data.data_sent_length += data_len;
	p->out_data.current_pdu_len = p->hdr.frag_len;
	p->out_data.current_pdu_sent = 0;

	prs_mem_free(&outgoing_pdu);
	return True;
}

/*******************************************************************
 Process an NTLMSSP authentication response.
 If this function succeeds, the user has been authenticated
 and their domain, name and calling workstation stored in
 the pipe struct.
 The initial challenge is stored in p->challenge.
 *******************************************************************/

static BOOL api_pipe_ntlmssp_verify(pipes_struct *p, RPC_AUTH_NTLMSSP_RESP *ntlmssp_resp)
{
	uchar lm_owf[24];
	uchar nt_owf[128];
	int nt_pw_len;
	int lm_pw_len;
	fstring user_name;
	fstring domain;
	fstring wks;

	NTSTATUS nt_status;

	struct auth_context *auth_context = NULL;
	auth_usersupplied_info *user_info = NULL;
	auth_serversupplied_info *server_info = NULL;

	DEBUG(5,("api_pipe_ntlmssp_verify: checking user details\n"));

	memset(p->user_name, '\0', sizeof(p->user_name));
	memset(p->pipe_user_name, '\0', sizeof(p->pipe_user_name));
	memset(p->domain, '\0', sizeof(p->domain));
	memset(p->wks, '\0', sizeof(p->wks));

	/* Set up for non-authenticated user. */
	delete_nt_token(&p->pipe_user.nt_user_token);
	p->pipe_user.ngroups = 0;
	SAFE_FREE( p->pipe_user.groups);

	/* 
	 * Setup an empty password for a guest user.
	 */

	/*
	 * We always negotiate UNICODE.
	 */

	if (p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		rpcstr_pull(user_name, ntlmssp_resp->user, sizeof(fstring), ntlmssp_resp->hdr_usr.str_str_len*2, 0 );
		rpcstr_pull(domain, ntlmssp_resp->domain, sizeof(fstring), ntlmssp_resp->hdr_domain.str_str_len*2, 0);
		rpcstr_pull(wks, ntlmssp_resp->wks, sizeof(fstring), ntlmssp_resp->hdr_wks.str_str_len*2, 0);
	} else {
		pull_ascii_fstring(user_name, ntlmssp_resp->user);
		pull_ascii_fstring(domain, ntlmssp_resp->domain);
		pull_ascii_fstring(wks, ntlmssp_resp->wks);
	}

	DEBUG(5,("user: %s domain: %s wks: %s\n", user_name, domain, wks));

	nt_pw_len = MIN(sizeof(nt_owf), ntlmssp_resp->hdr_nt_resp.str_str_len);
	lm_pw_len = MIN(sizeof(lm_owf), ntlmssp_resp->hdr_lm_resp.str_str_len);

	memcpy(lm_owf, ntlmssp_resp->lm_resp, sizeof(lm_owf));
	memcpy(nt_owf, ntlmssp_resp->nt_resp, nt_pw_len);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm, nt owfs, chal\n"));
	dump_data(100, (char *)lm_owf, sizeof(lm_owf));
	dump_data(100, (char *)nt_owf, nt_pw_len);
	dump_data(100, (char *)p->challenge, 8);
#endif

	/*
	 * Allow guest access. Patch from Shirish Kalele <kalele@veritas.com>.
	 */

	if (*user_name) {

	 	/* 
		 * Do the length checking only if user is not NULL.
		 */

 		if (ntlmssp_resp->hdr_lm_resp.str_str_len == 0)
 			return False;
 		if (ntlmssp_resp->hdr_nt_resp.str_str_len == 0)
 			return False;
 		if (ntlmssp_resp->hdr_usr.str_str_len == 0)
 			return False;
 		if (ntlmssp_resp->hdr_domain.str_str_len == 0)
 			return False;
 		if (ntlmssp_resp->hdr_wks.str_str_len == 0)
 			return False;

	}
	
	make_auth_context_fixed(&auth_context, (uchar*)p->challenge);

	if (!make_user_info_netlogon_network(&user_info, 
					     user_name, domain, wks,
					     lm_owf, lm_pw_len, 
					     nt_owf, nt_pw_len)) {
		DEBUG(0,("make_user_info_netlogon_network failed!  Failing authenticaion.\n"));
		return False;
	}
	
	nt_status = auth_context->check_ntlm_password(auth_context, user_info, &server_info); 
	
	(auth_context->free)(&auth_context);
	free_user_info(&user_info);
	
	p->ntlmssp_auth_validated = NT_STATUS_IS_OK(nt_status);
	
	if (!p->ntlmssp_auth_validated) {
		DEBUG(1,("api_pipe_ntlmssp_verify: User [%s]\\[%s] from machine %s \
failed authentication on named pipe %s.\n", domain, user_name, wks, p->name ));
		free_server_info(&server_info);
		return False;
	}

	/*
	 * Set up the sign/seal data.
	 */

	if (server_info->lm_session_key.length != 16) {
		DEBUG(1,("api_pipe_ntlmssp_verify: User [%s]\\[%s] from machine %s \
succeeded authentication on named pipe %s, but session key was of incorrect length [%u].\n", 
			 domain, user_name, wks, p->name, server_info->lm_session_key.length));
		free_server_info(&server_info);
		return False;
	} else {
		uchar p24[24];
		NTLMSSPOWFencrypt(server_info->lm_session_key.data, lm_owf, p24);
		{
			unsigned char j = 0;
			int ind;

			unsigned char k2[8];

			memcpy(k2, p24, 5);
			k2[5] = 0xe5;
			k2[6] = 0x38;
			k2[7] = 0xb0;

			for (ind = 0; ind < 256; ind++)
				p->ntlmssp_hash[ind] = (unsigned char)ind;

			for( ind = 0; ind < 256; ind++) {
				unsigned char tc;

				j += (p->ntlmssp_hash[ind] + k2[ind%8]);

				tc = p->ntlmssp_hash[ind];
				p->ntlmssp_hash[ind] = p->ntlmssp_hash[j];
				p->ntlmssp_hash[j] = tc;
			}

			p->ntlmssp_hash[256] = 0;
			p->ntlmssp_hash[257] = 0;
		}

		dump_data_pw("NTLMSSP hash (v1)\n", p->ntlmssp_hash, 
			     sizeof(p->ntlmssp_hash));

/*		NTLMSSPhash(p->ntlmssp_hash, p24); */
		p->ntlmssp_seq_num = 0;

	}

	fstrcpy(p->user_name, user_name);
	fstrcpy(p->pipe_user_name, server_info->unix_name);
	fstrcpy(p->domain, domain);
	fstrcpy(p->wks, wks);

	/*
	 * Store the UNIX credential data (uid/gid pair) in the pipe structure.
	 */

	p->session_key = data_blob(server_info->lm_session_key.data, server_info->lm_session_key.length);

	p->pipe_user.uid = server_info->uid;
	p->pipe_user.gid = server_info->gid;
	
	p->pipe_user.ngroups = server_info->n_groups;
	if (p->pipe_user.ngroups) {
		if (!(p->pipe_user.groups = memdup(server_info->groups, sizeof(gid_t) * p->pipe_user.ngroups))) {
			DEBUG(0,("failed to memdup group list to p->pipe_user.groups\n"));
			free_server_info(&server_info);
			return False;
		}
	}

	if (server_info->ptok)
		p->pipe_user.nt_user_token = dup_nt_token(server_info->ptok);
	else {
		DEBUG(1,("Error: Authmodule failed to provide nt_user_token\n"));
		p->pipe_user.nt_user_token = NULL;
		free_server_info(&server_info);
		return False;
	}

	p->ntlmssp_auth_validated = True;

	free_server_info(&server_info);
	return True;
}

/*******************************************************************
 The switch table for the pipe names and the functions to handle them.
 *******************************************************************/

struct rpc_table
{
  struct
  {
    const char *clnt;
    const char *srv;
  } pipe;
  struct api_struct *cmds;
  int n_cmds;
};

static struct rpc_table *rpc_lookup;
static int rpc_lookup_size;

/*******************************************************************
 This is the client reply to our challenge for an authenticated 
 bind request. The challenge we sent is in p->challenge.
*******************************************************************/

BOOL api_pipe_bind_auth_resp(pipes_struct *p, prs_struct *rpc_in_p)
{
	RPC_HDR_AUTHA autha_info;
	RPC_AUTH_VERIFIER auth_verifier;
	RPC_AUTH_NTLMSSP_RESP ntlmssp_resp;

	DEBUG(5,("api_pipe_bind_auth_resp: decode request. %d\n", __LINE__));

	if (p->hdr.auth_len == 0) {
		DEBUG(0,("api_pipe_bind_auth_resp: No auth field sent !\n"));
		return False;
	}

	/*
	 * Decode the authentication verifier response.
	 */

	if(!smb_io_rpc_hdr_autha("", &autha_info, rpc_in_p, 0)) {
		DEBUG(0,("api_pipe_bind_auth_resp: unmarshall of RPC_HDR_AUTHA failed.\n"));
		return False;
	}

	if (autha_info.auth_type != NTLMSSP_AUTH_TYPE || autha_info.auth_level != RPC_PIPE_AUTH_SEAL_LEVEL) {
		DEBUG(0,("api_pipe_bind_auth_resp: incorrect auth type (%d) or level (%d).\n",
			(int)autha_info.auth_type, (int)autha_info.auth_level ));
		return False;
	}

	if(!smb_io_rpc_auth_verifier("", &auth_verifier, rpc_in_p, 0)) {
		DEBUG(0,("api_pipe_bind_auth_resp: unmarshall of RPC_AUTH_VERIFIER failed.\n"));
		return False;
	}

	/*
	 * Ensure this is a NTLMSSP_AUTH packet type.
	 */

	if (!rpc_auth_verifier_chk(&auth_verifier, "NTLMSSP", NTLMSSP_AUTH)) {
		DEBUG(0,("api_pipe_bind_auth_resp: rpc_auth_verifier_chk failed.\n"));
		return False;
	}

	if(!smb_io_rpc_auth_ntlmssp_resp("", &ntlmssp_resp, rpc_in_p, 0)) {
		DEBUG(0,("api_pipe_bind_auth_resp: Failed to unmarshall RPC_AUTH_NTLMSSP_RESP.\n"));
		return False;
	}

	/*
	 * The following call actually checks the challenge/response data.
	 * for correctness against the given DOMAIN\user name.
	 */
	
	if (!api_pipe_ntlmssp_verify(p, &ntlmssp_resp))
		return False;

	p->pipe_bound = True
;
	return True;
}

/*******************************************************************
 Marshall a bind_nak pdu.
*******************************************************************/

static BOOL setup_bind_nak(pipes_struct *p)
{
	prs_struct outgoing_rpc;
	RPC_HDR nak_hdr;
	uint16 zero = 0;

	/* Free any memory in the current return data buffer. */
	prs_mem_free(&p->out_data.rdata);

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	prs_init( &outgoing_rpc, 0, p->mem_ctx, MARSHALL);
	prs_give_memory( &outgoing_rpc, (char *)p->out_data.current_pdu, sizeof(p->out_data.current_pdu), False);


	/*
	 * Initialize a bind_nak header.
	 */

	init_rpc_hdr(&nak_hdr, RPC_BINDNACK, RPC_FLG_FIRST | RPC_FLG_LAST,
            p->hdr.call_id, RPC_HEADER_LEN + sizeof(uint16), 0);

	/*
	 * Marshall the header into the outgoing PDU.
	 */

	if(!smb_io_rpc_hdr("", &nak_hdr, &outgoing_rpc, 0)) {
		DEBUG(0,("setup_bind_nak: marshalling of RPC_HDR failed.\n"));
		prs_mem_free(&outgoing_rpc);
		return False;
	}

	/*
	 * Now add the reject reason.
	 */

	if(!prs_uint16("reject code", &outgoing_rpc, 0, &zero)) {
		prs_mem_free(&outgoing_rpc);
        return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_len = prs_offset(&outgoing_rpc);
	p->out_data.current_pdu_sent = 0;

	p->pipe_bound = False;

	return True;
}

/*******************************************************************
 Marshall a fault pdu.
*******************************************************************/

BOOL setup_fault_pdu(pipes_struct *p, NTSTATUS status)
{
	prs_struct outgoing_pdu;
	RPC_HDR fault_hdr;
	RPC_HDR_RESP hdr_resp;
	RPC_HDR_FAULT fault_resp;

	/* Free any memory in the current return data buffer. */
	prs_mem_free(&p->out_data.rdata);

	/*
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	prs_init( &outgoing_pdu, 0, p->mem_ctx, MARSHALL);
	prs_give_memory( &outgoing_pdu, (char *)p->out_data.current_pdu, sizeof(p->out_data.current_pdu), False);

	/*
	 * Initialize a fault header.
	 */

	init_rpc_hdr(&fault_hdr, RPC_FAULT, RPC_FLG_FIRST | RPC_FLG_LAST | RPC_FLG_NOCALL,
            p->hdr.call_id, RPC_HEADER_LEN + RPC_HDR_RESP_LEN + RPC_HDR_FAULT_LEN, 0);

	/*
	 * Initialize the HDR_RESP and FAULT parts of the PDU.
	 */

	memset((char *)&hdr_resp, '\0', sizeof(hdr_resp));

	fault_resp.status = status;
	fault_resp.reserved = 0;

	/*
	 * Marshall the header into the outgoing PDU.
	 */

	if(!smb_io_rpc_hdr("", &fault_hdr, &outgoing_pdu, 0)) {
		DEBUG(0,("setup_fault_pdu: marshalling of RPC_HDR failed.\n"));
		prs_mem_free(&outgoing_pdu);
		return False;
	}

	if(!smb_io_rpc_hdr_resp("resp", &hdr_resp, &outgoing_pdu, 0)) {
		DEBUG(0,("setup_fault_pdu: failed to marshall RPC_HDR_RESP.\n"));
		prs_mem_free(&outgoing_pdu);
		return False;
	}

	if(!smb_io_rpc_hdr_fault("fault", &fault_resp, &outgoing_pdu, 0)) {
		DEBUG(0,("setup_fault_pdu: failed to marshall RPC_HDR_FAULT.\n"));
		prs_mem_free(&outgoing_pdu);
		return False;
	}

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_len = prs_offset(&outgoing_pdu);
	p->out_data.current_pdu_sent = 0;

	prs_mem_free(&outgoing_pdu);
	return True;
}

/*******************************************************************
 Ensure a bind request has the correct abstract & transfer interface.
 Used to reject unknown binds from Win2k.
*******************************************************************/

BOOL check_bind_req(struct pipes_struct *p, RPC_IFACE* abstract,
                    RPC_IFACE* transfer, uint32 context_id)
{
	extern struct pipe_id_info pipe_names[];
	char *pipe_name = p->name;
	int i=0;
	fstring pname;
	
	fstrcpy(pname,"\\PIPE\\");
	fstrcat(pname,pipe_name);

	DEBUG(3,("check_bind_req for %s\n", pname));

	/* we have to check all now since win2k introduced a new UUID on the lsaprpc pipe */
		
	for ( i=0; pipe_names[i].client_pipe; i++ ) 
	{
		if ( strequal(pipe_names[i].client_pipe, pname)
			&& (abstract->version == pipe_names[i].abstr_syntax.version) 
			&& (memcmp(&abstract->uuid, &pipe_names[i].abstr_syntax.uuid, sizeof(struct uuid)) == 0)
			&& (transfer->version == pipe_names[i].trans_syntax.version)
			&& (memcmp(&transfer->uuid, &pipe_names[i].trans_syntax.uuid, sizeof(struct uuid)) == 0) )
		{
			struct api_struct 	*fns = NULL;
			int 			n_fns = 0;
			PIPE_RPC_FNS		*context_fns;
			
			if ( !(context_fns = malloc(sizeof(PIPE_RPC_FNS))) ) {
				DEBUG(0,("check_bind_req: malloc() failed!\n"));
				return False;
			}
			
			/* save the RPC function table associated with this bind */
			
			get_pipe_fns(i, &fns, &n_fns);
			
			context_fns->cmds = fns;
			context_fns->n_cmds = n_fns;
			context_fns->context_id = context_id;
			
			/* add to the list of open contexts */
			
			DLIST_ADD( p->contexts, context_fns );
			
			break;
		}
	}

	if(pipe_names[i].client_pipe == NULL)
		return False;

	return True;
}

/*******************************************************************
 Register commands to an RPC pipe
*******************************************************************/
NTSTATUS rpc_pipe_register_commands(int version, const char *clnt, const char *srv, const struct api_struct *cmds, int size)
{
        struct rpc_table *rpc_entry;

	if (!clnt || !srv || !cmds) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (version != SMB_RPC_INTERFACE_VERSION) {
		DEBUG(0,("Can't register rpc commands!\n"
			 "You tried to register a rpc module with SMB_RPC_INTERFACE_VERSION %d"
			 ", while this version of samba uses version %d!\n", 
			 version,SMB_RPC_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	/* TODO: 
	 *
	 * we still need to make sure that don't register the same commands twice!!!
	 * 
	 * --metze
	 */

        /* We use a temporary variable because this call can fail and 
           rpc_lookup will still be valid afterwards.  It could then succeed if
           called again later */
        rpc_entry = realloc(rpc_lookup, 
                            ++rpc_lookup_size*sizeof(struct rpc_table));
        if (NULL == rpc_entry) {
                rpc_lookup_size--;
                DEBUG(0, ("rpc_pipe_register_commands: memory allocation failed\n"));
                return NT_STATUS_NO_MEMORY;
        } else {
                rpc_lookup = rpc_entry;
        }
        
        rpc_entry = rpc_lookup + (rpc_lookup_size - 1);
        ZERO_STRUCTP(rpc_entry);
        rpc_entry->pipe.clnt = strdup(clnt);
        rpc_entry->pipe.srv = strdup(srv);
        rpc_entry->cmds = realloc(rpc_entry->cmds, 
                                  (rpc_entry->n_cmds + size) *
                                  sizeof(struct api_struct));
        memcpy(rpc_entry->cmds + rpc_entry->n_cmds, cmds,
               size * sizeof(struct api_struct));
        rpc_entry->n_cmds += size;
        
        return NT_STATUS_OK;
}

/*******************************************************************
 Respond to a pipe bind request.
*******************************************************************/

BOOL api_pipe_bind_req(pipes_struct *p, prs_struct *rpc_in_p)
{
	RPC_HDR_BA hdr_ba;
	RPC_HDR_RB hdr_rb;
	RPC_HDR_AUTH auth_info;
	uint16 assoc_gid;
	fstring ack_pipe_name;
	prs_struct out_hdr_ba;
	prs_struct out_auth;
	prs_struct outgoing_rpc;
	int i = 0;
	int auth_len = 0;
	enum RPC_PKT_TYPE reply_pkt_type;

	p->ntlmssp_auth_requested = False;
	p->netsec_auth_validated = False;

	DEBUG(5,("api_pipe_bind_req: decode request. %d\n", __LINE__));

	/*
	 * Try and find the correct pipe name to ensure
	 * that this is a pipe name we support.
	 */


	for (i = 0; i < rpc_lookup_size; i++) {
	        if (strequal(rpc_lookup[i].pipe.clnt, p->name)) {
                  DEBUG(3, ("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
                            rpc_lookup[i].pipe.clnt, rpc_lookup[i].pipe.srv));
                  fstrcpy(p->pipe_srv_name, rpc_lookup[i].pipe.srv);
                  break;
                }
	}

	if (i == rpc_lookup_size) {
		if (NT_STATUS_IS_ERR(smb_probe_module("rpc", p->name))) {
                       DEBUG(3,("api_pipe_bind_req: Unknown pipe name %s in bind request.\n",
                                p->name ));
                       if(!setup_bind_nak(p))
                               return False;
                       return True;
                }

                for (i = 0; i < rpc_lookup_size; i++) {
                       if (strequal(rpc_lookup[i].pipe.clnt, p->name)) {
                               DEBUG(3, ("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
                                         rpc_lookup[i].pipe.clnt, rpc_lookup[i].pipe.srv));
                               fstrcpy(p->pipe_srv_name, rpc_lookup[i].pipe.srv);
                               break;
                       }
                }

		if (i == rpc_lookup_size) {
			DEBUG(0, ("module %s doesn't provide functions for pipe %s!\n", p->name, p->name));
			return False;
		}
	}

	/* decode the bind request */
	if(!smb_io_rpc_hdr_rb("", &hdr_rb, rpc_in_p, 0))  {
		DEBUG(0,("api_pipe_bind_req: unable to unmarshall RPC_HDR_RB struct.\n"));
		return False;
	}

	/*
	 * Check if this is an authenticated request.
	 */

	if (p->hdr.auth_len != 0) {
		RPC_AUTH_VERIFIER auth_verifier;
		RPC_AUTH_NTLMSSP_NEG ntlmssp_neg;

		/* 
		 * Decode the authentication verifier.
		 */

		if(!smb_io_rpc_hdr_auth("", &auth_info, rpc_in_p, 0)) {
			DEBUG(0,("api_pipe_bind_req: unable to unmarshall RPC_HDR_AUTH struct.\n"));
			return False;
		}

		if(auth_info.auth_type == NTLMSSP_AUTH_TYPE) {

			if(!smb_io_rpc_auth_verifier("", &auth_verifier, rpc_in_p, 0)) {
				DEBUG(0,("api_pipe_bind_req: unable to "
					 "unmarshall RPC_HDR_AUTH struct.\n"));
				return False;
			}

			if(!strequal(auth_verifier.signature, "NTLMSSP")) {
				DEBUG(0,("api_pipe_bind_req: "
					 "auth_verifier.signature != NTLMSSP\n"));
				return False;
			}

			if(auth_verifier.msg_type != NTLMSSP_NEGOTIATE) {
				DEBUG(0,("api_pipe_bind_req: "
					 "auth_verifier.msg_type (%d) != NTLMSSP_NEGOTIATE\n",
					 auth_verifier.msg_type));
				return False;
			}

			if(!smb_io_rpc_auth_ntlmssp_neg("", &ntlmssp_neg, rpc_in_p, 0)) {
				DEBUG(0,("api_pipe_bind_req: "
					 "Failed to unmarshall RPC_AUTH_NTLMSSP_NEG.\n"));
				return False;
			}

			p->ntlmssp_chal_flags = SMBD_NTLMSSP_NEG_FLAGS;
			p->ntlmssp_auth_requested = True;

		} else if (auth_info.auth_type == NETSEC_AUTH_TYPE) {

			RPC_AUTH_NETSEC_NEG neg;
			struct netsec_auth_struct *a = &(p->netsec_auth);

			if (!smb_io_rpc_auth_netsec_neg("", &neg, rpc_in_p, 0)) {
				DEBUG(0,("api_pipe_bind_req: "
					 "Could not unmarshal SCHANNEL auth neg\n"));
				return False;
			}

			p->netsec_auth_validated = True;

			memset(a->sess_key, 0, sizeof(a->sess_key));
			memcpy(a->sess_key, last_dcinfo.sess_key, sizeof(last_dcinfo.sess_key));

			a->seq_num = 0;

			DEBUG(10,("schannel auth: domain [%s] myname [%s]\n",
				  neg.domain, neg.myname));

		} else {
			DEBUG(0,("api_pipe_bind_req: unknown auth type %x requested.\n",
				 auth_info.auth_type ));
			return False;
		}
	}

	switch(p->hdr.pkt_type) {
		case RPC_BIND:
			/* name has to be \PIPE\xxxxx */
			fstrcpy(ack_pipe_name, "\\PIPE\\");
			fstrcat(ack_pipe_name, p->pipe_srv_name);
			reply_pkt_type = RPC_BINDACK;
			break;
		case RPC_ALTCONT:
			/* secondary address CAN be NULL
			 * as the specs say it's ignored.
			 * It MUST NULL to have the spoolss working.
			 */
			fstrcpy(ack_pipe_name,"");
			reply_pkt_type = RPC_ALTCONTRESP;
			break;
		default:
			return False;
	}

	DEBUG(5,("api_pipe_bind_req: make response. %d\n", __LINE__));

	/* 
	 * Marshall directly into the outgoing PDU space. We
	 * must do this as we need to set to the bind response
	 * header and are never sending more than one PDU here.
	 */

	prs_init( &outgoing_rpc, 0, p->mem_ctx, MARSHALL);
	prs_give_memory( &outgoing_rpc, (char *)p->out_data.current_pdu, sizeof(p->out_data.current_pdu), False);

	/*
	 * Setup the memory to marshall the ba header, and the
	 * auth footers.
	 */

	if(!prs_init(&out_hdr_ba, 1024, p->mem_ctx, MARSHALL)) {
		DEBUG(0,("api_pipe_bind_req: malloc out_hdr_ba failed.\n"));
		prs_mem_free(&outgoing_rpc);
		return False;
	}

	if(!prs_init(&out_auth, 1024, p->mem_ctx, MARSHALL)) {
		DEBUG(0,("pi_pipe_bind_req: malloc out_auth failed.\n"));
		prs_mem_free(&outgoing_rpc);
		prs_mem_free(&out_hdr_ba);
		return False;
	}

	if (p->ntlmssp_auth_requested)
		assoc_gid = 0x7a77;
	else
		assoc_gid = hdr_rb.bba.assoc_gid ? hdr_rb.bba.assoc_gid : 0x53f0;

	/*
	 * Create the bind response struct.
	 */

	/* If the requested abstract synt uuid doesn't match our client pipe,
		reject the bind_ack & set the transfer interface synt to all 0's,
		ver 0 (observed when NT5 attempts to bind to abstract interfaces
		unknown to NT4)
		Needed when adding entries to a DACL from NT5 - SK */

	if(check_bind_req(p, &hdr_rb.abstract, &hdr_rb.transfer, hdr_rb.context_id )) 
	{
		init_rpc_hdr_ba(&hdr_ba,
	                MAX_PDU_FRAG_LEN,
	                MAX_PDU_FRAG_LEN,
	                assoc_gid,
	                ack_pipe_name,
	                0x1, 0x0, 0x0,
	                &hdr_rb.transfer);
	} else {
		RPC_IFACE null_interface;
		ZERO_STRUCT(null_interface);
		/* Rejection reason: abstract syntax not supported */
		init_rpc_hdr_ba(&hdr_ba, MAX_PDU_FRAG_LEN,
					MAX_PDU_FRAG_LEN, assoc_gid,
					ack_pipe_name, 0x1, 0x2, 0x1,
					&null_interface);
	}

	/*
	 * and marshall it.
	 */

	if(!smb_io_rpc_hdr_ba("", &hdr_ba, &out_hdr_ba, 0)) {
		DEBUG(0,("api_pipe_bind_req: marshalling of RPC_HDR_BA failed.\n"));
		goto err_exit;
	}

	/*
	 * Now the authentication.
	 */

	if (p->ntlmssp_auth_requested) {
		RPC_AUTH_VERIFIER auth_verifier;
		RPC_AUTH_NTLMSSP_CHAL ntlmssp_chal;

		generate_random_buffer(p->challenge, 8, False);

		/*** Authentication info ***/

		init_rpc_hdr_auth(&auth_info, NTLMSSP_AUTH_TYPE, RPC_PIPE_AUTH_SEAL_LEVEL, RPC_HDR_AUTH_LEN, 1);
		if(!smb_io_rpc_hdr_auth("", &auth_info, &out_auth, 0)) {
			DEBUG(0,("api_pipe_bind_req: marshalling of RPC_HDR_AUTH failed.\n"));
			goto err_exit;
		}

		/*** NTLMSSP verifier ***/

		init_rpc_auth_verifier(&auth_verifier, "NTLMSSP", NTLMSSP_CHALLENGE);
		if(!smb_io_rpc_auth_verifier("", &auth_verifier, &out_auth, 0)) {
			DEBUG(0,("api_pipe_bind_req: marshalling of RPC_AUTH_VERIFIER failed.\n"));
			goto err_exit;
		}

		/* NTLMSSP challenge ***/

		init_rpc_auth_ntlmssp_chal(&ntlmssp_chal, p->ntlmssp_chal_flags, p->challenge);
		if(!smb_io_rpc_auth_ntlmssp_chal("", &ntlmssp_chal, &out_auth, 0)) {
			DEBUG(0,("api_pipe_bind_req: marshalling of RPC_AUTH_NTLMSSP_CHAL failed.\n"));
			goto err_exit;
		}

		/* Auth len in the rpc header doesn't include auth_header. */
		auth_len = prs_offset(&out_auth) - RPC_HDR_AUTH_LEN;
	}

	if (p->netsec_auth_validated) {
		RPC_AUTH_VERIFIER auth_verifier;
		uint32 flags;

		/* The client opens a second RPC NETLOGON pipe without
                   doing a auth2. The credentials for the schannel are
                   re-used from the auth2 the client did before. */
		p->dc = last_dcinfo;

		init_rpc_hdr_auth(&auth_info, NETSEC_AUTH_TYPE, auth_info.auth_level, RPC_HDR_AUTH_LEN, 1);
		if(!smb_io_rpc_hdr_auth("", &auth_info, &out_auth, 0)) {
			DEBUG(0,("api_pipe_bind_req: marshalling of RPC_HDR_AUTH failed.\n"));
			goto err_exit;
		}

		/*** NETSEC verifier ***/

		init_rpc_auth_verifier(&auth_verifier, "\001", 0x0);
		if(!smb_io_rpc_netsec_verifier("", &auth_verifier, &out_auth, 0)) {
			DEBUG(0,("api_pipe_bind_req: marshalling of RPC_AUTH_VERIFIER failed.\n"));
			goto err_exit;
		}

		prs_align(&out_auth);

		flags = 5;
		if(!prs_uint32("flags ", &out_auth, 0, &flags))
			goto err_exit;

		auth_len = prs_offset(&out_auth) - RPC_HDR_AUTH_LEN;
	}

	/*
	 * Create the header, now we know the length.
	 */

	init_rpc_hdr(&p->hdr, reply_pkt_type, RPC_FLG_FIRST | RPC_FLG_LAST,
			p->hdr.call_id,
			RPC_HEADER_LEN + prs_offset(&out_hdr_ba) + prs_offset(&out_auth),
			auth_len);

	/*
	 * Marshall the header into the outgoing PDU.
	 */

	if(!smb_io_rpc_hdr("", &p->hdr, &outgoing_rpc, 0)) {
		DEBUG(0,("pi_pipe_bind_req: marshalling of RPC_HDR failed.\n"));
		goto err_exit;
	}

	/*
	 * Now add the RPC_HDR_BA and any auth needed.
	 */

	if(!prs_append_prs_data( &outgoing_rpc, &out_hdr_ba)) {
		DEBUG(0,("api_pipe_bind_req: append of RPC_HDR_BA failed.\n"));
		goto err_exit;
	}

	if((p->ntlmssp_auth_requested|p->netsec_auth_validated) &&
	   !prs_append_prs_data( &outgoing_rpc, &out_auth)) {
		DEBUG(0,("api_pipe_bind_req: append of auth info failed.\n"));
		goto err_exit;
	}

	if(!p->ntlmssp_auth_requested)
		p->pipe_bound = True;

	/*
	 * Setup the lengths for the initial reply.
	 */

	p->out_data.data_sent_length = 0;
	p->out_data.current_pdu_len = prs_offset(&outgoing_rpc);
	p->out_data.current_pdu_sent = 0;

	prs_mem_free(&out_hdr_ba);
	prs_mem_free(&out_auth);

	return True;

  err_exit:

	prs_mem_free(&outgoing_rpc);
	prs_mem_free(&out_hdr_ba);
	prs_mem_free(&out_auth);
	return False;
}

/****************************************************************************
 Deal with sign & seal processing on an RPC request.
****************************************************************************/

BOOL api_pipe_auth_process(pipes_struct *p, prs_struct *rpc_in)
{
	/*
	 * We always negotiate the following two bits....
	 */
	BOOL auth_verify = ((p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SIGN) != 0);
	BOOL auth_seal   = ((p->ntlmssp_chal_flags & NTLMSSP_NEGOTIATE_SEAL) != 0);
	int data_len;
	int auth_len;
	uint32 old_offset;
	uint32 crc32 = 0;

	auth_len = p->hdr.auth_len;

	if ((auth_len != RPC_AUTH_NTLMSSP_CHK_LEN) && auth_verify) {
		DEBUG(0,("api_pipe_auth_process: Incorrect auth_len %d.\n", auth_len ));
		return False;
	}

	/*
	 * The following is that length of the data we must verify or unseal.
	 * This doesn't include the RPC headers or the auth_len or the RPC_HDR_AUTH_LEN
	 * preceeding the auth_data.
	 */

	data_len = p->hdr.frag_len - RPC_HEADER_LEN - RPC_HDR_REQ_LEN - 
			(auth_verify ? RPC_HDR_AUTH_LEN : 0) - auth_len;
	
	DEBUG(5,("api_pipe_auth_process: sign: %s seal: %s data %d auth %d\n",
	         BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, auth_len));

	if (auth_seal) {
		/*
		 * The data in rpc_in doesn't contain the RPC_HEADER as this
		 * has already been consumed.
		 */
		char *data = prs_data_p(rpc_in) + RPC_HDR_REQ_LEN;
		dump_data_pw("NTLMSSP hash (v1)\n", p->ntlmssp_hash, 
			     sizeof(p->ntlmssp_hash));

		dump_data_pw("Incoming RPC PDU (NTLMSSP sealed)\n", 
			     (const unsigned char *)data, data_len);
		NTLMSSPcalc_p(p, (uchar*)data, data_len);
		dump_data_pw("Incoming RPC PDU (NTLMSSP unsealed)\n", 
			     (const unsigned char *)data, data_len);
		crc32 = crc32_calc_buffer(data, data_len);
	}

	old_offset = prs_offset(rpc_in);

	if (auth_seal || auth_verify) {
		RPC_HDR_AUTH auth_info;

		if(!prs_set_offset(rpc_in, old_offset + data_len)) {
			DEBUG(0,("api_pipe_auth_process: cannot move offset to %u.\n",
				(unsigned int)old_offset + data_len ));
			return False;
		}

		if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, rpc_in, 0)) {
			DEBUG(0,("api_pipe_auth_process: failed to unmarshall RPC_HDR_AUTH.\n"));
			return False;
		}
	}

	if (auth_verify) {
		RPC_AUTH_NTLMSSP_CHK ntlmssp_chk;
		char *req_data = prs_data_p(rpc_in) + prs_offset(rpc_in) + 4;

		DEBUG(5,("api_pipe_auth_process: auth %d\n", prs_offset(rpc_in) + 4));

		/*
		 * Ensure we have RPC_AUTH_NTLMSSP_CHK_LEN - 4 more bytes in the
		 * incoming buffer.
		 */
		if(prs_mem_get(rpc_in, RPC_AUTH_NTLMSSP_CHK_LEN - 4) == NULL) {
			DEBUG(0,("api_pipe_auth_process: missing %d bytes in buffer.\n",
				RPC_AUTH_NTLMSSP_CHK_LEN - 4 ));
			return False;
		}

		NTLMSSPcalc_p(p, (uchar*)req_data, RPC_AUTH_NTLMSSP_CHK_LEN - 4);
		if(!smb_io_rpc_auth_ntlmssp_chk("auth_sign", &ntlmssp_chk, rpc_in, 0)) {
			DEBUG(0,("api_pipe_auth_process: failed to unmarshall RPC_AUTH_NTLMSSP_CHK.\n"));
			return False;
		}

		if (!rpc_auth_ntlmssp_chk(&ntlmssp_chk, crc32, p->ntlmssp_seq_num)) {
			DEBUG(0,("api_pipe_auth_process: NTLMSSP check failed.\n"));
			return False;
		}
	}

	/*
	 * Return the current pointer to the data offset.
	 */

	if(!prs_set_offset(rpc_in, old_offset)) {
		DEBUG(0,("api_pipe_auth_process: failed to set offset back to %u\n",
			(unsigned int)old_offset ));
		return False;
	}

	return True;
}

/****************************************************************************
 Deal with schannel processing on an RPC request.
****************************************************************************/
BOOL api_pipe_netsec_process(pipes_struct *p, prs_struct *rpc_in)
{
	/*
	 * We always negotiate the following two bits....
	 */
	int data_len;
	int auth_len;
	uint32 old_offset;
	RPC_HDR_AUTH auth_info;
	RPC_AUTH_NETSEC_CHK netsec_chk;


	auth_len = p->hdr.auth_len;

	if (auth_len != RPC_AUTH_NETSEC_CHK_LEN) {
		DEBUG(0,("Incorrect auth_len %d.\n", auth_len ));
		return False;
	}

	/*
	 * The following is that length of the data we must verify or unseal.
	 * This doesn't include the RPC headers or the auth_len or the RPC_HDR_AUTH_LEN
	 * preceeding the auth_data.
	 */

	data_len = p->hdr.frag_len - RPC_HEADER_LEN - RPC_HDR_REQ_LEN - 
		RPC_HDR_AUTH_LEN - auth_len;
	
	DEBUG(5,("data %d auth %d\n", data_len, auth_len));

	old_offset = prs_offset(rpc_in);

	if(!prs_set_offset(rpc_in, old_offset + data_len)) {
		DEBUG(0,("cannot move offset to %u.\n",
			 (unsigned int)old_offset + data_len ));
		return False;
	}

	if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, rpc_in, 0)) {
		DEBUG(0,("failed to unmarshall RPC_HDR_AUTH.\n"));
		return False;
	}

	if (auth_info.auth_type != NETSEC_AUTH_TYPE) {
		DEBUG(0,("Invalid auth info %d on schannel\n",
			 auth_info.auth_type));
		return False;
	}

	if (auth_info.auth_level == RPC_PIPE_AUTH_SEAL_LEVEL) {
		p->netsec_auth.auth_flags = AUTH_PIPE_NETSEC|AUTH_PIPE_SIGN|AUTH_PIPE_SEAL;
	} else if (auth_info.auth_level == RPC_PIPE_AUTH_SIGN_LEVEL) {
		p->netsec_auth.auth_flags = AUTH_PIPE_NETSEC|AUTH_PIPE_SIGN;
	} else {
		DEBUG(0,("Invalid auth level %d on schannel\n",
			 auth_info.auth_level));
		return False;
	}

	if(!smb_io_rpc_auth_netsec_chk("", &netsec_chk, rpc_in, 0)) {
		DEBUG(0,("failed to unmarshal RPC_AUTH_NETSEC_CHK.\n"));
		return False;
	}

	if (!netsec_decode(&p->netsec_auth,
			   p->netsec_auth.auth_flags,
			   SENDER_IS_INITIATOR,
			   &netsec_chk,
			   prs_data_p(rpc_in)+old_offset, data_len)) {
		DEBUG(0,("failed to decode PDU\n"));
		return False;
	}

	/*
	 * Return the current pointer to the data offset.
	 */

	if(!prs_set_offset(rpc_in, old_offset)) {
		DEBUG(0,("failed to set offset back to %u\n",
			 (unsigned int)old_offset ));
		return False;
	}

	/* The sequence number gets incremented on both send and receive. */
	p->netsec_auth.seq_num++;

	return True;
}

/****************************************************************************
 Return a user struct for a pipe user.
****************************************************************************/

struct current_user *get_current_user(struct current_user *user, pipes_struct *p)
{
	if (p->ntlmssp_auth_validated) {
		memcpy(user, &p->pipe_user, sizeof(struct current_user));
	} else {
		extern struct current_user current_user;
		memcpy(user, &current_user, sizeof(struct current_user));
	}

	return user;
}

/****************************************************************************
 Find the set of RPC functions associated with this context_id
****************************************************************************/

static PIPE_RPC_FNS* find_pipe_fns_by_context( PIPE_RPC_FNS *list, uint32 context_id )
{
	PIPE_RPC_FNS *fns = NULL;
	PIPE_RPC_FNS *tmp = NULL;
	
	if ( !list ) {
		DEBUG(0,("find_pipe_fns_by_context: ERROR!  No context list for pipe!\n"));
		return NULL;
	}
	
	for (tmp=list; tmp; tmp=tmp->next ) {
		if ( tmp->context_id == context_id )
			break;
	}
	
	fns = tmp;
	
	return fns;
}

/****************************************************************************
 memory cleanup
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

/****************************************************************************
 Find the correct RPC function to call for this request.
 If the pipe is authenticated then become the correct UNIX user
 before doing the call.
****************************************************************************/

BOOL api_pipe_request(pipes_struct *p)
{
	BOOL ret = False;
	PIPE_RPC_FNS *pipe_fns;
	
	if (p->ntlmssp_auth_validated) {

		if(!become_authenticated_pipe_user(p)) {
			prs_mem_free(&p->out_data.rdata);
			return False;
		}
	}

	DEBUG(5, ("Requested \\PIPE\\%s\n", p->name));
	
	/* get the set of RPC functions for this context */
	
	pipe_fns = find_pipe_fns_by_context(p->contexts, p->hdr_req.context_id);
	
	if ( pipe_fns ) {
		set_current_rpc_talloc(p->mem_ctx);
		ret = api_rpcTNP(p, p->name, pipe_fns->cmds, pipe_fns->n_cmds);
		set_current_rpc_talloc(NULL);	
	}
	else {
		DEBUG(0,("api_pipe_request: No rpc function table associated with context [%d] on pipe [%s]\n",
			p->hdr_req.context_id, p->name));
	}

	if(p->ntlmssp_auth_validated)
		unbecome_authenticated_pipe_user();

	return ret;
}

/*******************************************************************
 Calls the underlying RPC function for a named pipe.
 ********************************************************************/

BOOL api_rpcTNP(pipes_struct *p, const char *rpc_name, 
		const struct api_struct *api_rpc_cmds, int n_cmds)
{
	int fn_num;
	fstring name;
	uint32 offset1, offset2;
 
	/* interpret the command */
	DEBUG(4,("api_rpcTNP: %s op 0x%x - ", rpc_name, p->hdr_req.opnum));

	slprintf(name, sizeof(name)-1, "in_%s", rpc_name);
	prs_dump(name, p->hdr_req.opnum, &p->in_data.data);

	for (fn_num = 0; fn_num < n_cmds; fn_num++) {
		if (api_rpc_cmds[fn_num].opnum == p->hdr_req.opnum && api_rpc_cmds[fn_num].fn != NULL) {
			DEBUG(3,("api_rpcTNP: rpc command: %s\n", api_rpc_cmds[fn_num].name));
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
		setup_fault_pdu(p, NT_STATUS(0x1c010002));
		return True;
	}

	offset1 = prs_offset(&p->out_data.rdata);

        DEBUG(6, ("api_rpc_cmds[%d].fn == %p\n", 
                fn_num, api_rpc_cmds[fn_num].fn));
	/* do the actual command */
	if(!api_rpc_cmds[fn_num].fn(p)) {
		DEBUG(0,("api_rpcTNP: %s: %s failed.\n", rpc_name, api_rpc_cmds[fn_num].name));
		prs_mem_free(&p->out_data.rdata);
		return False;
	}

	if (p->bad_handle_fault_state) {
		DEBUG(4,("api_rpcTNP: bad handle fault return.\n"));
		p->bad_handle_fault_state = False;
		setup_fault_pdu(p, NT_STATUS(0x1C00001A));
		return True;
	}

	slprintf(name, sizeof(name)-1, "out_%s", rpc_name);
	offset2 = prs_offset(&p->out_data.rdata);
	prs_set_offset(&p->out_data.rdata, offset1);
	prs_dump(name, p->hdr_req.opnum, &p->out_data.rdata);
	prs_set_offset(&p->out_data.rdata, offset2);

	DEBUG(5,("api_rpcTNP: called %s successfully\n", rpc_name));

	/* Check for buffer underflow in rpc parsing */

	if ((DEBUGLEVEL >= 10) && 
	    (prs_offset(&p->in_data.data) != prs_data_size(&p->in_data.data))) {
		size_t data_len = prs_data_size(&p->in_data.data) - prs_offset(&p->in_data.data);
		char *data;

		data = malloc(data_len);

		DEBUG(10, ("api_rpcTNP: rpc input buffer underflow (parse error?)\n"));
		if (data) {
			prs_uint8s(False, "", &p->in_data.data, 0, (unsigned char *)data, (uint32)data_len);
			SAFE_FREE(data);
		}

	}

	return True;
}

/*******************************************************************
*******************************************************************/

void get_pipe_fns( int idx, struct api_struct **fns, int *n_fns )
{
	struct api_struct *cmds = NULL;
	int               n_cmds = 0;

	switch ( idx ) {
		case PI_LSARPC:
			lsa_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_LSARPC_DS:
			lsa_ds_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_SAMR:
			samr_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_NETLOGON:
			netlog_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_SRVSVC:
			srvsvc_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_WKSSVC:
			wkssvc_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_WINREG:
			reg_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_SPOOLSS:
			spoolss_get_pipe_fns( &cmds, &n_cmds );
			break;
		case PI_NETDFS:
			netdfs_get_pipe_fns( &cmds, &n_cmds );
			break;
#ifdef DEVELOPER
		case PI_ECHO:
			echo_get_pipe_fns( &cmds, &n_cmds );
			break;
#endif
		default:
			DEBUG(0,("get_pipe_fns: Unknown pipe index! [%d]\n", idx));
	}

	*fns = cmds;
	*n_fns = n_cmds;

	return;
}


