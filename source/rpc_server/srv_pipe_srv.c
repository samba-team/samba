
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
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
#include "nterr.h"

extern int DEBUGLEVEL;

static void NTLMSSPcalc_p( ntlmssp_auth_struct *a, unsigned char *data, int len)
{
	unsigned char *hash = a->ntlmssp_hash;
	unsigned char index_i = hash[256];
	unsigned char index_j = hash[257];
	int ind;

	for( ind = 0; ind < len; ind++)
	{
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
turns a DCE/RPC request into a DCE/RPC reply

this is where the data really should be split up into an array of
headers and data sections.

********************************************************************/
static BOOL create_ntlmssp_reply(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;

	BOOL ret;
	char *data;
	BOOL auth_verify = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SEAL);
	uint32 data_len;
	uint32 auth_len;
	uint32 data_end = l->rdata.offset + (l->auth ? (8 + 16) : 0);
	uint32 crc32 = 0;

	prs_struct rhdr;
	prs_struct rdata_i;
	prs_struct rauth;
	prs_struct rverf;

	RPC_HDR_RESP  hdr_resp;

	DEBUG(5,("create_rpc_reply: data_start: %d data_end: %d max_tsize: %d\n",
	          data_start, data_end, l->hdr_ba.bba.max_tsize));

	auth_len = l->hdr.auth_len;

	DEBUG(10,("create_rpc_reply: auth\n"));

	if (auth_len != 16)
	{
		return False;
	}

	prs_init(&rhdr , 0, 4, False);

	l->hdr.pkt_type = RPC_RESPONSE; /* mark header as an rpc response */

	/* set up rpc header (fragmentation issues) */
	if (data_start == 0)
	{
		l->hdr.flags = RPC_FLG_FIRST;
	}
	else
	{
		l->hdr.flags = 0;
	}

	hdr_resp.alloc_hint = data_end - data_start; /* calculate remaining data to be sent */

	DEBUG(10,("alloc_hint: %d\n", hdr_resp.alloc_hint));

	if (hdr_resp.alloc_hint + 0x18 <= l->hdr_ba.bba.max_tsize)
	{
		l->hdr.flags |= RPC_FLG_LAST;
		l->hdr.frag_len = hdr_resp.alloc_hint + 0x18;
	}
	else
	{
		l->hdr.frag_len = l->hdr_ba.bba.max_tsize;
	}

	hdr_resp.alloc_hint -= auth_len + 8;

	data_len = l->hdr.frag_len - auth_len - (auth_verify ? 8 : 0) - 0x18;

	rhdr.start = 0;
	rhdr.end   = 0x18;

	DEBUG(10,("hdr flags: %x\n", l->hdr.flags));

	/* store the header in the data stream */
	smb_io_rpc_hdr     ("rhdr", &(l->hdr     ), &(rhdr), 0);
	smb_io_rpc_hdr_resp("resp", &(hdr_resp), &(rhdr), 0);

	/* don't use rdata: use rdata_i instead, which moves... */
	/* make a pointer to the rdata data, NOT A COPY */

	data = prs_data(&l->rdata, data_start);
	prs_create(&rdata_i, data, data_len, l->rdata.align, rdata_i.io); 
	rdata_i.offset = data_len;
	l->rdata_offset += data_len;

	prs_debug_out(&rdata_i, "rdata_i", 200);
	prs_debug_out(&l->rdata, "rdata", 200);

	prs_init(&rauth, 0, 4, False);
	prs_init(&rverf, 0, 4, False);

	DEBUG(5,("create_ntlmssp_reply: sign: %s seal: %s data %d auth %d\n",
		 BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, auth_len));

	if (auth_seal)
	{
		crc32 = crc32_calc_buffer(data_len, data);
		NTLMSSPcalc_p(a, (uchar*)data, data_len);
	}

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH  auth_info;
		make_rpc_hdr_auth(&auth_info, 0x0a, 0x06, 0x08, (auth_verify ? 1 : 0));
		smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &rauth, 0);
	}

	if (auth_verify)
	{
		RPC_AUTH_NTLMSSP_CHK ntlmssp_chk;
		char *auth_data;
		a->ntlmssp_seq_num++;
		make_rpc_auth_ntlmssp_chk(&ntlmssp_chk,
					  NTLMSSP_SIGN_VERSION, crc32,
					  a->ntlmssp_seq_num++);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &ntlmssp_chk, &rverf, 0);
		auth_data = prs_data(&rverf, 4);
		NTLMSSPcalc_p(a, (uchar*)auth_data, 12);
	}
	prs_link(NULL    , &rhdr   , &rdata_i);
	prs_link(&rhdr   , &rdata_i, &rauth  );
	prs_link(&rdata_i, &rauth  , &rverf  );
	prs_link(&rauth  , &rverf  , NULL    );

	prs_init(resp, 0, 4, False);
	ret = prs_copy(resp, &rhdr);

	prs_free_data(&rauth  );
	prs_free_data(&rverf  );
	prs_free_data(&rhdr );

	if (IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_LAST) ||
	    l->hdr.pkt_type == RPC_BINDACK)
	{
		DEBUG(10,("create_ntlmssp_reply: finished sending\n"));
		prs_free_data(&l->rdata);
	}

	return ret;
}


/*******************************************************************
********************************************************************/
static BOOL create_noauth_reply(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	BOOL ret;
	char *data;
	uint32 data_len;
	uint32 auth_len;
	uint32 data_end = l->rdata.offset + (l->auth ? (8 + 16) : 0);
	prs_struct rhdr;
	prs_struct rdata_i;
	RPC_HDR_RESP  hdr_resp;

	DEBUG(5,("create_noauth_reply: data_start: %d data_end: %d max_tsize: %d\n",
	          data_start, data_end, l->hdr_ba.bba.max_tsize));

	auth_len = l->hdr.auth_len;

	if (auth_len != 0)
	{
		return False;
	}

	prs_init(&rhdr , 0, 4, False);

	l->hdr.pkt_type = RPC_RESPONSE; /* mark header as an rpc response */

	/* set up rpc header (fragmentation issues) */
	if (data_start == 0)
	{
		l->hdr.flags = RPC_FLG_FIRST;
	}
	else
	{
		l->hdr.flags = 0;
	}

	hdr_resp.alloc_hint = data_end - data_start; /* calculate remaining data to be sent */

	DEBUG(10,("alloc_hint: %d\n", hdr_resp.alloc_hint));

	if (hdr_resp.alloc_hint + 0x18 <= l->hdr_ba.bba.max_tsize)
	{
		l->hdr.flags |= RPC_FLG_LAST;
		l->hdr.frag_len = hdr_resp.alloc_hint + 0x18;
	}
	else
	{
		l->hdr.frag_len = l->hdr_ba.bba.max_tsize;
	}

	data_len = l->hdr.frag_len - 0x18;

	rhdr.start = 0;
	rhdr.end   = 0x18;

	DEBUG(10,("hdr flags: %x\n", l->hdr.flags));

	/* store the header in the data stream */
	smb_io_rpc_hdr     ("rhdr", &(l->hdr     ), &(rhdr), 0);
	smb_io_rpc_hdr_resp("resp", &(hdr_resp), &(rhdr), 0);

	/* don't use rdata: use rdata_i instead, which moves... */
	/* make a pointer to the rdata data, NOT A COPY */

	data = prs_data(&l->rdata, data_start);
	prs_create(&rdata_i, data, data_len, l->rdata.align, rdata_i.io); 
	rdata_i.offset = data_len;
	l->rdata_offset += data_len;

	prs_debug_out(&rdata_i, "rdata_i", 200);
	prs_debug_out(&l->rdata, "rdata", 200);

	prs_link(NULL , &rhdr   , &rdata_i);
	prs_link(&rhdr, &rdata_i, NULL    );

	prs_init(resp, 0, 4, False);
	ret = prs_copy(resp, &rhdr);

	prs_free_data(&rhdr );

	return ret;
}

/*******************************************************************
turns a DCE/RPC response stream into a DCE/RPC reply
********************************************************************/
static BOOL create_rpc_reply(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	BOOL ret;

	if (l->auth != NULL)
	{
		ret = l->auth->api_create_pdu(l, data_start, resp);
	}
	else
	{
		ret =  create_noauth_reply(l, data_start, resp);
	}
	if ((!ret) || IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_LAST))
	{
		DEBUG(10,("create_noauth_reply: finished sending\n"));
		prs_free_data(&l->rdata);
	}
	return ret;
}

static BOOL api_pipe_ntlmssp_verify(rpcsrv_struct *l,
				RPC_AUTH_NTLMSSP_RESP *ntlmssp_resp)
{
	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;
	uchar *pwd = NULL;
	uchar password[16];
	uchar lm_owf[24];
	uchar nt_owf[128];
	size_t lm_owf_len;
	size_t nt_owf_len;
	size_t usr_len;
	size_t dom_len;
	size_t wks_len;
	BOOL anonymous = False;

	memset(password, 0, sizeof(password));

	DEBUG(5,("api_pipe_ntlmssp_verify: checking user details\n"));

	lm_owf_len = ntlmssp_resp->hdr_lm_resp.str_str_len;
	nt_owf_len = ntlmssp_resp->hdr_nt_resp.str_str_len;
	usr_len    = ntlmssp_resp->hdr_usr    .str_str_len;
	dom_len    = ntlmssp_resp->hdr_domain .str_str_len;
	wks_len    = ntlmssp_resp->hdr_wks    .str_str_len;

	if (lm_owf_len == 0 && nt_owf_len == 0 &&
	    usr_len == 0 && dom_len == 0 && wks_len == 0)
	{
		anonymous = True;
	}
	else
	{
		if (lm_owf_len == 0) return False;
		if (nt_owf_len == 0) return False;
		if (ntlmssp_resp->hdr_usr    .str_str_len == 0) return False;
		if (ntlmssp_resp->hdr_domain .str_str_len == 0) return False;
		if (ntlmssp_resp->hdr_wks    .str_str_len == 0) return False;
	}

	if (lm_owf_len > sizeof(lm_owf)) return False;
	if (nt_owf_len > sizeof(nt_owf)) return False;

	memcpy(lm_owf, ntlmssp_resp->lm_resp, sizeof(lm_owf));
	memcpy(nt_owf, ntlmssp_resp->nt_resp, sizeof(nt_owf));

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm, nt owfs, chal\n"));
	dump_data(100, lm_owf, sizeof(lm_owf));
	dump_data(100, nt_owf, sizeof(nt_owf));
	dump_data(100, a->ntlmssp_chal.challenge, 8);
#endif

	memset(a->user_name, 0, sizeof(a->user_name));
	memset(a->domain   , 0, sizeof(a->domain   ));
	memset(a->wks      , 0, sizeof(a->wks      ));

	if (IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		unibuf_to_ascii(a->user_name, ntlmssp_resp->user,
				MIN(ntlmssp_resp->hdr_usr   .str_str_len/2,
				    sizeof(a->user_name)-1));
		unibuf_to_ascii(a->domain   , ntlmssp_resp->domain,
				MIN(ntlmssp_resp->hdr_domain.str_str_len/2,
				    sizeof(a->domain   )-1));
		unibuf_to_ascii(a->wks      , ntlmssp_resp->wks,
				MIN(ntlmssp_resp->hdr_wks   .str_str_len/2,
				    sizeof(a->wks      )-1));
	}
	else
	{
		fstrcpy(a->user_name, ntlmssp_resp->user  );
		fstrcpy(a->domain   , ntlmssp_resp->domain);
		fstrcpy(a->wks      , ntlmssp_resp->wks   );
	}


	if (anonymous)
	{
		DEBUG(5,("anonymous user session\n"));
		mdfour(a->user_sess_key, password, 16);
		pwd = password;
		l->auth_validated = True;
	}
	else
	{
		DEBUG(5,("user: %s domain: %s wks: %s\n", a->user_name, a->domain, a->wks));
		become_root(False);
		l->auth_validated = check_domain_security(a->user_name, a->domain,
				      (uchar*)a->ntlmssp_chal.challenge,
				      lm_owf, lm_owf_len,
				      nt_owf, nt_owf_len,
				      a->user_sess_key,
				      password) == 0x0;
		pwd = password;
		unbecome_root(False);
	}

	if (l->auth_validated && pwd != NULL)
	{
		uchar p24[24];
		NTLMSSPOWFencrypt(pwd, lm_owf, p24);
		{
			unsigned char j = 0;
			int ind;

			unsigned char k2[8];

			memcpy(k2, p24, 5);
			k2[5] = 0xe5;
			k2[6] = 0x38;
			k2[7] = 0xb0;

			for (ind = 0; ind < 256; ind++)
			{
				a->ntlmssp_hash[ind] = (unsigned char)ind;
			}

			for( ind = 0; ind < 256; ind++)
			{
				unsigned char tc;

				j += (a->ntlmssp_hash[ind] + k2[ind%8]);

				tc = a->ntlmssp_hash[ind];
				a->ntlmssp_hash[ind] = a->ntlmssp_hash[j];
				a->ntlmssp_hash[j] = tc;
			}

			a->ntlmssp_hash[256] = 0;
			a->ntlmssp_hash[257] = 0;
		}
		a->ntlmssp_seq_num = 0;
	}
	else
	{
		l->auth_validated = False;
	}

	return l->auth_validated;
}

static BOOL api_pipe_ntlmssp(rpcsrv_struct *l, uint32 msg_type)
{
	/* receive a negotiate; send a challenge; receive a response */
	switch (msg_type)
	{
		case NTLMSSP_NEGOTIATE:
		{
			RPC_AUTH_NTLMSSP_NEG ntlmssp_neg;
			smb_io_rpc_auth_ntlmssp_neg("", &ntlmssp_neg, &l->data_i, 0);
			break;
		}
		case NTLMSSP_AUTH:
		{
			RPC_AUTH_NTLMSSP_RESP ntlmssp_resp;
			smb_io_rpc_auth_ntlmssp_resp("", &ntlmssp_resp, &l->data_i, 0);
			if (!api_pipe_ntlmssp_verify(l, &ntlmssp_resp))
			{
				l->data_i.offset = 0;
			}
			break;
		}
		default:
		{
			/* NTLMSSP expected: unexpected message type */
			DEBUG(3,("unexpected message type in NTLMSSP %d\n",
			          msg_type));
			return False;
		}
	}

	return (l->data_i.offset != 0);
}

struct api_cmd
{
  char * pipe_clnt_name;
  char * pipe_srv_name;
  BOOL (*fn) (rpcsrv_struct *);
};

static struct api_cmd **api_fd_commands = NULL;
uint32 num_cmds = 0;

static void api_cmd_free(struct api_cmd *item)
{
	if (item != NULL)
	{
		if (item->pipe_clnt_name != NULL)
		{
			free(item->pipe_clnt_name);
		}
		if (item->pipe_srv_name != NULL)
		{
			free(item->pipe_srv_name);
		}
		free(item);
	}
}

static struct api_cmd *api_cmd_dup(const struct api_cmd *from)
{
	struct api_cmd *copy = NULL;
	if (from == NULL)
	{
		return NULL;
	}
	copy = (struct api_cmd *) malloc(sizeof(struct api_cmd));
	if (copy != NULL)
	{
		ZERO_STRUCTP(copy);
		if (from->pipe_clnt_name != NULL)
		{
			copy->pipe_clnt_name  = strdup(from->pipe_clnt_name );
		}
		if (from->pipe_srv_name != NULL)
		{
			copy->pipe_srv_name = strdup(from->pipe_srv_name);
		}
		if (from->fn != NULL)
		{
			copy->fn    = from->fn;
		}
	}
	return copy;
}

static void free_api_cmd_array(uint32 num_entries, struct api_cmd **entries)
{
	void(*fn)(void*) = (void(*)(void*))&api_cmd_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

static struct api_cmd* add_api_cmd_to_array(uint32 *len,
				struct api_cmd ***array,
				const struct api_cmd *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&api_cmd_dup;
	return (struct api_cmd*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
}


void close_msrpc_command_processor(void)
{
	free_api_cmd_array(num_cmds, api_fd_commands);
}

void add_msrpc_command_processor(char* pipe_name,
				char* process_name,
				BOOL (*fn) (rpcsrv_struct *))
{
	struct api_cmd cmd;
	cmd.pipe_clnt_name = pipe_name;
	cmd.pipe_srv_name = process_name;
	cmd.fn = fn;

	add_api_cmd_to_array(&num_cmds, &api_fd_commands, &cmd);
}

static BOOL api_pipe_bind_auth_resp(rpcsrv_struct *l)
{
	RPC_HDR_AUTHA autha_info;
	RPC_AUTH_NTLMSSP_VERIFIER auth_verifier;

	DEBUG(5,("api_pipe_bind_auth_resp: decode request. %d\n", __LINE__));

	if (l->hdr.auth_len == 0) return False;

	/* decode the authentication verifier response */
	smb_io_rpc_hdr_autha("", &autha_info, &l->data_i, 0);
	if (l->data_i.offset == 0) return False;

	smb_io_rpc_auth_ntlmssp_verifier("", &auth_verifier, &l->data_i, 0);
	if (l->data_i.offset == 0) return False;

	if (!rpc_auth_ntlmssp_verifier_chk(&auth_verifier, "NTLMSSP", NTLMSSP_AUTH)) return False;
	
	return api_pipe_ntlmssp(l, auth_verifier.msg_type);
}

static BOOL api_pipe_fault_resp(rpcsrv_struct *l, uint32 status,
				prs_struct *resp)
{
	prs_struct rhdr;
	prs_struct rfault;
	RPC_HDR_FAULT hdr_fault;
	RPC_HDR_RESP  hdr_resp;

	DEBUG(5,("api_pipe_fault_resp: make response\n"));

	l->faulted_once_before = True;

	prs_init(&(rhdr     ), 0, 4, False);
	prs_init(&(rfault   ), 0, 4, False);

	/***/
	/*** set up the header, response header and fault status ***/
	/***/

	hdr_fault.status   = status;
	hdr_fault.reserved = 0x0;

	hdr_resp.alloc_hint   = 0x0;
	hdr_resp.cancel_count = 0x0;
	hdr_resp.reserved     = 0x0;

	make_rpc_hdr(&l->hdr, RPC_FAULT, RPC_FLG_NOCALL | RPC_FLG_FIRST | RPC_FLG_LAST,
	             l->hdr.call_id,
	             0x20,
	             0);

	smb_io_rpc_hdr      ("hdr"  , &(l->hdr      ), &(rhdr), 0);
	smb_io_rpc_hdr_resp ("resp" , &(hdr_resp ), &(rhdr), 0);
	smb_io_rpc_hdr_fault("fault", &(hdr_fault), &(rfault), 0);
	prs_realloc_data(&rhdr  , rhdr.offset  );
	prs_realloc_data(&rfault, rfault.offset);

	/***/
	/*** link rpc header and fault together ***/
	/***/

	prs_link(NULL    , &rhdr  , &rfault);
	prs_link(&rhdr, &rfault, NULL      );

	prs_init(resp, 0, 4, False);
	if (!prs_copy(resp, &rhdr)) return False;
	prs_free_data(&rfault);
	prs_free_data(&rhdr);

	return True;
}

static BOOL api_pipe_ntlmssp_auth_chk(rpcsrv_struct *l)
{
	RPC_AUTH_NTLMSSP_VERIFIER auth_verifier;
	smb_io_rpc_auth_ntlmssp_verifier("", &auth_verifier, &l->data_i, 0);
	if (l->data_i.offset == 0) return False;

	
	if (strequal(auth_verifier.signature, "NTLMSSP"))
	{
		return api_pipe_ntlmssp(l, auth_verifier.msg_type);
	}
	return False;
}

static BOOL api_pipe_ntlmssp_auth_gen(rpcsrv_struct *l, prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	BOOL ret;
	uint8 challenge[8];
	RPC_HDR_AUTH  auth_info;
	RPC_AUTH_NTLMSSP_VERIFIER auth_verifier;
	prs_struct rhdr;
	prs_struct rauth;
	prs_struct rverf;
	prs_struct rntlm;

	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;

	prs_init(&(rhdr ), 0, 4, False);
	prs_init(&(rauth), 0, 4, False);
	prs_init(&(rverf), 140, 4, False);
	prs_init(&(rntlm), 0, 4, False);

	generate_random_buffer(challenge, 8, False);

	/*** authentication info ***/

	make_rpc_hdr_auth(&auth_info, 0x0a, 0x06, 0, 1);
	smb_io_rpc_hdr_auth("", &auth_info, &rverf, 0);
	prs_realloc_data(&rverf, rverf.offset);

	/*** NTLMSSP verifier ***/

	make_rpc_auth_ntlmssp_verifier(&auth_verifier,
			       "NTLMSSP", NTLMSSP_CHALLENGE);
	smb_io_rpc_auth_ntlmssp_verifier("", &auth_verifier, &rauth, 0);
	prs_realloc_data(&rauth, rauth.offset);

	/* NTLMSSP challenge ***/

	make_rpc_auth_ntlmssp_chal(&a->ntlmssp_chal,
				   0x000082b1, challenge);
	smb_io_rpc_auth_ntlmssp_chal("", &a->ntlmssp_chal, &rntlm, 0);
	prs_realloc_data(&rntlm, rntlm.offset);

	/***/
	/*** then do the header, now we know the length ***/
	/***/

	make_rpc_hdr(&l->hdr, pkt_type, RPC_FLG_FIRST | RPC_FLG_LAST,
		     l->hdr.call_id,
		     l->rdata.offset + rverf.offset + rauth.offset + rntlm.offset + 0x10,
		     rauth.offset + rntlm.offset);

	smb_io_rpc_hdr("", &l->hdr, &rhdr, 0);
	prs_realloc_data(&rhdr, l->rdata.offset);

	/***/
	/*** link rpc header, bind ack and auth responses ***/
	/***/

	prs_link(NULL     , &rhdr    , &l->rdata);
	prs_link(&rhdr    , &l->rdata, &rverf   );
	prs_link(&l->rdata, &rverf   , &rauth   );
	prs_link(&rverf   , &rauth   , &rntlm   );
	prs_link(&rauth   , &rntlm   , NULL     );

	prs_init(resp, 0, 4, False);
	ret = prs_copy(resp, &rhdr);

	prs_free_data(&l->rdata);
	prs_free_data(&rhdr    );
	prs_free_data(&rauth   );
	prs_free_data(&rverf   );
	prs_free_data(&rntlm   );		

	return ret;
}

static void api_ntlmssp_usr_sess_key(rpcsrv_struct *l, uchar usr_sess_key[16])
{
	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;
	memcpy(usr_sess_key, a->user_sess_key, 16);
}

static srv_auth_fns ntlmssp_fns = 
{
	api_pipe_ntlmssp_auth_chk,
	api_pipe_ntlmssp_auth_gen,
	create_ntlmssp_reply,
	api_ntlmssp_usr_sess_key

};

static BOOL srv_pipe_bind_and_alt_req(rpcsrv_struct *l, 
				const char* ack_pipe_name,
				prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	BOOL ret;

	prs_struct rhdr;
	uint16 assoc_gid;

	l->auth = NULL;

	/* decode the bind request */
	smb_io_rpc_hdr_rb("", &l->hdr_rb, &l->data_i, 0);

	if (l->data_i.offset == 0) return False;

	if (l->hdr.auth_len != 0)
	{
		RPC_HDR_AUTH  auth_info;

		/* decode the authentication verifier */
		smb_io_rpc_hdr_auth    ("", &auth_info    , &l->data_i, 0);
		if (l->data_i.offset == 0) return False;

		if (rpc_hdr_ntlmssp_auth_chk(&(auth_info)))
		{
			l->auth = &ntlmssp_fns;
			l->auth_info = (void*)malloc(sizeof(ntlmssp_auth_struct));
			if (l->auth_info == NULL)
			{
				DEBUG(10,("srv_pipe_bind_and_alt_req: malloc failed\n"));
				return False;
			}
		}

		if (l->auth)
		{
			if (!l->auth->api_auth_chk(l))
			{
				free(l->auth_info);
				l->auth_info = NULL;
				return False;
			}
		}
	}

	DEBUG(5,("api_pipe_bind_req: make response. %d\n", __LINE__));

	prs_init(&(l->rdata), 0, 4, False);
	prs_init(&(rhdr    ), 0, 4, False);

	/***/
	/*** do the bind ack first ***/
	/***/

	if (l->auth != NULL)
	{
		assoc_gid = 0x7a77;
	}
	else
	{
		assoc_gid = l->hdr_rb.bba.assoc_gid;
	}

	make_rpc_hdr_ba(&l->hdr_ba,
	                l->hdr_rb.bba.max_tsize,
	                l->hdr_rb.bba.max_rsize,
	                assoc_gid,
	                ack_pipe_name,
	                0x1, 0x0, 0x0,
	                &(l->hdr_rb.transfer));

	smb_io_rpc_hdr_ba("", &l->hdr_ba, &l->rdata, 0);
	prs_realloc_data(&l->rdata, l->rdata.offset);

	if (l->auth != NULL)
	{
		/***/
		/*** now the authentication ***/
		/***/

		if (!l->auth->api_auth_gen(l, resp, pkt_type))
		{
			free(l->auth_info);
			l->auth_info = NULL;
			prs_free_data(&l->rdata);
			return False;
		}
	}
	else
	{
		/***/
		/*** do the header ***/
		/***/

		make_rpc_hdr(&l->hdr, pkt_type, RPC_FLG_FIRST | RPC_FLG_LAST,
			     l->hdr.call_id,
			     l->rdata.offset + 0x10, 0);

		smb_io_rpc_hdr("", &l->hdr, &rhdr, 0);
		prs_realloc_data(&rhdr, l->rdata.offset);

		/***/
		/*** link rpc header and bind acknowledgment ***/
		/***/

		prs_link(NULL    , &rhdr , &l->rdata);
		prs_link(&rhdr, &l->rdata, NULL     );

		prs_init(resp, 0, 4, False);
		ret = prs_copy(resp, &rhdr);

		prs_free_data(&l->rdata);
		prs_free_data(&rhdr );
	}

	return ret;
}

static BOOL api_pipe_bind_and_alt_req(rpcsrv_struct *l, 
				const char* name,
				prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	fstring ack_pipe_name;
	fstring pipe_srv_name;
	int i = 0;

	DEBUG(5,("api_pipe_bind_req: decode request. %d\n", __LINE__));

	for (i = 0; i < num_cmds; i++)
	{
		if (strequal(api_fd_commands[i]->pipe_clnt_name, name) &&
		    api_fd_commands[i]->fn != NULL)
		{
			DEBUG(3,("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
			           api_fd_commands[i]->pipe_clnt_name,
			           api_fd_commands[i]->pipe_srv_name));
			fstrcpy(pipe_srv_name, api_fd_commands[i]->pipe_srv_name);
			break;
		}
	}

	if (api_fd_commands[i]->fn == NULL) return False;

	switch (pkt_type)
	{
		case RPC_BINDACK:
		{
			/* name has to be \PIPE\xxxxx */
			fstrcpy(ack_pipe_name, "\\PIPE\\");
			fstrcat(ack_pipe_name, pipe_srv_name);
			break;
		}
		case RPC_ALTCONTRESP:
		{
			/* secondary address CAN be NULL
			 * as the specs says it's ignored.
			 * It MUST NULL to have the spoolss working.
			 */
			fstrcpy(ack_pipe_name, "");
			break;
		}
		default:
		{
			return False;
		}
	}
	return srv_pipe_bind_and_alt_req(l, ack_pipe_name, resp, pkt_type);
}

/*
 * The RPC Alter-Context call is used only by the spoolss pipe
 * simply because there is a bug (?) in the MS unmarshalling code
 * or in the marshalling code. If it's in the later, then Samba
 * have the same bug.
 */
static BOOL api_pipe_bind_req(rpcsrv_struct *l, const char* name, prs_struct *resp)
{
	return api_pipe_bind_and_alt_req(l, name, resp, RPC_BINDACK);
}

static BOOL api_pipe_alt_req(rpcsrv_struct *l, const char* name, prs_struct *resp)
{
	return api_pipe_bind_and_alt_req(l, name, resp, RPC_ALTCONTRESP);
}

static BOOL api_pipe_auth_process(rpcsrv_struct *l)
{
	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;
	BOOL auth_verify = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SEAL);
	int data_len;
	int auth_len;
	uint32 old_offset;
	uint32 crc32 = 0;

	auth_len = l->hdr.auth_len;

	if (auth_len != 16 && auth_verify)
	{
		return False;
	}

	data_len = l->hdr.frag_len - auth_len - (auth_verify ? 8 : 0) - 0x18;
	
	DEBUG(5,("api_pipe_auth_process: sign: %s seal: %s data %d auth %d\n",
	         BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, auth_len));

	if (auth_seal)
	{
		char *data = prs_data(&l->data_i, l->data_i.offset);
		DEBUG(5,("api_pipe_auth_process: data %d\n", l->data_i.offset));
		NTLMSSPcalc_p(a, (uchar*)data, data_len);
		crc32 = crc32_calc_buffer(data_len, data);
	}

	/*** skip the data, record the offset so we can restore it again */
	old_offset = l->data_i.offset;

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH auth_info;
		l->data_i.offset += data_len;
		smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &l->data_i, 0);
		if (!rpc_hdr_ntlmssp_auth_chk(&(auth_info))) return False;
	}

	if (auth_verify)
	{
		RPC_AUTH_NTLMSSP_CHK ntlmssp_chk;
		char *req_data = prs_data(&l->data_i, l->data_i.offset + 4);
		DEBUG(5,("api_pipe_auth_process: auth %d\n", l->data_i.offset + 4));
		NTLMSSPcalc_p(a, (uchar*)req_data, 12);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &ntlmssp_chk, &l->data_i, 0);

		if (!rpc_auth_ntlmssp_chk(&ntlmssp_chk, crc32,
		                          a->ntlmssp_seq_num))
		{
			return False;
		}
	}

	l->data_i.offset = old_offset;

	return True;
}

static BOOL api_pipe_request(rpcsrv_struct *l, const char* name,
				prs_struct *resp)
{
	int i = 0;

	if (l->auth != NULL && l->auth_validated)
	{
		DEBUG(10,("api_pipe_request: validated auth\n"));
		if (!api_pipe_auth_process(l)) return False;

		DEBUG(0,("api_pipe_request: **** MUST CALL become_user() HERE **** \n"));
#if 0
		become_user();
#endif
	}

	for (i = 0; i < num_cmds; i++)
	{
		if (strequal(api_fd_commands[i]->pipe_clnt_name, name) &&
		    api_fd_commands[i]->fn != NULL)
		{
			DEBUG(3,("Doing \\PIPE\\%s\n", api_fd_commands[i]->pipe_clnt_name));
			if (!api_fd_commands[i]->fn(l))
			{
				return False;
			}
			l->rdata_offset = 0;

			/* create the rpc pdu */
			return create_rpc_reply(l, 0, resp);

		}
	}
	return False;
}

static BOOL rpc_redir_local(rpcsrv_struct *l, prs_struct *req, prs_struct *resp,
				const char* name)
{
	BOOL reply = False;
	BOOL last;
	BOOL first;

	if (req->data == NULL || req->data_size == 0)
	{
		if (l->rdata.data == NULL)
		{
			return False;
		}
		/* hmm, must need some more data.
		 * create, flatten and return data in a single pdu
		 */
		if (!create_rpc_reply(l, l->rdata_offset, resp)) return False;

		return True;
	}

	if (req->data == NULL) return False;

	/* lkclXXXX still assume that the first complete PDU is always
	   in a single request!!!
	 */
	/* process the rpc header */
	req->offset = 0x0;
	req->io = True;
	smb_io_rpc_hdr("hdr", &l->hdr, req, 0);

	if (req->offset == 0) return False;

	last  = IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_LAST);
	first = IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_FIRST);

	if (l->hdr.pkt_type == RPC_BIND ||
	    l->hdr.pkt_type == RPC_BINDRESP)
	{
		last = True;
		first = True;
	}

	if (first)
	{
		prs_init(&l->data_i, 0, 4, True);
	}
	if (last)
	{
		prs_append_data(&l->data_i,
		                prs_data(req, req->offset),
		                req->data_size - req->offset);
	}
	else
	{
		prs_init(resp, 0, 4, False);
		return True;
	}

	/* previous authentication failure.  don't give a monkey's what
	 * is sent to us, we reject it, outright
	 */

	if (l->faulted_once_before)
	{
		DEBUG(10,("rpc_redir_local: faulted before (so do it again)\n"));
		prs_free_data(&l->data_i);		
		return api_pipe_fault_resp(l, 0x1c010002, resp);
	}

	switch (l->hdr.pkt_type)
	{
		case RPC_BIND   :
		{
			reply = api_pipe_bind_req(l, name, resp);
			break;
		}
		case RPC_ALTCONT:
		{
			reply = api_pipe_alt_req(l, name, resp);
 			break;
 		}
		case RPC_REQUEST:
		{
			if (l->auth != NULL && !l->auth_validated)
			{
				/* authentication _was_ requested
				   and it failed.  sorry, no deal!
				 */
				reply = False;
			}
			else
			{
				/* read the rpc header */
				smb_io_rpc_hdr_req("req", &(l->hdr_req), &l->data_i, 0);
				reply = api_pipe_request(l, name, resp);
			}
			break;
		}
		case RPC_BINDRESP: /* not the real name! */
		{
			reply = api_pipe_bind_auth_resp(l);
			if (!reply)
			{
				l->auth = NULL;
				if (l->auth_info != NULL)
				{
					free(l->auth_info);
					l->auth_info = NULL;
				}
				l->auth_validated = False;
			}
			break;
		}
	}

	if (!reply)
	{
		reply = api_pipe_fault_resp(l, 0x1c010002, resp);
	}
	
	if (reply)
	{
		/* flatten the data into a single pdu */
		DEBUG(200,("rpc_redir_local: %d\n", __LINE__));
		prs_debug_out(resp    , "redir_local resp", 200);

		return True;
	}

	/* delete intermediate data used to set up the pdu.  leave
	   rdata alone because that's got the rest of the data in it */
	prs_free_data(&l->data_i);		

	return reply;
}

/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
static BOOL api_rpc_command(rpcsrv_struct *l, char *rpc_name,
				struct api_struct *api_rpc_cmds)
{
	int fn_num;
	DEBUG(4,("api_rpc_command: %s op 0x%x - ", rpc_name, l->hdr_req.opnum));

	for (fn_num = 0; api_rpc_cmds[fn_num].name; fn_num++)
	{
		if (api_rpc_cmds[fn_num].opnum == l->hdr_req.opnum && api_rpc_cmds[fn_num].fn != NULL)
		{
			DEBUG(3,("api_rpc_command: %s\n", api_rpc_cmds[fn_num].name));
			break;
		}
	}

	if (api_rpc_cmds[fn_num].name == NULL)
	{
		DEBUG(4, ("unknown\n"));
		return False;
	}

	prs_init(&l->rdata, 0, 4, False);

	/* do the actual command */
	api_rpc_cmds[fn_num].fn(l, &l->data_i, &(l->rdata));

	if (l->rdata.data == NULL || l->rdata.offset == 0)
	{
		prs_free_data(&l->rdata);
		return False;
	}

	prs_realloc_data(&l->rdata, l->rdata.offset);

	DEBUG(10,("called %s\n", rpc_name));

	return True;
}


/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
BOOL api_rpcTNP(rpcsrv_struct *l, char *rpc_name,
				struct api_struct *api_rpc_cmds)
{
	if (l->data_i.data == NULL)
	{
		DEBUG(2,("%s: NULL data received\n", rpc_name));
		return False;
	}

	/* interpret the command */
	if (!api_rpc_command(l, rpc_name, api_rpc_cmds))
	{
		return False;
	}

	return True;
}

/*******************************************************************
 entry point from msrpc to smb.  adds data received to pdu; checks
 pdu; hands pdu off to msrpc, which gets a pdu back (except in the
 case of the RPC_BINDCONT pdu).
 ********************************************************************/
BOOL rpc_local(rpcsrv_struct *l, char *data, int len, char *name)
{
	BOOL reply = False;

	DEBUG(10,("rpc_local: len %d\n", len));

	if (len != 0)
	{
		reply = prs_add_data(&l->smb_pdu, data, len);

		if (reply && is_complete_pdu(&l->smb_pdu))
		{
			l->smb_pdu.offset = l->smb_pdu.data_size;
			prs_link(NULL, &l->smb_pdu, NULL);
			reply = rpc_redir_local(l, &l->smb_pdu, &l->rsmb_pdu, name);
			prs_free_data(&l->smb_pdu);
			prs_init(&l->smb_pdu, 0, 4, True);
		}
	}
	else
	{
		if (l->rdata.data == NULL || l->rdata.data_size == 0)
		{
			DEBUG(10,("rpc_local: no data to send\n"));
			return True;
		}
		prs_free_data(&l->smb_pdu);
		prs_init(&l->smb_pdu, 0, 4, True);
		reply = rpc_redir_local(l, &l->smb_pdu, &l->rsmb_pdu, name);
	}
	return reply;
}

