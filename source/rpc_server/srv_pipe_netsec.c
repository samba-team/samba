
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe server routines
 *  Copyright (C) Andrew Tridgell              1992-1999
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
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

static void NETSECcalc_p( netsec_auth_struct *a, unsigned char *data, int len)
{
	unsigned char *hash = a->netsec_hash;
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
static BOOL api_netsec_create_pdu(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
#if 0
	netsec_auth_struct *a = (netsec_auth_struct *)l->auth_info;

	BOOL ret;
	char *data;
	BOOL auth_verify = IS_BITS_SET_ALL(a->netsec_chal.neg_flags, NETSEC_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(a->netsec_chal.neg_flags, NETSEC_NEGOTIATE_SEAL);
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

	DEBUG(5,("create_netsec_reply: sign: %s seal: %s data %d auth %d\n",
		 BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, auth_len));

	if (auth_seal)
	{
		crc32 = crc32_calc_buffer(data_len, data);
		NETSECcalc_p(a, (uchar*)data, data_len);
	}

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH  auth_info;
		make_rpc_hdr_auth(&auth_info, 0x44, 0x06, 0x08, (auth_verify ? 1 : 0));
		smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &rauth, 0);
	}

	if (auth_verify)
	{
		RPC_AUTH_NETSEC_CHK netsec_chk;
		char *auth_data;
		a->netsec_seq_num++;
		make_rpc_auth_netsec_chk(&netsec_chk,
					  NETSEC_SIGN_VERSION, crc32,
					  a->netsec_seq_num++);
		smb_io_rpc_auth_netsec_chk("auth_sign", &netsec_chk, &rverf, 0);
		auth_data = prs_data(&rverf, 4);
		NETSECcalc_p(a, (uchar*)auth_data, 12);
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
		DEBUG(10,("create_netsec_reply: finished sending\n"));
		prs_free_data(&l->rdata);
	}

	return ret;
#endif
	return False;
}

#if 0
static BOOL api_netsec_verify(rpcsrv_struct *l,
				RPC_AUTH_NETSEC_RESP *netsec_resp)
{
	netsec_auth_struct *a = (netsec_auth_struct *)l->auth_info;
	uchar password[16];
	uchar lm_owf[24];
	uchar nt_owf[128];
	size_t lm_owf_len;
	size_t nt_owf_len;
	size_t usr_len;
	size_t dom_len;
	size_t wks_len;
	BOOL anonymous = False;
	fstring user_name;
	fstring domain;
	fstring wks;
	const struct passwd *pw = NULL;
	fstring unix_user;
	fstring nt_user;
	uchar user_sess_key[16];
	BOOL guest = False;

	memset(password, 0, sizeof(password));

	DEBUG(5,("api_netsec_verify: checking user details\n"));

	lm_owf_len = netsec_resp->hdr_lm_resp.str_str_len;
	nt_owf_len = netsec_resp->hdr_nt_resp.str_str_len;
	usr_len    = netsec_resp->hdr_usr    .str_str_len;
	dom_len    = netsec_resp->hdr_domain .str_str_len;
	wks_len    = netsec_resp->hdr_wks    .str_str_len;

	if (lm_owf_len == 0 && nt_owf_len == 0 &&
	    usr_len == 0 && dom_len == 0 && wks_len == 0)
	{
		anonymous = True;
	}
	else
	{
		if (lm_owf_len == 0) return False;
		if (nt_owf_len == 0) return False;
		if (netsec_resp->hdr_usr    .str_str_len == 0) return False;
		if (netsec_resp->hdr_wks    .str_str_len == 0) return False;
	}

	if (lm_owf_len > sizeof(lm_owf)) return False;
	if (nt_owf_len > sizeof(nt_owf)) return False;

	memcpy(lm_owf, netsec_resp->lm_resp, sizeof(lm_owf));
	memcpy(nt_owf, netsec_resp->nt_resp, sizeof(nt_owf));

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm, nt owfs, chal\n"));
	dump_data(100, lm_owf, sizeof(lm_owf));
	dump_data(100, nt_owf, sizeof(nt_owf));
	dump_data(100, a->netsec_chal.challenge, 8);
#endif

	memset(user_name, 0, sizeof(user_name));
	memset(domain   , 0, sizeof(domain   ));
	memset(wks      , 0, sizeof(wks      ));

	if (IS_BITS_SET_ALL(a->netsec_chal.neg_flags, NETSEC_NEGOTIATE_UNICODE))
	{
		unibuf_to_ascii(user_name, netsec_resp->user,
				MIN(netsec_resp->hdr_usr   .str_str_len/2,
				    sizeof(user_name)-1));
		unibuf_to_ascii(domain   , netsec_resp->domain,
				MIN(netsec_resp->hdr_domain.str_str_len/2,
				    sizeof(domain   )-1));
		unibuf_to_ascii(wks      , netsec_resp->wks,
				MIN(netsec_resp->hdr_wks   .str_str_len/2,
				    sizeof(wks      )-1));
	}
	else
	{
		fstrcpy(user_name, netsec_resp->user  );
		fstrcpy(domain   , netsec_resp->domain);
		fstrcpy(wks      , netsec_resp->wks   );
	}

	if (anonymous)
	{
		DEBUG(5,("anonymous user session\n"));
		mdfour(user_sess_key, password, 16);
		l->auth_validated = True;
		guest = True;
		safe_strcpy(unix_user, lp_guestaccount(-1), sizeof(unix_user)-1);
		nt_user[0] = 0;
		pw = Get_Pwnam(unix_user, True);
		l->auth_validated = pw != NULL;
	}
	else
	{
		DEBUG(5,("user: %s domain: %s wks: %s\n",
		          user_name, domain, wks));

		l->auth_validated = check_domain_security(user_name, domain,
				      (uchar*)a->netsec_chal.challenge,
				      lm_owf, lm_owf_len,
				      nt_owf, nt_owf_len,
				      user_sess_key,
				      password) == 0x0;
		if (l->auth_validated)
		{
			pw = map_nt_and_unix_username(domain, user_name,
			                              unix_user, nt_user);
			l->auth_validated = pw != NULL;
		}
	}

	if (l->auth_validated)
	{
		l->vuid = register_vuid(pw->pw_uid, pw->pw_gid,
					unix_user, nt_user,
					guest, user_sess_key);
		l->auth_validated = l->vuid != UID_FIELD_INVALID;
	}

	if (l->auth_validated)
	{
		l->auth_validated = become_vuser(l->vuid);
	}

	if (l->auth_validated)
	{
		/************************************************************/
		/****************** lkclXXXX - NTLMv1 ONLY! *****************/
		/************************************************************/

		uchar p24[24];
		NETSECOWFencrypt(password, lm_owf, p24);
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
				a->netsec_hash[ind] = (unsigned char)ind;
			}

			for( ind = 0; ind < 256; ind++)
			{
				unsigned char tc;

				j += (a->netsec_hash[ind] + k2[ind%8]);

				tc = a->netsec_hash[ind];
				a->netsec_hash[ind] = a->netsec_hash[j];
				a->netsec_hash[j] = tc;
			}

			a->netsec_hash[256] = 0;
			a->netsec_hash[257] = 0;
		}
		a->netsec_seq_num = 0;
	}
	else
	{
		l->auth_validated = False;
	}

	return l->auth_validated;
}

static BOOL api_netsec_bind_auth_resp(rpcsrv_struct *l)
{
	RPC_HDR_AUTHA autha_info;
	RPC_AUTH_VERIFIER auth_verifier;

	DEBUG(5,("api_pipe_bind_auth_resp: decode request. %d\n", __LINE__));

	if (l->hdr.auth_len == 0) return False;

	/* decode the authentication verifier response */
	smb_io_rpc_hdr_autha("", &autha_info, &l->data_i, 0);
	if (l->data_i.offset == 0) return False;

	smb_io_rpc_auth_verifier("", &auth_verifier, &l->data_i, 0);
	if (l->data_i.offset == 0) return False;

	if (!rpc_auth_verifier_chk(&auth_verifier, "NETSEC", NETSEC_AUTH))
	{
		return False;
	}
	
	return api_netsec(l, auth_verifier.msg_type);
}
#endif

static BOOL api_netsec(rpcsrv_struct *l, uint32 msg_type)
{
	/* receive a negotiate; send a challenge; receive a response */
	switch (msg_type)
	{
		case 0x3:
		{
			netsec_auth_struct *a;
			a = (netsec_auth_struct *)l->auth_info;

			smb_io_rpc_auth_netsec_neg("", &a->netsec_neg, &l->data_i, 0);
			if (l->data_i.offset == 0) return False;

			return True;
		}
		default:
		{
			/* NEGSEC expected: unexpected message type */
			DEBUG(3,("unexpected message type in NEGSEC %d\n",
			          msg_type));
			return False;
		}
	}

	return False;
}

static BOOL api_netsec_auth_chk(rpcsrv_struct *l,
				enum RPC_PKT_TYPE pkt_type)
{
	switch (pkt_type)
	{
		case RPC_BINDACK:
		{
			RPC_AUTH_VERIFIER auth_verifier;
			smb_io_rpc_auth_verifier("", &auth_verifier, &l->data_i, 0);
			if (l->data_i.offset == 0) return False;

			if (strequal(auth_verifier.signature, ""))
			{
				return api_netsec(l, auth_verifier.msg_type);
			}
			break;
		}
		default:
		{
			DEBUG(10,("api_netsec_auth_chk: unknown pkt_type %x\n",
			           pkt_type));
			return False;
		}
	}
	return False;
}

static BOOL api_netsec_auth_gen(rpcsrv_struct *l, prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	BOOL ret;
	RPC_HDR_AUTH  auth_info;
	RPC_AUTH_VERIFIER auth_verifier;
	RPC_AUTH_NETSEC_RESP auth_resp;
	prs_struct rhdr;
	prs_struct rauth;
	prs_struct rverf;
	prs_struct rresp;

	prs_init(&(rhdr ), 0, 4, False);
	prs_init(&(rauth), 0, 4, False);
	prs_init(&(rverf), 0, 4, False);
	prs_init(&(rresp), 0, 4, False);

	/*** authentication info ***/

	make_rpc_hdr_auth(&auth_info, 0x44, 0x06, 0, 1);
	smb_io_rpc_hdr_auth("", &auth_info, &rverf, 0);
	prs_realloc_data(&rverf, rverf.offset);

	/*** NETSEC verifier ***/

	make_rpc_auth_verifier(&auth_verifier, "\001", 0x0);
	smb_io_rpc_auth_verifier("", &auth_verifier, &rauth, 0);
	prs_realloc_data(&rauth, rauth.offset);

	/* NETSEC challenge ***/

	make_rpc_auth_netsec_resp(&auth_resp, 0x05);
	smb_io_rpc_auth_netsec_resp("", &auth_resp, &rresp, 0);
	prs_realloc_data(&rresp, rresp.offset);

	/***/
	/*** then do the header, now we know the length ***/
	/***/

	make_rpc_hdr(&l->hdr, pkt_type, RPC_FLG_FIRST | RPC_FLG_LAST,
		     l->hdr.call_id,
		     l->rdata.offset + rverf.offset + rauth.offset + rresp.offset + 0x10,
		     rauth.offset + rresp.offset);

	smb_io_rpc_hdr("", &l->hdr, &rhdr, 0);
	prs_realloc_data(&rhdr, l->rdata.offset);

	/***/
	/*** link rpc header, bind ack and auth responses ***/
	/***/

	prs_link(NULL     , &rhdr    , &l->rdata);
	prs_link(&rhdr    , &l->rdata, &rverf   );
	prs_link(&l->rdata, &rverf   , &rauth   );
	prs_link(&rverf   , &rauth   , &rresp   );
	prs_link(&rauth   , &rresp   , NULL     );

	prs_init(resp, 0, 4, False);
	ret = prs_copy(resp, &rhdr);

	prs_free_data(&l->rdata);
	prs_free_data(&rhdr    );
	prs_free_data(&rauth   );
	prs_free_data(&rverf   );
	prs_free_data(&rresp   );		

	return ret;
}

static BOOL api_netsec_decode_pdu(rpcsrv_struct *l)
{
#if 0
	netsec_auth_struct *a = (netsec_auth_struct *)l->auth_info;
	BOOL auth_verify = IS_BITS_SET_ALL(a->netsec_chal.neg_flags, NETSEC_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(a->netsec_chal.neg_flags, NETSEC_NEGOTIATE_SEAL);
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
		NETSECcalc_p(a, (uchar*)data, data_len);
		crc32 = crc32_calc_buffer(data_len, data);
	}

	/*** skip the data, record the offset so we can restore it again */
	old_offset = l->data_i.offset;

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH auth_info;
		l->data_i.offset += data_len;
		smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &l->data_i, 0);
		if (!rpc_hdr_netsec_auth_chk(&(auth_info))) return False;
	}

	if (auth_verify)
	{
		RPC_AUTH_NETSEC_CHK netsec_chk;
		char *req_data = prs_data(&l->data_i, l->data_i.offset + 4);
		DEBUG(5,("api_pipe_auth_process: auth %d\n", l->data_i.offset + 4));
		NETSECcalc_p(a, (uchar*)req_data, 12);
		smb_io_rpc_auth_netsec_chk("auth_sign", &netsec_chk, &l->data_i, 0);

		if (!rpc_auth_netsec_chk(&netsec_chk, crc32,
		                          a->netsec_seq_num))
		{
			return False;
		}
	}

	l->data_i.offset = old_offset;

	return True;
#endif
	return False;
}

static BOOL api_netsec_hdr_chk(RPC_HDR_AUTH *auth_info, void **auth_struct)
{
	DEBUG(10,("api_netsec_hdr_chk:\n"));
	if (!rpc_hdr_netsec_auth_chk(auth_info))
	{
		return False;
	}
	(*auth_struct) = (void*)malloc(sizeof(netsec_auth_struct));
	return (*auth_struct) != NULL;
}

srv_auth_fns netsec_fns = 
{
	api_netsec_hdr_chk,
	api_netsec_auth_chk,
	api_netsec_auth_gen,
	api_netsec_decode_pdu,
	api_netsec_create_pdu,
};

