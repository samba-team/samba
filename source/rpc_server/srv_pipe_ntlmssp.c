
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

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

static void NTLMSSPcalc_p( ntlmssp_auth_struct *a, uchar *data, int len)
{
	uchar *hash = a->ntlmssp_hash;
	uchar index_i = hash[256];
	uchar index_j = hash[257];
	int ind;

	for( ind = 0; ind < len; ind++)
	{
		uchar tc;
		uchar t;

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
static BOOL api_ntlmssp_create_pdu(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;

	BOOL ret;
	BOOL auth_verify = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SEAL);
	uint32 data_len;
	uint32 auth_len;
	uint32 data_end = l->rdata.offset + (l->auth ? (8 + 16) : 0);
	uint32 crc32 = 0;
	char *data;

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
	hdr_resp.cancel_count = 0x0;
	hdr_resp.context_id   = 0x0;
	hdr_resp.reserved = 0x0;

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
		a->ntlmssp_seq_num++;
		make_rpc_auth_ntlmssp_chk(&ntlmssp_chk,
					  NTLMSSP_SIGN_VERSION, crc32,
					  a->ntlmssp_seq_num++);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &ntlmssp_chk, &rverf, 0);
		NTLMSSPcalc_p(a, (uchar*)prs_data(&rverf, 4), 12);
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

static BOOL api_ntlmssp_verify(rpcsrv_struct *l,
				RPC_AUTH_NTLMSSP_RESP *ntlmssp_resp)
{
	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;
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
	NET_USER_INFO_3 info3;
	BOOL guest = False;

	ZERO_STRUCT(info3);

	DEBUG(5,("api_ntlmssp_verify: checking user details\n"));

	lm_owf_len = ntlmssp_resp->hdr_lm_resp.str_str_len;
	nt_owf_len = ntlmssp_resp->hdr_nt_resp.str_str_len;
	usr_len    = ntlmssp_resp->hdr_usr    .str_str_len;
	dom_len    = ntlmssp_resp->hdr_domain .str_str_len;
	wks_len    = ntlmssp_resp->hdr_wks    .str_str_len;

	if (lm_owf_len <= 1 && nt_owf_len == 0 &&
	    usr_len == 0 && dom_len == 0)
	{
		anonymous = True;
	}
	else
	{
		if (lm_owf_len == 0) return False;
		if (nt_owf_len == 0) return False;
		if (ntlmssp_resp->hdr_usr    .str_str_len == 0) return False;
		if (ntlmssp_resp->hdr_wks    .str_str_len == 0) return False;
	}

	if (lm_owf_len > sizeof(lm_owf)) return False;
	if (nt_owf_len > sizeof(nt_owf)) return False;

	memcpy(lm_owf, ntlmssp_resp->lm_resp, sizeof(lm_owf));
	memcpy(nt_owf, ntlmssp_resp->nt_resp, sizeof(nt_owf));

	dump_data_pw("lm_owf:", lm_owf, sizeof(lm_owf));
	dump_data_pw("nt_owf:", nt_owf, sizeof(nt_owf));
	dump_data_pw("chal:", a->ntlmssp_chal.challenge, 8);

	memset(user_name, 0, sizeof(user_name));
	memset(domain   , 0, sizeof(domain   ));
	memset(wks      , 0, sizeof(wks      ));

	if (IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		unibuf_to_ascii(user_name, ntlmssp_resp->user,
				MIN(ntlmssp_resp->hdr_usr   .str_str_len/2,
				    sizeof(user_name)-1));
		unibuf_to_ascii(domain   , ntlmssp_resp->domain,
				MIN(ntlmssp_resp->hdr_domain.str_str_len/2,
				    sizeof(domain   )-1));
		unibuf_to_ascii(wks      , ntlmssp_resp->wks,
				MIN(ntlmssp_resp->hdr_wks   .str_str_len/2,
				    sizeof(wks      )-1));
	}
	else
	{
		fstrcpy(user_name, ntlmssp_resp->user  );
		fstrcpy(domain   , ntlmssp_resp->domain);
		fstrcpy(wks      , ntlmssp_resp->wks   );
	}

	if (anonymous)
	{
		DEBUG(5,("anonymous user session\n"));
		guest = True;
		safe_strcpy(unix_user, lp_guestaccount(-1), sizeof(unix_user)-1);
		nt_user[0] = 0;
		pw = Get_Pwnam(unix_user, True);
	}
	DEBUG(5,("user: %s domain: %s wks: %s\n",
		          user_name, domain, wks));

	l->auth_validated = check_domain_security(user_name, domain,
				      (const uchar*)a->ntlmssp_chal.challenge,
				      lm_owf, lm_owf_len,
				      nt_owf, nt_owf_len,
				      &info3) == 0x0;

	if (!anonymous && l->auth_validated)
	{
		pw = map_nt_and_unix_username(domain, user_name,
		                              unix_user, nt_user);
		l->auth_validated = pw != NULL;
	}

	if (l->auth_validated)
	{
		become_root(False);
		l->key.pid = getpid();
		l->key.vuid = register_vuid(l->key.pid, pw->pw_uid, pw->pw_gid,
					unix_user, nt_user,
					guest, &info3);
		unbecome_root(False);
		l->auth_validated = l->key.vuid != UID_FIELD_INVALID;
	}

	if (l->auth_validated)
	{
		l->auth_validated = become_vuser(&l->key);
	}

	if (l->auth_validated)
	{
		/************************************************************/
		/****************** lkclXXXX - NTLMv1 ONLY! *****************/
		/************************************************************/

		uchar p24[24];
		uchar j = 0;
		int ind;
		uchar password[16];
		uchar k2[16];
		int len;

		ZERO_STRUCT(password);
		memcpy(password, info3.padding, 8);

		NTLMSSPOWFencrypt(password, lm_owf, p24);

		if (True)
		{
			len = 8;
			memcpy(k2, p24, 5);
			k2[5] = 0xe5;
			k2[6] = 0x38;
			k2[7] = 0xb0;
		}
		else
		{
			len = 16;
			memcpy(k2, p24, 16);
		}

		for (ind = 0; ind < 256; ind++)
		{
			a->ntlmssp_hash[ind] = (uchar)ind;
		}

		for (ind = 0; ind < 256; ind++)
		{
			uchar tc;

			j += (a->ntlmssp_hash[ind] + k2[ind%len]);
			tc = a->ntlmssp_hash[ind];
			a->ntlmssp_hash[ind] = a->ntlmssp_hash[j];
			a->ntlmssp_hash[j] = tc;
		}

		a->ntlmssp_hash[256] = 0;
		a->ntlmssp_hash[257] = 0;
		a->ntlmssp_seq_num = 0;
	}
	else
	{
		l->auth_validated = False;
	}

	return l->auth_validated;
}

static BOOL api_ntlmssp(rpcsrv_struct *l, uint32 msg_type)
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
			if (!api_ntlmssp_verify(l, &ntlmssp_resp))
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

static BOOL api_ntlmssp_bind_auth_resp(rpcsrv_struct *l)
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

	if (!rpc_auth_verifier_chk(&auth_verifier, "NTLMSSP", NTLMSSP_AUTH))
	{
		return False;
	}
	
	return api_ntlmssp(l, auth_verifier.msg_type);
}

static BOOL api_ntlmssp_auth_chk(rpcsrv_struct *l,
				enum RPC_PKT_TYPE pkt_type)
{
	switch (pkt_type)
	{
		case RPC_BINDRESP:
		{
			return api_ntlmssp_bind_auth_resp(l);
		}
		case RPC_BINDACK:
		case RPC_ALTCONTRESP:
		{
			RPC_AUTH_VERIFIER auth_verifier;
			smb_io_rpc_auth_verifier("", &auth_verifier, &l->data_i, 0);
			if (l->data_i.offset == 0) return False;

			if (strequal(auth_verifier.signature, "NTLMSSP"))
			{
				return api_ntlmssp(l, auth_verifier.msg_type);
			}
			break;
		}
		default:
		{
			return False;
		}
	}
	return False;
}

static BOOL api_ntlmssp_auth_gen(rpcsrv_struct *l, prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	BOOL ret;
	uint8 challenge[8];
	RPC_HDR_AUTH  auth_info;
	RPC_AUTH_VERIFIER auth_verifier;
	prs_struct rhdr;
	prs_struct rauth;
	prs_struct rverf;
	prs_struct rntlm;

	ntlmssp_auth_struct *a = (ntlmssp_auth_struct *)l->auth_info;

	prs_init(&(rhdr ), 0, 4, False);
	prs_init(&(rauth), 0, 4, False);
	prs_init(&(rverf), 0, 4, False);
	prs_init(&(rntlm), 0, 4, False);

	generate_random_buffer(challenge, 8, False);

	/*** authentication info ***/

	make_rpc_hdr_auth(&auth_info, 0x0a, 0x06, 0, 1);
	smb_io_rpc_hdr_auth("", &auth_info, &rverf, 0);
	prs_realloc_data(&rverf, rverf.offset);

	/*** NTLMSSP verifier ***/

	make_rpc_auth_verifier(&auth_verifier,
			       "NTLMSSP", NTLMSSP_CHALLENGE);
	smb_io_rpc_auth_verifier("", &auth_verifier, &rauth, 0);
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

static BOOL api_ntlmssp_decode_pdu(rpcsrv_struct *l)
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
		DEBUG(5,("api_pipe_auth_process: auth %d\n",
		          l->data_i.offset + 4));
		NTLMSSPcalc_p(a, (uchar*)prs_data(&l->data_i,
		                                  l->data_i.offset + 4),
		                 12);
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

static BOOL api_ntlmssp_hdr_chk(RPC_HDR_AUTH *auth_info, void **auth_struct)
{
	DEBUG(10,("api_ntlmssp_hdr_chk:\n"));
	if (!rpc_hdr_ntlmssp_auth_chk(auth_info))
	{
		return False;
	}
	(*auth_struct) = (void*)malloc(sizeof(ntlmssp_auth_struct));
	return (*auth_struct) != NULL;
}

srv_auth_fns ntlmssp_fns = 
{
	api_ntlmssp_hdr_chk,
	api_ntlmssp_auth_chk,
	api_ntlmssp_auth_gen,
	api_ntlmssp_decode_pdu,
	api_ntlmssp_create_pdu,
};

