
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe server routines
 *  Copyright (C) Andrew Tridgell              1992-2000
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
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

static void netsechash(uchar *key, uchar *data, int data_len)
{
  uchar hash[256];
  uchar index_i = 0;
  uchar index_j = 0;
  uchar j = 0;
  int ind;

  for (ind = 0; ind < 256; ind++)
  {
    hash[ind] = (uchar)ind;
  }

  for( ind = 0; ind < 256; ind++)
  {
     uchar tc;

     j += (hash[ind] + key[ind%16]);

     tc = hash[ind];
     hash[ind] = hash[j];
     hash[j] = tc;
  }

  for( ind = 0; ind < data_len; ind++)
  {
    uchar tc;
    uchar t;

    index_i++;
    index_j += hash[index_i];

    tc = hash[index_i];
    hash[index_i] = hash[index_j];
    hash[index_j] = tc;

    t = hash[index_i] + hash[index_j];
    data[ind] ^= hash[t];
  }
}


static BOOL netsec_decode(struct netsec_auth_struct *a,
				RPC_AUTH_NETSEC_CHK *verf,
				char *data, size_t data_len)
{
	char dataN[4];
	char digest1[16]; 
	struct MD5Context ctx3; 

	/* store the sequence number */
	SIVAL(dataN, 0, a->seq_num);

	dump_data_pw("a->sess_key:\n", a->sess_key, sizeof(a->sess_key));
	hmac_md5(a->sess_key, dataN , 0x4, digest1 );
	dump_data_pw("ctx:\n", digest1, sizeof(digest1));

	hmac_md5(digest1, verf->data1, 8, digest1);

	dump_data_pw("netsechashkey:\n", digest1, sizeof(digest1));
	dump_data_pw("verf->data3:\n", verf->data3, sizeof(verf->data3));
	netsechash(digest1, verf->data3, 8);
	dump_data_pw("verf->data3_dec:\n", verf->data3, sizeof(verf->data3));

	MD5Init(&ctx3);
	MD5Update(&ctx3, dataN, 0x4);
	MD5Update(&ctx3, verf->sig, 8);

	dump_data_pw("a->sess_kf0:\n", a->sess_kf0, sizeof(a->sess_kf0));

	hmac_md5(a->sess_kf0, dataN, 0x4, digest1 );
	dump_data_pw("digest1 (ebp-8):\n", digest1, sizeof(digest1));
	hmac_md5(digest1, verf->data3, 8, digest1);
	dump_data_pw("netsechashkey:\n", digest1, sizeof(digest1));

	dump_data_pw("verf->data8:\n", verf->data8, sizeof(verf->data8));
	netsechash(digest1, verf->data8, 8);
	dump_data_pw("verf->data8_dec:\n", verf->data8, sizeof(verf->data8));
	MD5Update(&ctx3, verf->data8, 8); 

	dump_data_pw("data   :\n", data, data_len);
	netsechash(digest1, data , data_len);
	dump_data_pw("datadec:\n", data, data_len);

	MD5Update(&ctx3, data, data_len); 
	{
		char digest_tmp[16];
		MD5Final(digest_tmp, &ctx3);
		hmac_md5(digest_tmp, a->sess_key, 16, digest1);
	}

	dump_data_pw("digest:\n", digest1, sizeof(digest1));

	return True;
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

	DEBUG(5,("api_netsec_create_pdu: data_start: %d data_end: %d max_tsize: %d\n",
	          data_start, data_end, l->hdr_ba.bba.max_tsize));

	auth_len = l->hdr.auth_len;

	DEBUG(10,("api_netsec_create_pdu: auth\n"));

	if (auth_len != 0x20)
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
		a->seq_num++;
		make_rpc_auth_netsec_chk(&netsec_chk,
					  NETSEC_SIGN_VERSION, crc32,
					  a->seq_num);
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

static BOOL api_netsec_verify(rpcsrv_struct *l)
{
	netsec_auth_struct *a = (netsec_auth_struct *)l->auth_info;
	struct dcinfo dc;
	int i;

	DEBUG(5,("api_netsec_verify: checking credential details\n"));

	/*
	 * obtain the session key
	 */
	if (!cred_get(a->netsec_neg.domain, a->netsec_neg.myname, &dc))
	{
		return False;
	}

	l->auth_validated = True;

	memset(a->sess_key, 0, sizeof(a->sess_key));
	memcpy(a->sess_key, dc.sess_key, sizeof(dc.sess_key));

	for (i = 0; i < sizeof(a->sess_key); i++)
	{
		a->sess_kf0[i] = a->sess_key[i] ^ 0xf0;
	}

	dump_data_pw("sess_key:\n", a->sess_key, sizeof(a->sess_key));
	dump_data_pw("sess_kf0:\n", a->sess_kf0, sizeof(a->sess_kf0));

	if (l->auth_validated)
	{
		a->seq_num = 0;
	}
	else
	{
		l->auth_validated = False;
	}

	return l->auth_validated;
}

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

			return api_netsec_verify(l);
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
	netsec_auth_struct *a = (netsec_auth_struct *)l->auth_info;
	int data_len;
	int auth_len;
	uint32 old_offset;
	RPC_HDR_AUTH auth_info;
	RPC_AUTH_NETSEC_CHK netsec_chk;
	char *data = prs_data(&l->data_i, l->data_i.offset);

	auth_len = l->hdr.auth_len;

	if (auth_len != 0x20 )
	{
		return False;
	}

	data_len = l->hdr.frag_len - auth_len - 8 - 0x18;
	
	DEBUG(5,("api_pipe_auth_process: data %d auth %d\n",
	         data_len, auth_len));

	/*** skip the data, record the offset so we can restore it again */
	old_offset = l->data_i.offset;

	l->data_i.offset += data_len;
	smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &l->data_i, 0);
	if (!rpc_hdr_netsec_auth_chk(&(auth_info))) return False;

	smb_io_rpc_auth_netsec_chk("auth_sign", &netsec_chk, &l->data_i, 0);

	if (!netsec_decode(a, &netsec_chk, data, data_len))
	{
		return False;
	}

	/* restore the [data, now decoded] offset */
	l->data_i.offset = old_offset;

	return True;
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

