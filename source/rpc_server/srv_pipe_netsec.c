
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

/*******************************************************************
turns a DCE/RPC request into a DCE/RPC reply

this is where the data really should be split up into an array of
headers and data sections.

********************************************************************/
static BOOL api_netsec_create_pdu(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	netsec_auth_struct *a = (netsec_auth_struct *)l->auth_info;

	BOOL ret;
	uint32 data_len;
	uint32 frag_len;
	uint32 auth_len;
	uint32 data_end = l->rdata.offset + 8 + 0x20;
	char *data;

	prs_struct rhdr;
	prs_struct rdata_i;
	prs_struct rauth;
	prs_struct rverf;

	RPC_HDR_RESP  hdr_resp;
	RPC_HDR_AUTH  auth_info;
	RPC_AUTH_NETSEC_CHK verf;
	uchar sign[8];
	static const uchar netsec_sig[8] = NETSEC_SIGNATURE;

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
	hdr_resp.cancel_count = 0x0;
	hdr_resp.context_id   = 0x0;
	hdr_resp.reserved     = 0x0;

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

	data_len = l->hdr.frag_len - auth_len - 8 - 0x18;

	rhdr.start = 0;
	rhdr.end   = 0x18;

	DEBUG(10,("hdr flags: %x\n", l->hdr.flags));

	/* store the header in the data stream */
	smb_io_rpc_hdr     ("rhdr", &(l->hdr  ), &rhdr, 0);
	smb_io_rpc_hdr_resp("resp", &(hdr_resp), &rhdr, 0);

	/* don't use rdata: use rdata_i instead, which moves... */
	/* make a pointer to the rdata data, NOT A COPY */
	data = prs_data(&l->rdata, data_start);
	prs_create(&rdata_i, data, data_len, l->rdata.align, rdata_i.io); 
	rdata_i.offset = data_len;
	l->rdata_offset += data_len;

	prs_debug_out(&rdata_i, "rdata_i", 200);
	prs_debug_out(&l->rdata, "rdata", 200);

	/* happen to know that NETSEC authentication verifier is 32 bytes */
	frag_len = data_len + auth_len + 8 + 0x18;

	prs_init(&rauth , 8       , 4, False);
	prs_init(&rverf, auth_len, 4, False);

	make_rpc_hdr_auth(&auth_info, 0x44, 0x06, 0x0, 1);
	smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &rauth, 0);

	memset(sign, 0, sizeof(sign));
	sign[3] = 0x01;

	make_rpc_auth_netsec_chk(&verf, netsec_sig, NULL, sign, NULL);
	ret = netsec_encode(a, &verf, data, data_len);

	if (ret)
	{
		smb_io_rpc_auth_netsec_chk("auth_sign", &verf, &rverf, 0);
		a->seq_num++;
	}

	if (ret)
	{
		prs_link(NULL     , &rhdr      , &rdata_i  );
		prs_link(&rhdr     , &rdata_i  , &rauth );
		prs_link(&rdata_i , &rauth , &rverf);
		prs_link(&rauth, &rverf, NULL      );

		prs_init(resp, 0, 4, False);
		ret = prs_copy(resp, &rhdr);
	}

	prs_free_data(&rauth);
	prs_free_data(&rverf);
	prs_free_data(&rhdr );

	if (IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_LAST) ||
	    l->hdr.pkt_type == RPC_BINDACK)
	{
		DEBUG(10,("create_netsec_reply: finished sending\n"));
		prs_free_data(&l->rdata);
	}

	return ret;
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

	dump_data_pw("sess_key:\n", a->sess_key, sizeof(a->sess_key));

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
	switch (msg_type)
	{
		case 0x3:
		case 0x13:
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

	if (!netsec_decode(a, &netsec_chk,
	                   prs_data(&l->data_i, old_offset),
	                   data_len))
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

