
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;
extern struct pipe_id_info pipe_names[];
extern pstring global_myname;

static void NETSECcalc_ap( struct netsec_auth_struct *a, unsigned char *data, int len)
{
	unsigned char *hash = a->netsec_hash;
    unsigned char index_i = hash[256];
    unsigned char index_j = hash[257];
    int ind;

    for (ind = 0; ind < len; ind++)
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

/****************************************************************************
 decrypt data on an rpc pipe
 ****************************************************************************/

static BOOL decode_netsec_pdu(struct cli_connection *con,
				prs_struct *rdata,
				int len, int auth_len)
{
#if 0
	RPC_AUTH_NETSEC_CHK chk;
	uint32 crc32;

	int data_len = len - 0x18 - auth_len - 8;
	char *reply_data = prs_data(rdata, 0x18);

	BOOL auth_verify;
	BOOL auth_seal  ;

	netsec_auth_struct *a;
	a = (netsec_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	auth_verify = IS_BITS_SET_ALL(a->netsec_chal.neg_flags,
	                              NETSEC_NEGOTIATE_SIGN);
	auth_seal   = IS_BITS_SET_ALL(a->netsec_chal.neg_flags,
	                              NETSEC_NEGOTIATE_SEAL);

	DEBUG(5,("decode_netsec_pdu: len: %d auth_len: %d verify %s seal %s\n",
	          len, auth_len, BOOLSTR(auth_verify), BOOLSTR(auth_seal)));

	if (reply_data == NULL) return False;

	if (auth_seal)
	{
		DEBUG(10,("decode_netsec_pdu: seal\n"));
		dump_data(100, reply_data, data_len);
		NETSECcalc_ap(a, (uchar*)reply_data, data_len);
		dump_data(100, reply_data, data_len);
	}

	if (auth_verify || auth_seal)
	{
		RPC_HDR_AUTH         rhdr_auth; 
		prs_struct auth_req;
		char *data = prs_data(rdata, len - auth_len - 8);
		prs_init(&auth_req , 0x0, 4, True);
		prs_append_data(&auth_req, data, 8);
		smb_io_rpc_hdr_auth("hdr_auth", &rhdr_auth, &auth_req, 0);
		prs_free_data(&auth_req);

		if (!rpc_hdr_netsec_auth_chk(&rhdr_auth))
		{
			return False;
		}
	}

	if (auth_verify)
	{
		prs_struct auth_verf;
		char *data = prs_data(rdata, len - auth_len);
		if (data == NULL) return False;

		DEBUG(10,("decode_netsec_pdu: verify\n"));
		dump_data(100, data, auth_len);
		NETSECcalc_ap(a, (uchar*)(data+4), auth_len - 4);
		prs_init(&auth_verf, 0x0, 4, True);
		prs_append_data(&auth_verf, data, 16);
		smb_io_rpc_auth_netsec_chk("auth_sign", &chk, &auth_verf, 0);
		dump_data(100, data, auth_len);
		prs_free_data(&auth_verf);
	}

	if (auth_verify)
	{
		char *data = prs_data(rdata, 0x18);
		crc32 = crc32_calc_buffer(data_len, data);
		if (!rpc_auth_netsec_chk(&chk, crc32 , a->netsec_seq_num))
		{
			return False;
		}
		a->netsec_seq_num++;
	}
	return True;
#endif
	return False;
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
static BOOL create_netsec_pdu(struct cli_connection *con,
				uint8 op_num,
				prs_struct *data, int data_start, int *data_end,
				prs_struct *dataa,
				uint8 *flags)
{
#if 0
	/* fudge this, at the moment: create the header; memcpy the data.  oops. */
	prs_struct data_t;
	prs_struct hdr;
	prs_struct hdr_auth;
	prs_struct auth_verf;
	int data_len;
	int frag_len;
	int auth_len;
	BOOL auth_verify;
	BOOL auth_seal;
	uint32 crc32 = 0;
	char *d = prs_data(data, data_start);
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	netsec_auth_struct *a = NULL;
	a = (netsec_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	*flags = 0;

	auth_verify = IS_BITS_SET_ALL(a->netsec_chal.neg_flags,
	                              NETSEC_NEGOTIATE_SIGN);
	auth_seal   = IS_BITS_SET_ALL(a->netsec_chal.neg_flags,
	                              NETSEC_NEGOTIATE_SEAL);

	auth_len = (auth_verify ? 16 : 0);
	data_len = data->offset - data_start;

	if (data_start == 0)
	{
		(*flags) |= RPC_FLG_FIRST;
	}

	if (data_len > nt->max_recv_frag)
	{
		data_len = nt->max_recv_frag - (auth_len + (auth_verify ? 8 : 0) + 0x18);
	}
	else
	{
		(*flags) |= RPC_FLG_LAST;
	}

	(*data_end) += data_len;

	/* happen to know that NETSEC authentication verifier is 16 bytes */
	frag_len = data_len + auth_len + (auth_verify ? 8 : 0) + 0x18;

	prs_init(&data_t   , 0       , 4, False);
	prs_init(&hdr      , frag_len, 4, False);
	prs_init(&hdr_auth , 8       , 4, False);
	prs_init(&auth_verf, auth_len, 4, False);

	prs_append_data(&data_t, d, data_len);
	data_t.end = data_t.data_size;
	data_t.offset = data_t.data_size;

	create_rpc_request(&hdr, op_num, (*flags), frag_len, auth_len);

	if (auth_seal)
	{
		char *buf = prs_data(&data_t, 0);
		size_t len = prs_buf_len(&data_t);
		crc32 = crc32_calc_buffer(len, buf);
		NETSECcalc_ap(a, (uchar*)buf, len);
	}

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH         rhdr_auth;

		make_rpc_hdr_auth(&rhdr_auth, 0x44, 0x06, 0x08, (auth_verify ? 1 : 0));
		smb_io_rpc_hdr_auth("hdr_auth", &rhdr_auth, &hdr_auth, 0);
	}

	if (auth_verify)
	{
		RPC_AUTH_NETSEC_CHK chk;

		make_rpc_auth_netsec_chk(&chk, NETSEC_SIGN_VERSION, crc32, a->netsec_seq_num++);
		smb_io_rpc_auth_netsec_chk("auth_sign", &chk, &auth_verf, 0);
		NETSECcalc_ap(a, (uchar*)prs_data(&auth_verf, 4), 12);
	}

	if (auth_seal || auth_verify)
	{
		prs_link(NULL     , &hdr      , &data_t   );
		prs_link(&hdr     , &data_t   , &hdr_auth );
		prs_link(&data_t  , &hdr_auth , &auth_verf);
		prs_link(&hdr_auth, &auth_verf, NULL      );
	}
	else
	{
		prs_link(NULL, &hdr   , &data_t);
		prs_link(&hdr, &data_t, NULL   );
	}

	DEBUG(100,("frag_len: 0x%x data_len: 0x%x data_calc_len: 0x%x\n",
		frag_len, data_len, prs_buf_len(&data_t)));

	if (frag_len != prs_buf_len(&hdr))
	{
		DEBUG(0,("expected fragment length does not match\n"));

		prs_free_data(&hdr_auth );
		prs_free_data(&auth_verf);
		prs_free_data(&hdr      );
		prs_free_data(&data_t   );

		return False;
	}

	DEBUG(100,("create_netsec_pdu: %d\n", __LINE__));

	/* this is all a hack */
	prs_init(dataa, prs_buf_len(&hdr), 4, False);
	prs_debug_out(dataa, "create_netsec_pdu", 200);
	prs_buf_copy(dataa->data, &hdr, 0, frag_len);

	DEBUG(100,("create_netsec_pdu: %d\n", __LINE__));

	prs_free_data(&hdr_auth );
	prs_free_data(&auth_verf);
	prs_free_data(&hdr      );
	prs_free_data(&data_t   );

	return True;
#endif
	return False;
}

/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_netsec_bind_req(struct cli_connection *con,
				prs_struct *data,
				uint32 rpc_call_id,
                                RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	prs_struct rhdr;
	prs_struct rhdr_rb;
	prs_struct rhdr_auth;
	prs_struct auth_req;

	RPC_HDR_RB           hdr_rb;
	RPC_HDR              hdr;
	RPC_HDR_AUTH         hdr_auth;
	RPC_AUTH_VERIFIER    auth_verifier;
	RPC_AUTH_NETSEC_NEG  netsec_neg;

	struct netsec_creds *usr;
	usr = (struct netsec_creds*)cli_conn_get_auth_creds(con);

	prs_init(&rhdr     , 0x10, 4, False);
	prs_init(&rhdr_rb  , 0x0 , 4, False);
	prs_init(&rhdr_auth, 8   , 4, False);
	prs_init(&auth_req , 0x0 , 4, False);

	/* create the bind request RPC_HDR_RB */
	make_rpc_hdr_rb(&hdr_rb, 0x1630, 0x1630, 0x0,
	                0x1, 0x0, 0x1, abstract, transfer);

	/* stream the bind request data */
	smb_io_rpc_hdr_rb("", &hdr_rb,  &rhdr_rb, 0);

	make_rpc_hdr_auth(&hdr_auth, 0x44, 0x06, 0x00, 1);
	smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, &rhdr_auth, 0);

	make_rpc_auth_verifier(&auth_verifier, "", 0x3);

	smb_io_rpc_auth_verifier("auth_verifier", &auth_verifier, &auth_req, 0);

	make_rpc_auth_netsec_neg(&netsec_neg, usr->domain, usr->myname);

	smb_io_rpc_auth_netsec_neg("netsec_neg", &netsec_neg, &auth_req, 0);

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BIND, 0x0, rpc_call_id,
	             auth_req .offset + rhdr_auth.offset +
	             rhdr_rb.offset + 0x10,
	             auth_req .offset);

	smb_io_rpc_hdr("hdr"   , &hdr   , &rhdr, 0);

	if (rhdr.data == NULL || rhdr_rb.data == NULL) return False;

	/***/
	/*** link rpc header, bind ack and auth responses ***/
	/***/

	prs_link(NULL      , &rhdr      , &rhdr_rb  );
	prs_link(&rhdr     , &rhdr_rb   , &rhdr_auth);
	prs_link(&rhdr_rb  , &rhdr_auth , &auth_req );
	prs_link(&rhdr_auth, &auth_req  , NULL      );

	prs_init(data, prs_buf_len(&rhdr), 4, False);
	prs_buf_copy(data->data, &rhdr, 0, prs_buf_len(&rhdr));

	prs_free_data(&rhdr     );
	prs_free_data(&rhdr_rb  );
	prs_free_data(&rhdr_auth);
	prs_free_data(&auth_req );

	return cli_conn_set_auth_info(con,
	             (void*)malloc(sizeof(struct netsec_auth_struct)));
}

static BOOL decode_netsec_bind_resp(struct cli_connection *con,
				prs_struct *rdata)
{
	BOOL valid_ack = True;
	netsec_auth_struct *a;
	a = (netsec_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	if (valid_ack)
	{
		RPC_HDR_AUTH rhdr_auth;
		smb_io_rpc_hdr_auth("", &rhdr_auth, rdata, 0);
		if (rdata->offset == 0 ||
		    !rpc_hdr_netsec_auth_chk(&rhdr_auth))
		{
			valid_ack = False;
		}
	}
	if (valid_ack)
	{
		RPC_AUTH_VERIFIER rhdr_verf;
		smb_io_rpc_auth_verifier("", &rhdr_verf, rdata, 0);
		if (rdata->offset == 0 ||
		    !rpc_auth_verifier_chk(&rhdr_verf, "\001", 0))
		{
			valid_ack = False;
		}
	}
	if (valid_ack)
	{
		RPC_AUTH_NETSEC_RESP rresp;
		smb_io_rpc_auth_netsec_resp("", &rresp, rdata, 0);
		if (rdata->offset == 0) valid_ack = False;
		if (rresp.flags != 0x05)
		{
			valid_ack = False;
		}
	}
	return valid_ack;
}

cli_auth_fns cli_netsec_fns =
{
	create_netsec_bind_req,
	decode_netsec_bind_resp,
	NULL,
	create_netsec_pdu,
	decode_netsec_pdu
};
