
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/****************************************************************************
 decrypt data on an rpc pipe
 ****************************************************************************/
static BOOL decode_netsec_pdu(struct cli_connection *con,
				prs_struct *rdata,
				int len, int auth_len)
{
	RPC_AUTH_NETSEC_CHK chk;
	RPC_HDR_AUTH auth_info;
	int data_len = len - 0x18 - auth_len - 8;
	char *reply_data = prs_data(rdata, 0x18);
	uint32 old_offset;

	netsec_auth_struct *a;
	a = (netsec_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	DEBUG(5,("decode_netsec_pdu: len: %d auth_len: %d\n",
	          len, auth_len));

	if (reply_data == NULL) return False;

	if (auth_len != 0x20 )
	{
		return False;
	}

	/*** skip the data, record the offset so we can restore it again */
	old_offset = rdata->offset;

	rdata->offset = data_len + 0x18;
	smb_io_rpc_hdr_auth("hdr_auth", &auth_info, rdata, 0);
	if (!rpc_hdr_netsec_auth_chk(&(auth_info)))
	{
		return False;
	}

	smb_io_rpc_auth_netsec_chk("auth_sign", &chk, rdata, 0);

	if (!netsec_decode(a, &chk, reply_data, data_len))
	{
		return False;
	}

	a->seq_num++;

	/* restore the [data, now decoded] offset */
	rdata->offset = old_offset;

	return True;
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
	prs_struct data_t;
	prs_struct hdr;
	prs_struct hdr_auth;
	prs_struct auth_verf;
	int data_len;
	int frag_len;
	int auth_len;
	char *d = prs_data(data, data_start);
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	netsec_auth_struct *a = NULL;
	BOOL ret;
	RPC_HDR_AUTH  auth_info;
	RPC_AUTH_NETSEC_CHK verf;
	uchar sign[8];
	static const uchar netsec_sig[8] = NETSEC_SIGNATURE;

	a = (netsec_auth_struct *)cli_conn_get_auth_info(con);
	if (a == NULL)
	{
		return False;
	}

	*flags = 0;

	auth_len = 0x20;
	data_len = data->offset - data_start;

	if (data_start == 0)
	{
		(*flags) |= RPC_FLG_FIRST;
	}

	if (data_len > nt->max_recv_frag)
	{
		data_len = nt->max_recv_frag - auth_len - 8 - 0x18;
	}
	else
	{
		(*flags) |= RPC_FLG_LAST;
	}

	(*data_end) += data_len;

	/* happen to know that NETSEC authentication verifier is 16 bytes */
	frag_len = data_len + auth_len + 8 + 0x18;

	prs_init(&data_t   , 0       , 4, False);
	prs_init(&hdr      , frag_len, 4, False);
	prs_init(&hdr_auth , 8       , 4, False);
	prs_init(&auth_verf, auth_len, 4, False);

	prs_append_data(&data_t, d, data_len);
	data_t.end = data_t.data_size;
	data_t.offset = data_t.data_size;

	create_rpc_request(&hdr, nt->key.vuid, op_num, (*flags),
	                                      frag_len, auth_len);

	DEBUG(5,("create_netsec_reply: data %d auth %d\n",
		 data_len, auth_len));

	make_rpc_hdr_auth(&auth_info, 0x44, 0x06, 0x0, 1);
	smb_io_rpc_hdr_auth("hdr_auth", &auth_info, &hdr_auth, 0);

	memset(sign, 0, sizeof(sign));
	sign[4] = 0x80;

	make_rpc_auth_netsec_chk(&verf, netsec_sig, NULL, sign, NULL);

	ret = netsec_encode(a, &verf, prs_data(&data_t, 0),
	                              prs_buf_len(&data_t));

	if (ret)
	{
		smb_io_rpc_auth_netsec_chk("auth_sign", &verf, &auth_verf, 0);
	}

	if (ret)
	{
		prs_link(NULL     , &hdr      , &data_t   );
		prs_link(&hdr     , &data_t   , &hdr_auth );
		prs_link(&data_t  , &hdr_auth , &auth_verf);
		prs_link(&hdr_auth, &auth_verf, NULL      );

		prs_init(dataa, 0, 4, False);
		ret = prs_copy(dataa, &hdr);
	}

	prs_free_data(&hdr_auth );
	prs_free_data(&data_t   );
	prs_free_data(&auth_verf);
	prs_free_data(&hdr      );

	return True;
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

	netsec_auth_struct *a;
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

	a = malloc(sizeof(struct netsec_auth_struct));
	if (a == NULL)
	{
		return False;
	}

	memcpy(a->sess_key, usr->sess_key, sizeof(a->sess_key));

	if (!cli_conn_set_auth_info(con, (void*)a))
	{
		free(a);
		return False;
	}
	return True;
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
