
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

/********************************************************************
 rpc pipe call id 
 ********************************************************************/
static uint32 get_rpc_call_id(void)
{
  static uint32 call_id = 0;
  return ++call_id;
}

/*******************************************************************
 uses SMBreadX to get rest of rpc data
 ********************************************************************/

static BOOL rpc_read(struct cli_state *cli, uint16 fnum,
                     prs_struct *rdata, uint32 data_to_read,
                     uint32 rdata_offset, BOOL one_only)
{
	size_t size = cli->nt.max_recv_frag;
	int file_offset = 0;
	int num_read;
	char *data;
	uint32 new_data_size = rdata_offset + data_to_read;
	uint8 cls;
	uint32 type;

	DEBUG(5,("rpc_read: data_to_read: %d data offset: %d file offset: %d\n",
	data_to_read, rdata_offset, file_offset));

	if (new_data_size > rdata->data_size)
	{
		prs_grow_data(rdata, True, new_data_size, True);
		DEBUG(5,("rpc_read: grow buffer to %d\n", rdata->data_size));
	}

	data = rdata->data + rdata_offset;

	do /* read data using SMBreadX */
	{
		if (size > data_to_read)
		{
			size = data_to_read;
		}

		num_read = cli_read_one(cli, fnum, data, file_offset, size);

		DEBUG(5,("rpc_read: read offset: %d read: %d to read: %d\n",
		          file_offset, num_read, data_to_read));

		data_to_read -= num_read;
		file_offset  += num_read;
		data         += num_read;

		if (cli_error(cli, &cls, &type))
		{
			if (cls != ERRDOS || type != ERRmoredata)
			{
				return False;
			}
		}

	} while (!one_only && num_read > 0 && data_to_read > 0);

	rdata->end = new_data_size;

	DEBUG(5,("rpc_read: offset end: 0x%x.  data left to read:0x%x\n",
	          rdata->end, data_to_read));

	return True;
}

/****************************************************************************
 checks the header
 ****************************************************************************/
static BOOL rpc_check_hdr(prs_struct *rdata, RPC_HDR *rhdr, 
                          BOOL *first, BOOL *last, int *len)
{
	DEBUG(5,("rpc_check_hdr: rdata->data_size: %d\n", rdata->data_size));

	smb_io_rpc_hdr   ("rpc_hdr   ", rhdr   , rdata, 0);

	if (!rdata->offset || rdata->offset != 0x10)
	{
		DEBUG(0,("rpc_check_hdr: error in rpc header\n"));
		return False;
	}

	DEBUG(5,("rpc_check_hdr: (after smb_io_rpc_hdr call) rdata->data_size: %d\n",
	          rdata->data_size));

	(*first   ) = IS_BITS_SET_ALL(rhdr->flags, RPC_FLG_FIRST);
	(*last    ) = IS_BITS_SET_ALL(rhdr->flags, RPC_FLG_LAST );
	(*len     ) = rhdr->frag_len - rdata->data_size;

	return rhdr->pkt_type != RPC_FAULT;
}

static void NTLMSSPcalc_ap( struct ntdom_info *nt, unsigned char *data, int len)
{
	unsigned char *hash = nt->ntlmssp_hash;
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

/****************************************************************************
 decrypt data on an rpc pipe
 ****************************************************************************/

static BOOL rpc_auth_pipe(struct ntdom_info *nt, prs_struct *rdata,
				int len, int auth_len)
{
	RPC_AUTH_NTLMSSP_CHK chk;
	uint32 crc32;
	int data_len = len - 0x18 - auth_len - 8;
	char *reply_data = prs_data(rdata, 0x18);

	BOOL auth_verify = IS_BITS_SET_ALL(nt->ntlmssp_srv_flgs, NTLMSSP_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(nt->ntlmssp_srv_flgs, NTLMSSP_NEGOTIATE_SEAL);

	DEBUG(5,("rpc_auth_pipe: len: %d auth_len: %d verify %s seal %s\n",
	          len, auth_len, BOOLSTR(auth_verify), BOOLSTR(auth_seal)));

	if (reply_data == NULL) return False;

	if (auth_seal)
	{
		DEBUG(10,("rpc_auth_pipe: seal\n"));
		dump_data(100, reply_data, data_len);
		NTLMSSPcalc_ap(nt, (uchar*)reply_data, data_len);
		dump_data(100, reply_data, data_len);
	}

	if (auth_verify || auth_seal)
	{
		RPC_HDR_AUTH         rhdr_auth; 
		prs_struct auth_req;
		char *data = prs_data(rdata, len - auth_len - 8);
		prs_init(&auth_req , 0x08, 4, True);
		memcpy(auth_req.data, data, 8);
		smb_io_rpc_hdr_auth("hdr_auth", &rhdr_auth, &auth_req, 0);
		prs_free_data(&auth_req);

		if (!rpc_hdr_ntlmssp_auth_chk(&rhdr_auth))
		{
			return False;
		}
	}

	if (auth_verify)
	{
		prs_struct auth_verf;
		char *data = prs_data(rdata, len - auth_len);
		if (data == NULL) return False;

		DEBUG(10,("rpc_auth_pipe: verify\n"));
		dump_data(100, data, auth_len);
		NTLMSSPcalc_ap(nt, (uchar*)(data+4), auth_len - 4);
		prs_init(&auth_verf, 0x08, 4, True);
		memcpy(auth_verf.data, data, 16);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &chk, &auth_verf, 0);
		dump_data(100, data, auth_len);
		prs_free_data(&auth_verf);
	}

	if (auth_verify)
	{
		crc32 = crc32_calc_buffer(data_len, reply_data);
		if (!rpc_auth_ntlmssp_chk(&chk, crc32 , nt->ntlmssp_seq_num))
		{
			return False;
		}
		nt->ntlmssp_seq_num++;
	}
	return True;
}

/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_rpc_request(prs_struct *rhdr, uint8 op_num, uint8 flags,
				int data_len,
				int auth_len)
{
	uint32 alloc_hint;
	RPC_HDR_REQ hdr_req;
	RPC_HDR     hdr;

	DEBUG(5,("create_rpc_request: opnum: 0x%x data_len: 0x%x\n",
	op_num, data_len));

	/* create the rpc header RPC_HDR */
	make_rpc_hdr(&hdr   , RPC_REQUEST, flags,
	             get_rpc_call_id(), data_len, auth_len);

	if (auth_len != 0)
	{
		alloc_hint = data_len - 0x18 - auth_len - 16;
	}
	else
	{
		alloc_hint = data_len - 0x18;
	}

	DEBUG(10,("create_rpc_request: data_len: %x auth_len: %x alloc_hint: %x\n",
	           data_len, auth_len, alloc_hint));

	/* create the rpc request RPC_HDR_REQ */
	make_rpc_hdr_req(&hdr_req, alloc_hint, op_num);

	/* stream-time... */
	smb_io_rpc_hdr    ("hdr    ", &hdr    , rhdr, 0);
	smb_io_rpc_hdr_req("hdr_req", &hdr_req, rhdr, 0);

	if (rhdr->data == NULL || rhdr->offset != 0x18) return False;

	rhdr->start = 0;
	rhdr->end   = rhdr->offset;

	return True;
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
static BOOL create_request_pdu(struct cli_connection *con,
				uint8 op_num,
				prs_struct *data, int data_start, int *data_end,
				prs_struct *dataa,
				uint8 *flags)
{
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
	*flags = 0;

	auth_verify = IS_BITS_SET_ALL(nt->ntlmssp_srv_flgs, NTLMSSP_NEGOTIATE_SIGN);
	auth_seal   = IS_BITS_SET_ALL(nt->ntlmssp_srv_flgs, NTLMSSP_NEGOTIATE_SEAL);

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

	/* happen to know that NTLMSSP authentication verifier is 16 bytes */
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
		crc32 = crc32_calc_buffer(frag_len, d);
		NTLMSSPcalc_ap(nt, (uchar*)d, frag_len);
	}

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH         rhdr_auth;

		make_rpc_hdr_auth(&rhdr_auth, 0x0a, 0x06, 0x08, (auth_verify ? 1 : 0));
		smb_io_rpc_hdr_auth("hdr_auth", &rhdr_auth, &hdr_auth, 0);
	}

	if (auth_verify)
	{
		RPC_AUTH_NTLMSSP_CHK chk;

		make_rpc_auth_ntlmssp_chk(&chk, NTLMSSP_SIGN_VERSION, crc32, nt->ntlmssp_seq_num++);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &chk, &auth_verf, 0);
		NTLMSSPcalc_ap(nt, (uchar*)prs_data(&auth_verf, 4), 12);
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

	if (data_len != prs_buf_len(&data_t))
	{
		prs_free_data(&hdr_auth );
		prs_free_data(&auth_verf);
		prs_free_data(&hdr      );
		prs_free_data(&data_t   );
	
		return False;
	}

	DEBUG(100,("create_request_pdu: %d\n", __LINE__));

	/* this is all a hack */
	prs_init(dataa, prs_buf_len(&hdr), 4, False);
	prs_debug_out(dataa, "create_request_pdu", 200);
	prs_buf_copy(dataa->data, &hdr, 0, frag_len);

	DEBUG(100,("create_request_pdu: %d\n", __LINE__));

	prs_free_data(&hdr_auth );
	prs_free_data(&auth_verf);
	prs_free_data(&hdr      );
	prs_free_data(&data_t   );

	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...

 read the first fragment: unfortunately have to use SMBtrans for the first
 bit, then SMBreadX for subsequent bits.

 if first fragment received also wasn't the last fragment, continue
 getting fragments until we _do_ receive the last fragment.

 ****************************************************************************/

BOOL rpc_api_pipe_bind(struct cli_connection *con, prs_struct *data, prs_struct *rdata)
{
	int len;

	BOOL first = True;
	BOOL last  = True;
	RPC_HDR    rhdr;
	prs_struct rpdu;
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);

	prs_init(&rpdu, 0, 4, True);

	rpc_api_send_rcv_pdu(con, data, &rpdu);

	/**** parse the header: check it's a response record */

	rpdu.start = 0;
	rpdu.end   = rpdu.data_size;
	rpdu.offset = 0;

	if (!rpc_check_hdr(&rpdu, &rhdr, &first, &last, &len))
	{
		return False;
	}

	if (rhdr.pkt_type != RPC_BINDACK)
	{
		return False;
	}
	if (!last && !first)
	{
		DEBUG(5,("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
		first = True;
		last = True;
	}

	if (rhdr.auth_len != 0 && !rpc_auth_pipe(nt, &rpdu, rhdr.frag_len, rhdr.auth_len))
	{
		return False;
	}

	{
		char *d = prs_data(&rpdu, rpdu.offset);
		int l = rhdr.frag_len - rpdu.offset;
		prs_append_data(rdata, d, l);
		prs_free_data(&rpdu);
	}

	/* only one rpc fragment, and it has been read */
	if (!first || !last)
	{
		return False;
	}

	DEBUG(6,("cli_pipe: fragment first and last both set\n"));

	return True;
}

/****************************************************************************
 receive response data from an rpc pipe, which may be large...

 read the first fragment: unfortunately have to use SMBtrans for the first
 bit, then SMBreadX for subsequent bits.

 if first fragment received also wasn't the last fragment, continue
 getting fragments until we _do_ receive the last fragment.

 ****************************************************************************/
BOOL rpc_api_pipe_req(struct cli_connection *con, uint8 opnum,
				prs_struct *data,
				prs_struct *rdata)
{
	int len;

	BOOL first = True;
	BOOL last  = True;
	RPC_HDR    rhdr;
	prs_struct rpdu;
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	uint8 flags;

	int data_start = 0;
	int data_end = 0;

	prs_init(&rpdu, 0, 4, True);

	do
	{
		prs_struct data_t;

		DEBUG(10,("rpc_api_pipe_req: start: %d off: %d\n",
			data_start, data->offset));

		if (!create_request_pdu(con, opnum, data, data_start,
		                 &data_end, &data_t, &flags))
		{
			return False;
		}
		
		DEBUG(10,("rpc_api_pipe_req: end: %d\n", data_end));
		dbgflush();

		if (IS_BITS_CLR_ALL(flags, RPC_FLG_LAST))
		{
			if (!rpc_api_write(con, &data_t))
			{
				prs_free_data(&data_t);
				return False;
			}
		} 
		else
		{
			if (!rpc_api_send_rcv_pdu(con, &data_t, &rpdu))
			{
				prs_free_data(&data_t);
				return False;
			}

			if (data_end != data->offset)
			{
				prs_free_data(&rpdu);
				prs_init(&rpdu, 0, 4, True);
			}
		}

		prs_free_data(&data_t);
		data_start = data_end;

	} while (data_end < data->offset);

	if (data_end != data->offset)
	{
		DEBUG(2,("rpc_api_pipe_req: data_end: %d and offset %d wrong\n",
		          data_end, data->offset));
		prs_free_data(&rpdu);
		return False;
	}

	/**** parse the header: check it's a response record */

	rpdu.start = 0;
	rpdu.end   = rpdu.data_size;
	rpdu.offset = 0;

	if (!rpc_check_hdr(&rpdu, &rhdr, &first, &last, &len))
	{
		return False;
	}

	if (rhdr.pkt_type == RPC_BINDACK)
	{
		if (!last && !first)
		{
			DEBUG(5,("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
			first = True;
			last = True;
		}
	}

	if (rhdr.pkt_type == RPC_RESPONSE)
	{
		RPC_HDR_RESP rhdr_resp;
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, &rpdu, 0);
	}

	if (rhdr.auth_len != 0 && !rpc_auth_pipe(nt, &rpdu, rhdr.frag_len, rhdr.auth_len))
	{
		return False;
	}

	{
		char *d = prs_data(&rpdu, rpdu.offset);
		int l = rhdr.frag_len - rpdu.offset;
		prs_append_data(rdata, d, l);
		prs_free_data(&rpdu);
	}

	/* only one rpc fragment, and it has been read */
	if (first && last)
	{
		DEBUG(6,("cli_pipe: fragment first and last both set\n"));
		return True;
	}

	DEBUG(100,("first frag: %s", BOOLSTR(first)));
	DEBUG(100,("last frag: %s\n", BOOLSTR(last)));

	while (!last) /* read more fragments until we get the last one */
	{
		RPC_HDR_RESP rhdr_resp;
		int num_read;

		DEBUG(10,("rpc_api_pipe: another fragment expected\n"));

		prs_init(&rpdu, 0x18, 4, True);

		rpc_api_rcv_pdu(con, &rpdu);

		rpdu.start = 0;
		rpdu.end   = rpdu.data_size;
		rpdu.offset = 0;
		num_read = rpdu.data_size;

		DEBUG(5,("cli_pipe: read header (size:%d)\n", num_read));

		if (!rpc_check_hdr(&rpdu, &rhdr, &first, &last, &len))
		{
			prs_free_data(&rpdu);
			return False;
		}

		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, &rpdu, 0);

		if (first)
		{
			DEBUG(0,("cli_pipe: wierd rpc header received\n"));
			prs_free_data(&rpdu);
			return False;
		}

		if (rhdr.auth_len != 0 &&
		    !rpc_auth_pipe(nt, &rpdu, rhdr.frag_len, rhdr.auth_len))
		{
			prs_free_data(&rpdu);
			return False;
		}

		{
			char *d = prs_data(&rpdu, rpdu.offset);
			int l = rhdr.frag_len - rpdu.offset;
			prs_append_data(rdata, d, l);
			prs_free_data(&rpdu);
		}
	}

	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...

 read the first fragment: unfortunately have to use SMBtrans for the first
 bit, then SMBreadX for subsequent bits.

 if first fragment received also wasn't the last fragment, continue
 getting fragments until we _do_ receive the last fragment.

 [note: from a data abstraction viewpoint, this function is marginally
        complicated by the return side of cli_api_pipe getting in the way
        (i.e, the SMB header stuff).  the proper way to do this is to split
        cli_api_pipe down into receive / transmit.  oh, and split cli_readx
        down.  in other words, state-based (kernel) techniques...]

 ****************************************************************************/

static BOOL cli_send_trans_data(struct cli_state *cli, uint16 fnum,
			prs_struct *data,
			int max_data_len,
			prs_struct *rdata)
{
	uint16 cmd = 0x0026;
	uint16 setup[2]; /* only need 2 uint16 setup parameters */

	char *rparam = NULL;
	uint32 rparam_len = 0;

	/*
	 * Setup the pointers to the outgoing.
	 */
	char *rdata_t = NULL;
	uint32 rdata_len = 0;
	char *pipe_name = "\\PIPE\\\0\0\0";
	int pipe_len = 8;
	int setup_len = 2;

	/*
	 * Setup the pointers from the incoming.
	 */
	char *pdata = prs_data(data, 0);
	int data_len = data ? (data->data_size): 0;
	data_len = MIN(max_data_len, data_len);

	/* create setup parameters. */
	setup[0] = cmd; 
	setup[1] = fnum; /* pipe file handle.  got this from an SMBOpenX. */

	DEBUG(5,("cli_send_trans_data: data_len: %d cmd:%x fnum:%x\n",
				data_len, cmd, fnum));

	/* send the data: receive a response. */
	if (!cli_api_pipe(cli, pipe_name, pipe_len,
		  setup, setup_len, 0,   /* Setup, length, max */
		  NULL, 0, 0,          /* Params, length, max */
		  pdata, data_len, max_data_len,           /* data, length, max */                  
	            &rparam, &rparam_len,        /* return param, length */
		    &rdata_t, &rdata_len))    /* return data, len */
	{
		fstring errstr;
		cli_safe_errstr(cli, errstr, sizeof(errstr)-1);
		DEBUG(0, ("cli_pipe: return critical error. Error was %s\n", errstr));
		return False;
	}

	if (rparam) free(rparam);

	if (rdata_len != 0)
	{
		return prs_append_data(rdata, rdata_t, rdata_len);
	}
	
	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...
 ****************************************************************************/
BOOL cli_send_and_rcv_pdu_trans(struct cli_state *cli, uint16 fnum,
			prs_struct *data, prs_struct *rdata,
			int max_send_pdu)
{
	int len;
	uint16 cmd = 0x0026;

	BOOL first = True;
	BOOL last  = True;
	RPC_HDR    rhdr;
	size_t data_len  = data->data_size;
	int max_data_len = MAX(data_len, 2048);
	DEBUG(5,("cli_send_and_rcv_pdu_trans: cmd:%x fnum:%x\n", cmd, fnum));

	DEBUG(10,("cli_send_and_rcv_pdu_trans: len: %d\n", data_len));

	if (!cli_send_trans_data(cli, fnum,
		data, max_data_len, rdata))
	{
		return False;
	}

	if (rdata->data == NULL) return False;

	/**** parse the header: check it's a response record */

	rdata->start = 0;
	rdata->end   = rdata->data_size;
	rdata->offset = 0;

	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len))
	{
		return False;
	}

	if (rhdr.pkt_type == RPC_BINDACK)
	{
		if (!last && !first)
		{
			DEBUG(5,("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
			first = True;
			last = True;
		}
	}

#if 0
	if (rhdr.pkt_type == RPC_RESPONSE)
	{
		RPC_HDR_RESP rhdr_resp;
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0);
	}
#endif

	DEBUG(5,("cli_pipe: len left: %d smbtrans read: %d\n",
		  len, rdata->data_size));

	/* check if data to be sent back was too large for one SMB. */
	/* err status is only informational: the _real_ check is on the length */
	if (len > 0) /* || err == (0x80000000 | STATUS_BUFFER_OVERFLOW)) */
	{
		if (!rpc_read(cli, fnum, rdata, len, rdata->data_size, False))
		{
			return False;
		}
	}

	if (rhdr.auth_len != 0 && !rpc_auth_pipe(&cli->nt, rdata, rhdr.frag_len, rhdr.auth_len))
	{
		return False;
	}
	
	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...
 ****************************************************************************/

BOOL cli_send_and_rcv_pdu_rw(struct cli_state *cli, uint16 fnum,
			prs_struct *data, prs_struct *rdata,
			int max_send_pdu)
{
	int len;
	int data_offset = 0;
	uint16 cmd = 0x0026;

	BOOL first = True;
	BOOL last  = True;
	RPC_HDR    rhdr;
	int max_data_len = 2048;
	int write_mode = 0x000c;
	char *d = NULL;
	size_t data_left = data->data_size;
	size_t data_len  = data->data_size;
	DEBUG(5,("cli_send_and_rcv_pdu_rw: cmd:%x fnum:%x\n", cmd, fnum));

	while (data_offset < data_len)
	{
		DEBUG(10,("cli_send_and_rcv_pdu_rw: off: %d len: %d left: %d\n",
			   data_offset, data_len, data_left));

		if (d == NULL)
		{
			d = (char*)malloc(data_left + 2);

			if (d == NULL)
			{
				return False;
			}
			SSVAL(d, 0, data_len);
			memcpy(d+2, data->data, data_len);
			data_len += 2;
		}
		max_data_len = MIN(max_data_len, data_len - data_offset);
		if (cli_write(cli, fnum, write_mode,
			      d, data_offset,
			      max_data_len,
			      data_left) != max_data_len)
		{	
			return False;
		}
		write_mode = 0x0004;
		d += max_data_len;
		data_offset += max_data_len;
		data_left   -= max_data_len;
	}
	if (!rpc_read(cli, fnum, rdata, max_send_pdu, 0, True))
	{
		return False;
	}

	if (rdata->data == NULL) return False;

	/**** parse the header: check it's a response record */

	rdata->start = 0;
	rdata->end   = rdata->data_size;
	rdata->offset = 0;

	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len))
	{
		return False;
	}

	if (rhdr.pkt_type == RPC_BINDACK)
	{
		if (!last && !first)
		{
			DEBUG(5,("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
			first = True;
			last = True;
		}
	}

	if (rhdr.pkt_type == RPC_RESPONSE)
	{
		RPC_HDR_RESP rhdr_resp;
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0);
	}

	DEBUG(5,("cli_pipe: len left: %d smbtrans read: %d\n",
		  len, rdata->data_size));

	/* check if data to be sent back was too large for one SMB. */
	/* err status is only informational: the _real_ check is on the length */
	if (len > 0)
	{
		if (!rpc_read(cli, fnum, rdata, len, rdata->data_size, False))
		{
			return False;
		}
	}

	if (rhdr.auth_len != 0 && !rpc_auth_pipe(&cli->nt, rdata, rhdr.frag_len, rhdr.auth_len))
	{
		return False;
	}
	
	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...
 ****************************************************************************/
BOOL cli_send_and_rcv_pdu(struct cli_state *cli, uint16 fnum,
			prs_struct *data, prs_struct *rdata,
			int max_send_pdu)
{
	if (True)
	{
		return cli_send_and_rcv_pdu_trans(cli, fnum, data, rdata, max_send_pdu);
	}
	else
	{
		return cli_send_and_rcv_pdu_rw(cli, fnum, data, rdata, max_send_pdu);
	}
}

BOOL cli_rcv_pdu(struct cli_state *cli, uint16 fnum, prs_struct *rdata)
{
	RPC_HDR_RESP rhdr_resp;
	RPC_HDR    rhdr;
	int num_read;
	BOOL first = True;
	BOOL last  = True;
	int len;

	num_read = cli_read_one(cli, fnum, rdata->data, 0, 0x18);
	DEBUG(5,("cli_pipe: read header (size:%d)\n", num_read));

	if (num_read != 0x18) return False;

	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len))
	{
		return False;
	}

	smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0);

	if (!rpc_read(cli, fnum, rdata, len, rdata->data_size, False))
	{
		return False;
	}

	if (rhdr.auth_len != 0 &&
	    !rpc_auth_pipe(&cli->nt, rdata, rhdr.frag_len, rhdr.auth_len))
	{
		return False;
	}

	return True;
}

/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_rpc_bind_req(prs_struct *rhdr,
                                prs_struct *rhdr_rb,
                                prs_struct *rhdr_auth,
                                prs_struct *auth_req,
                                prs_struct *auth_ntlm,
				uint32 rpc_call_id,
                                RPC_IFACE *abstract, RPC_IFACE *transfer,
                                char *my_name, char *domain, uint32 neg_flags)
{
	RPC_HDR_RB           hdr_rb;
	RPC_HDR              hdr;
	RPC_HDR_AUTH         hdr_auth;
	RPC_AUTH_NTLMSSP_VERIFIER auth_verifier;
	RPC_AUTH_NTLMSSP_NEG ntlmssp_neg;

	/* create the bind request RPC_HDR_RB */
	make_rpc_hdr_rb(&hdr_rb, 0x1630, 0x1630, 0x0,
	                0x1, 0x0, 0x1, abstract, transfer);

	/* stream the bind request data */
	smb_io_rpc_hdr_rb("", &hdr_rb,  rhdr_rb, 0);
	prs_realloc_data(rhdr_rb, rhdr_rb->offset);

	if (auth_req != NULL && rhdr_auth != NULL && auth_ntlm != NULL)
	{
		make_rpc_hdr_auth(&hdr_auth, 0x0a, 0x06, 0x00, 1);
		smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, rhdr_auth, 0);
		prs_realloc_data(rhdr_auth, rhdr_auth->offset);

		make_rpc_auth_ntlmssp_verifier(&auth_verifier,
		                       "NTLMSSP", NTLMSSP_NEGOTIATE);

		smb_io_rpc_auth_ntlmssp_verifier("auth_verifier", &auth_verifier, auth_req, 0);
		prs_realloc_data(auth_req, auth_req->offset);

		make_rpc_auth_ntlmssp_neg(&ntlmssp_neg,
		                       neg_flags, my_name, domain);

		smb_io_rpc_auth_ntlmssp_neg("ntlmssp_neg", &ntlmssp_neg, auth_req, 0);
		prs_realloc_data(auth_req, auth_req->offset);
	}

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BIND, 0x0, rpc_call_id,
	             (auth_req  != NULL ? auth_req ->offset : 0) +
	             (auth_ntlm != NULL ? auth_ntlm->offset : 0) +
	             (rhdr_auth != NULL ? rhdr_auth->offset : 0) +
	             rhdr_rb->offset + 0x10,
	             (auth_req  != NULL ? auth_req ->offset : 0) +
	             (auth_ntlm != NULL ? auth_ntlm->offset : 0));

	smb_io_rpc_hdr("hdr"   , &hdr   , rhdr, 0);
	prs_realloc_data(rhdr, rhdr->offset);

	if (rhdr->data == NULL || rhdr_rb->data == NULL) return False;

	/***/
	/*** link rpc header, bind acknowledgment and authentication responses ***/
	/***/

	if (auth_req != NULL)
	{
		prs_link(NULL     , rhdr      , rhdr_rb  );
		prs_link(rhdr     , rhdr_rb   , rhdr_auth);
		prs_link(rhdr_rb  , rhdr_auth , auth_req );
		prs_link(rhdr_auth, auth_req  , auth_ntlm);
		prs_link(auth_req , auth_ntlm , NULL     );
	}
	else
	{
		prs_link(NULL, rhdr   , rhdr_rb);
		prs_link(rhdr, rhdr_rb, NULL   );
	}

	return True;
}

/*******************************************************************
 creates a DCE/RPC bind authentication response

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
BOOL create_rpc_bind_resp(struct pwd_info *pwd,
				char *domain, char *user_name, char *my_name,
				uint32 ntlmssp_cli_flgs,
				uint32 rpc_call_id,
				prs_struct *rhdr,
                                prs_struct *rhdr_autha,
                                prs_struct *auth_resp)
{
	RPC_HDR                   hdr;
	RPC_HDR_AUTHA             hdr_autha;
	RPC_AUTH_NTLMSSP_VERIFIER auth_verifier;

	make_rpc_hdr_autha(&hdr_autha, 0x1630, 0x1630, 0x0a, 0x06, 0x00);
	smb_io_rpc_hdr_autha("hdr_autha", &hdr_autha, rhdr_autha, 0);
	prs_realloc_data(rhdr_autha, rhdr_autha->offset);

	make_rpc_auth_ntlmssp_verifier(&auth_verifier,
			       "NTLMSSP", NTLMSSP_AUTH);

	smb_io_rpc_auth_ntlmssp_verifier("auth_verifier", &auth_verifier, auth_resp, 0);
	prs_realloc_data(auth_resp, auth_resp->offset);

	create_ntlmssp_resp(pwd, domain, user_name, my_name, ntlmssp_cli_flgs,
                                auth_resp);

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BINDRESP, 0x0, rpc_call_id,
	             auth_resp->offset + rhdr_autha->offset + 0x10,
	             auth_resp->offset);

	smb_io_rpc_hdr("hdr"   , &hdr   , rhdr, 0);
	prs_realloc_data(rhdr, rhdr->offset);

	if (rhdr->data == NULL || rhdr_autha->data == NULL) return False;

	/***/
	/*** link rpc header and authentication responses ***/
	/***/

	prs_link(NULL      , rhdr       , rhdr_autha);
	prs_link(rhdr      , rhdr_autha , auth_resp );
	prs_link(rhdr_autha, auth_resp  , NULL );

	return True;
}


/****************************************************************************
do an rpc bind
****************************************************************************/

static BOOL rpc_pipe_set_hnd_state(struct cli_state *cli, uint16 fnum,
				const char *pipe_name, uint16 device_state)
{
	BOOL state_set = False;
	char param[2];
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	char *rparam = NULL;
	char *rdata = NULL;
	uint32 rparam_len, rdata_len;

	if (pipe_name == NULL) return False;

	DEBUG(5,("Set Handle state Pipe[%x]: %s - device state:%x\n",
	          fnum, pipe_name, device_state));

	/* create parameters: device state */
	SSVAL(param, 0, device_state);

	/* create setup parameters. */
	setup[0] = 0x0001; 
	setup[1] = fnum; /* pipe file handle.  got this from an SMBOpenX. */

	/* send the data on \PIPE\ */
	if (cli_api_pipe(cli, "\\PIPE\\\0\0\0", 8,
	            setup, 2, 0,                /* setup, length, max */
	            param, 2, 0,                /* param, length, max */
	            NULL, 0, 1024,              /* data, length, max */
	            &rparam, &rparam_len,        /* return param, length */
	            &rdata, &rdata_len))         /* return data, length */
	{
		DEBUG(5, ("Set Handle state: return OK\n"));
		state_set = True;
	}

	if (rparam) free(rparam);
	if (rdata ) free(rdata );

	return state_set;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

static BOOL valid_pipe_name(const char *pipe_name,
				RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	int pipe_idx = 0;

	while (pipe_names[pipe_idx].client_pipe != NULL)
	{
		if (strequal(pipe_name, pipe_names[pipe_idx].client_pipe ))
		{
			DEBUG(5,("Bind Abstract Syntax:\n"));	
			dump_data(5, (char*)&(pipe_names[pipe_idx].abstr_syntax), 
			          sizeof(pipe_names[pipe_idx].abstr_syntax));
			DEBUG(5,("Bind Transfer Syntax:\n"));
			dump_data(5, (char*)&(pipe_names[pipe_idx].trans_syntax),
			          sizeof(pipe_names[pipe_idx].trans_syntax));

			/* copy the required syntaxes out so we can do the right bind */
			memcpy(transfer, &(pipe_names[pipe_idx].trans_syntax),
			       sizeof(pipe_names[pipe_idx].trans_syntax));
			memcpy(abstract, &(pipe_names[pipe_idx].abstr_syntax),
			       sizeof(pipe_names[pipe_idx].abstr_syntax));

			return True;
		}
		pipe_idx++;
	};

	DEBUG(5,("Bind RPC Pipe[%s] unsupported\n", pipe_name));
	return False;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

static BOOL check_bind_response(RPC_HDR_BA *hdr_ba, const char *pipe_name,
				RPC_IFACE *transfer)
{
	int i = 0;

	while ((pipe_names[i].client_pipe != NULL) && hdr_ba->addr.len > 0)
	{
		DEBUG(6,("bind_rpc_pipe: searching pipe name: client:%s server:%s\n",
		pipe_names[i].client_pipe , pipe_names[i].server_pipe ));

		if ((strequal(pipe_name, pipe_names[i].client_pipe )))
		{
			if (strequal(hdr_ba->addr.str, pipe_names[i].server_pipe ))
			{
				DEBUG(5,("bind_rpc_pipe: server pipe_name found: %s\n",
				         pipe_names[i].server_pipe ));
				break;
			}
			else
			{
				DEBUG(4,("bind_rpc_pipe: pipe_name %s != expected pipe %s.  oh well!\n",
				         pipe_names[i].server_pipe ,
				         hdr_ba->addr.str));
				break;
			}
		}
		else
		{
			i++;
		}
	}

	if (pipe_names[i].server_pipe == NULL)
	{
		DEBUG(2,("bind_rpc_pipe: pipe name %s unsupported\n", hdr_ba->addr.str));
		return False;
	}

	/* check the transfer syntax */
	if (!((hdr_ba->transfer.version == transfer->version) &&
	     (memcmp(hdr_ba->transfer.data, transfer->data,
	             sizeof(transfer->version)) ==0)))
	{
		DEBUG(0,("bind_rpc_pipe: transfer syntax differs\n"));
		return False;
	}

	/* lkclXXXX only accept one result: check the result(s) */
	if (hdr_ba->res.num_results != 0x1 || hdr_ba->res.result != 0)
	{
		DEBUG(2,("bind_rpc_pipe: bind denied results: %d reason: %x\n",
		          hdr_ba->res.num_results, hdr_ba->res.reason));
	}

	DEBUG(5,("bind_rpc_pipe: accepted!\n"));
	return True;
}

/****************************************************************************
do an rpc bind
****************************************************************************/

BOOL rpc_pipe_bind(struct cli_connection *con, 
				const char *pipe_name,
				RPC_IFACE *abstract, RPC_IFACE *transfer, 
				char *my_name)
{
	prs_struct hdr;
	prs_struct hdr_rb;
	prs_struct hdr_auth;
	prs_struct auth_req;
	prs_struct auth_ntlm;
	prs_struct data;
	prs_struct rdata;

	BOOL valid_ack = False;
	uint32 rpc_call_id;
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	struct ntuser_creds *usr = cli_conn_get_usercreds(con);
	BOOL ntlmsspauth = nt->ntlmssp_cli_flgs != 0;

	if (pipe_name == NULL || abstract == NULL || transfer == NULL)
	{
		return False;
	}

	DEBUG(5,("Bind RPC Pipe: %s\n", pipe_name));

	if (!valid_pipe_name(pipe_name, abstract, transfer)) return False;

	prs_init(&hdr      , 0x10                     , 4, False);
	prs_init(&hdr_rb   , 1024                     , 4, False);
	prs_init(&hdr_auth , (ntlmsspauth ?    8 : 0), 4, False);
	prs_init(&auth_req , (ntlmsspauth ? 1024 : 0), 4, False);
	prs_init(&auth_ntlm, (ntlmsspauth ? 1024 : 0), 4, False);

	prs_init(&rdata    , 0   , 4, True);

	rpc_call_id = get_rpc_call_id();
	create_rpc_bind_req(&hdr, &hdr_rb,
	                    ntlmsspauth ? &hdr_auth : NULL,
	                    ntlmsspauth ? &auth_req : NULL,
	                    ntlmsspauth ? &auth_ntlm : NULL,
	                    rpc_call_id,
	                    abstract, transfer,
	                    global_myname, usr->domain, usr->ntlmssp_flags);

	/* this is a hack due to limitations in rpc_api_pipe */
	prs_init(&data, prs_buf_len(&hdr), 4, False);
	prs_buf_copy(data.data, &hdr, 0, prs_buf_len(&hdr));

	nt->max_recv_frag = 0x1000;
	nt->max_xmit_frag = 0x1000;

	/* send data on \PIPE\.  receive a response */
	if (rpc_api_pipe_bind(con, &data, &rdata))
	{
		RPC_HDR_BA                hdr_ba;
		RPC_HDR_AUTH              rhdr_auth;
		RPC_AUTH_NTLMSSP_VERIFIER rhdr_verf;
		RPC_AUTH_NTLMSSP_CHAL     rhdr_chal;

		DEBUG(5, ("rpc_api_pipe: return OK\n"));

		smb_io_rpc_hdr_ba("", &hdr_ba, &rdata, 0);

		if (rdata.offset != 0)
		{
			valid_ack = check_bind_response(&hdr_ba, pipe_name, transfer);
		}

		if (valid_ack)
		{
			nt->max_xmit_frag = hdr_ba.bba.max_tsize;
			nt->max_recv_frag = hdr_ba.bba.max_rsize;
		}

		if (valid_ack && ntlmsspauth)
		{
			smb_io_rpc_hdr_auth("", &rhdr_auth, &rdata, 0);
			if (rdata.offset == 0) valid_ack = False;
		}

		if (valid_ack && ntlmsspauth)
		{
			smb_io_rpc_auth_ntlmssp_verifier("", &rhdr_verf, &rdata, 0);
			if (rdata.offset == 0) valid_ack = False;
		}
		if (valid_ack && ntlmsspauth)
		{
			smb_io_rpc_auth_ntlmssp_chal("", &rhdr_chal, &rdata, 0);
			if (rdata.offset == 0) valid_ack = False;
		}
		if (valid_ack && ntlmsspauth)
		{
			unsigned char p24[24];
			unsigned char lm_owf[24];
			unsigned char lm_hash[16];

			prs_struct hdra;
			prs_struct hdr_autha;
			prs_struct auth_resp;
			prs_struct dataa;

			nt->ntlmssp_cli_flgs = rhdr_chal.neg_flags;

			prs_init(&hdra     , 0x10, 4, False);
			prs_init(&hdr_autha, 1024, 4, False);
			prs_init(&auth_resp, 1024, 4, False);

			pwd_make_lm_nt_owf(&usr->pwd, rhdr_chal.challenge);

			create_rpc_bind_resp(&usr->pwd, usr->domain,
			                     usr->user_name, global_myname, 
			                     nt->ntlmssp_cli_flgs,
			                     rpc_call_id,
			                     &hdra, &hdr_autha, &auth_resp);
			                    
			pwd_get_lm_nt_owf(&usr->pwd, lm_owf, NULL, NULL, NULL);
			pwd_get_lm_nt_16(&usr->pwd, lm_hash, NULL);
			NTLMSSPOWFencrypt(lm_hash, lm_owf, p24);
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
					nt->ntlmssp_hash[ind] = (unsigned char)ind;
				}

				for( ind = 0; ind < 256; ind++)
				{
					unsigned char tc;

					j += (nt->ntlmssp_hash[ind] + k2[ind%8]);

					tc = nt->ntlmssp_hash[ind];
					nt->ntlmssp_hash[ind] = nt->ntlmssp_hash[j];
					nt->ntlmssp_hash[j] = tc;
				}

				nt->ntlmssp_hash[256] = 0;
				nt->ntlmssp_hash[257] = 0;
			}
/*			NTLMSSPhash(nt->ntlmssp_hash, p24); */
			bzero(lm_hash, sizeof(lm_hash));

			/* this is a hack! */
			prs_init(&dataa, prs_buf_len(&hdra), 4, False);
			prs_buf_copy(dataa.data, &hdra, 0, prs_buf_len(&hdra));

			if (!rpc_api_write(con, &dataa))
			{
				valid_ack = False;
			}

			if (valid_ack)
			{
				nt->ntlmssp_srv_flgs = rhdr_chal.neg_flags;
			}

			prs_free_data(&hdra);
			prs_free_data(&dataa);
			prs_free_data(&hdr_autha);
			prs_free_data(&auth_resp);
		}
	}

	prs_free_data(&data     );
	prs_free_data(&hdr      );
	prs_free_data(&hdr_rb   );
	prs_free_data(&hdr_auth );
	prs_free_data(&auth_req );
	prs_free_data(&auth_ntlm);
	prs_free_data(&rdata    );

	return valid_ack;
}

/****************************************************************************
 set ntlmssp negotiation flags
 ****************************************************************************/

void cli_nt_set_ntlmssp_flgs(struct cli_state *cli, uint32 ntlmssp_flgs)
{
	cli->nt.ntlmssp_cli_flgs = ntlmssp_flgs;
}


/****************************************************************************
 open a session
 ****************************************************************************/

BOOL cli_nt_session_open(struct cli_state *cli, const char *pipe_name,
		uint16* fnum)
{
	/******************* open the pipe *****************/
	if (IS_BITS_SET_ALL(cli->capabilities, CAP_NT_SMBS))
	{
		int f;
		f = cli_nt_create(cli, &(pipe_name[5]));
		if (f == -1)
		{
			fstring errstr;
			cli_safe_errstr(cli, errstr, sizeof(errstr)-1);
			DEBUG(0,("cli_nt_session_open: cli_nt_create failed on pipe %s to machine %s.  Error was %s\n",
				 &(pipe_name[5]), cli->desthost, errstr));
			return False;
		}
		*fnum = (uint16)f;
	}
	else
	{
		int f;
		f = cli_open(cli, pipe_name, O_CREAT|O_RDWR, DENY_NONE);
		if (f == -1)
		{
			fstring errstr;
			cli_safe_errstr(cli, errstr, sizeof(errstr)-1);
			DEBUG(0,("cli_nt_session_open: cli_open failed on pipe %s to machine %s.  Error was %s\n",
				 pipe_name, cli->desthost, errstr));
			return False;
		}
		*fnum = (uint16)f;

		/**************** Set Named Pipe State ***************/
		if (!rpc_pipe_set_hnd_state(cli, *fnum, pipe_name, 0x4300))
		{
			fstring errstr;
			cli_safe_errstr(cli, errstr, sizeof(errstr)-1);
			DEBUG(0,("cli_nt_session_open: pipe hnd state failed.  Error was %s\n",
				  errstr));
			cli_close(cli, *fnum);
			return False;
		}

	}

	return True;
}

/****************************************************************************
close the session
****************************************************************************/

void cli_nt_session_close(struct cli_state *cli, uint16 fnum)
{
	if (fnum != 0xffff)
	{
		cli_close(cli, fnum);
	}
}
