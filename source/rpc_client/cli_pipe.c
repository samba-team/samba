/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Elrond                            2000,
 *  Copyright (C) Tim Potter                        2000
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
#include "rpc_parse.h"
#include "rpc_client.h"

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

	DEBUG(5,
	      ("rpc_read: data_to_read: %d data offset: %d file offset: %d\n",
	       data_to_read, rdata_offset, file_offset));

	if (new_data_size > rdata->data_size)
	{
		prs_grow_data(rdata, True, new_data_size, True);
		DEBUG(5, ("rpc_read: grow buffer to %d\n", rdata->data_size));
	}

	data = rdata->data + rdata_offset;

	do			/* read data using SMBreadX */
	{
		if (size > data_to_read)
		{
			size = data_to_read;
		}

		num_read = cli_read_one(cli, fnum, data, file_offset, size);

		DEBUG(5, ("rpc_read: read offset: %d read: %d to read: %d\n",
			  file_offset, num_read, data_to_read));

		data_to_read -= num_read;
		file_offset += num_read;
		data += num_read;

		if (cli_error(cli, &cls, &type))
		{
			if (cls != ERRDOS || type != ERRmoredata)
			{
				return False;
			}
		}

	}
	while (!one_only && num_read > 0 && data_to_read > 0);

	rdata->end = new_data_size;

	DEBUG(5, ("rpc_read: offset end: 0x%x.  data left to read:0x%x\n",
		  rdata->end, data_to_read));

	return True;
}

/****************************************************************************
 checks the header
 ****************************************************************************/
static BOOL rpc_check_hdr(prs_struct *rdata, RPC_HDR * rhdr,
			  BOOL *first, BOOL *last, int *len)
{
	DEBUG(5, ("rpc_check_hdr: rdata->data_size: %d\n", rdata->data_size));

	smb_io_rpc_hdr("rpc_hdr   ", rhdr, rdata, 0);

	if (!rdata->offset || rdata->offset != 0x10)
	{
		DEBUG(0, ("rpc_check_hdr: error in rpc header\n"));
		return False;
	}

	DEBUG(5,
	      ("rpc_check_hdr: (after smb_io_rpc_hdr call) rdata->data_size: %d\n",
	       rdata->data_size));

	(*first) = IS_BITS_SET_ALL(rhdr->flags, RPC_FLG_FIRST);
	(*last) = IS_BITS_SET_ALL(rhdr->flags, RPC_FLG_LAST);
	(*len) = rhdr->frag_len - rdata->data_size;

	return rhdr->pkt_type != RPC_FAULT;
}

/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
BOOL create_rpc_request(prs_struct *rhdr, uint16 vuid,
			uint8 op_num, uint8 flags, int data_len, int auth_len)
{
	uint32 alloc_hint;
	RPC_HDR_REQ hdr_req;
	RPC_HDR hdr;

	DEBUG(5, ("create_rpc_request: opnum: 0x%x data_len: 0x%x\n",
		  op_num, data_len));

	/* create the rpc header RPC_HDR */
	make_rpc_hdr(&hdr, RPC_REQUEST, flags,
		     get_rpc_call_id(), data_len, auth_len);

	if (auth_len != 0)
	{
		alloc_hint = data_len - 0x18 - auth_len - 16;
	}
	else
	{
		alloc_hint = data_len - 0x18;
	}

	DEBUG(10,
	      ("create_rpc_request: data_len: 0x%x auth_len: 0x%x alloc_hint: 0x%x\n",
	       data_len, auth_len, alloc_hint));

	/* create the rpc request RPC_HDR_REQ */
	make_rpc_hdr_req(&hdr_req, alloc_hint, vuid, op_num);

	/* stream-time... */
	smb_io_rpc_hdr("hdr    ", &hdr, rhdr, 0);
	smb_io_rpc_hdr_req("hdr_req", &hdr_req, rhdr, 0);

	if (rhdr->data == NULL || rhdr->offset != 0x18)
		return False;

	rhdr->start = 0;
	rhdr->end = rhdr->offset;

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
static BOOL rpc_api_pipe_bind(struct cli_connection *con, prs_struct *data,
			      prs_struct *rdata)
{
	int len;

	BOOL first = True;
	BOOL last = True;
	RPC_HDR rhdr;
	prs_struct rpdu;

	prs_init(&rpdu, 0, 4, True);

	if (!rpc_api_send_rcv_pdu(con, data, &rpdu)) {
		prs_free_data(&rpdu);
		return False;
	}

	/**** parse the header: check it's a response record */

	rpdu.start = 0;
	rpdu.end = rpdu.data_size;
	rpdu.offset = 0;

	if (!rpc_check_hdr(&rpdu, &rhdr, &first, &last, &len))
	{
		return False;
	}

	prs_set_packtype(rdata, rhdr.pack_type);

	if (rhdr.pkt_type != RPC_BINDACK)
	{
		return False;
	}
	if (!last && !first)
	{
		DEBUG(5,
		      ("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
		first = True;
		last = True;
	}

	prs_append_data(rdata, prs_data(&rpdu, rpdu.offset),
			rhdr.frag_len - rpdu.offset);
	prs_free_data(&rpdu);

	/* only one rpc fragment, and it has been read */
	if (!first || !last)
	{
		return False;
	}

	DEBUG(6, ("cli_pipe: fragment first and last both set\n"));

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
		      prs_struct *data, prs_struct *rdata)
{
	int len;

	BOOL first = True;
	BOOL last = True;
	RPC_HDR rhdr;
	prs_struct rpdu;
	cli_auth_fns *auth = cli_conn_get_authfns(con);
	uint8 flags;

	int data_start = 0;
	int data_end = 0;

	prs_init(&rpdu, 0, 4, True);

	do
	{
		prs_struct data_t;

		DEBUG(10, ("rpc_api_pipe_req: start: 0x%x off: 0x%x\n",
			   data_start, data->offset));

		SMB_ASSERT(auth->cli_create_pdu != NULL);

		if (!auth->cli_create_pdu(con, opnum, data, data_start,
					  &data_end, &data_t, &flags))
		{
			DEBUG(2,("rpc_api_pipe_req: cli_create_pdu failed "
				 "%d %d %d %d\n",
				 opnum, data_start, data_end, flags));
			return False;
		}

		DEBUG(10, ("rpc_api_pipe_req: end: 0x%x\n", data_end));
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

	}
	while (data_end < data->offset);

	if (data_end != data->offset)
	{
		DEBUG(2,
		      ("rpc_api_pipe_req: data_end: 0x%x and offset 0x%x wrong\n",
		       data_end, data->offset));
		prs_free_data(&rpdu);
		return False;
	}

	/**** parse the header: check it's a response record */

	rpdu.start = 0;
	rpdu.end = rpdu.data_size;
	rpdu.offset = 0;

	if (!rpc_check_hdr(&rpdu, &rhdr, &first, &last, &len))
	{
		DEBUG(2,("rpc_check_hdr: failed. %d %d %d\n",
					first, last, len));
		return False;
	}

	prs_set_packtype(rdata, rhdr.pack_type);

	if (rhdr.pkt_type == RPC_BINDACK)
	{
		if (!last && !first)
		{
			DEBUG(5,
			      ("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
			first = True;
			last = True;
		}
	}

	if (rhdr.pkt_type == RPC_RESPONSE)
	{
		RPC_HDR_RESP rhdr_resp;
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, &rpdu, 0);
	}

	if (rhdr.auth_len != 0 &&
	    (auth->cli_decode_pdu == NULL ||
	     !auth->cli_decode_pdu(con, &rpdu, rhdr.frag_len, rhdr.auth_len)))
	{
		DEBUG(10, ("auth->cli_decode_pdu: failed\n"));
		return False;
	}

	prs_append_data(rdata, prs_data(&rpdu, rpdu.offset),
			rhdr.frag_len - rpdu.offset);
	prs_free_data(&rpdu);

	/* only one rpc fragment, and it has been read */
	if (first && last)
	{
		DEBUG(6, ("cli_pipe: fragment first and last both set\n"));
		DEBUG(10, ("cli_pipe: dce/rpc `body' data:\n"));
		dump_data(10, prs_data(rdata, 0), rdata->data_size);
		return True;
	}

	DEBUG(100, ("first frag: %s", BOOLSTR(first)));
	DEBUG(100, ("last frag: %s\n", BOOLSTR(last)));
	while (!last)		/* read more fragments until we get the last one */
	{
		RPC_HDR_RESP rhdr_resp;
		int num_read;
		DEBUG(10, ("rpc_api_pipe: another fragment expected\n"));
		prs_init(&rpdu, 0, 4, True);
		rpc_api_rcv_pdu(con, &rpdu);
		rpdu.start = 0;
		rpdu.end = rpdu.data_size;
		rpdu.offset = 0;
		num_read = rpdu.data_size;
		DEBUG(5, ("cli_pipe: read header (size:%d)\n", num_read));
		if (!rpc_check_hdr(&rpdu, &rhdr, &first, &last, &len))
		{
			prs_free_data(&rpdu);
			return False;
		}

		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, &rpdu, 0);
		if (first)
		{
			DEBUG(0, ("cli_pipe: wierd rpc header received\n"));
			prs_free_data(&rpdu);
			return False;
		}

		if (rhdr.auth_len != 0 &&
		    (auth->cli_decode_pdu == NULL ||
		     !auth->cli_decode_pdu(con, &rpdu, rhdr.frag_len,
					   rhdr.auth_len)))
		{
			DEBUG(10, ("auth->cli_decode_pdu: failed\n"));
			prs_free_data(&rpdu);
			return False;
		}

		{
			prs_append_data(rdata,
					prs_data(&rpdu, rpdu.offset),
					rhdr.frag_len - rpdu.offset);
			prs_free_data(&rpdu);
		}
	}

	DEBUG(10, ("cli_pipe: dce/rpc `body' data:\n"));
	dump_data(10, prs_data(rdata, 0), rdata->data_size);
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

static BOOL cli_send_trans_data(struct cli_state *cli,
				uint16 fnum, prs_struct *data,
				int max_data_len, prs_struct *rdata)
{
	uint16 cmd = 0x0026;
	uint16 setup[2];	/* only need 2 uint16 setup parameters */
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
	int data_len = data ? (data->data_size) : 0;
	data_len = MIN(max_data_len, data_len);
	/* create setup parameters. */
	setup[0] = cmd;
	setup[1] = fnum;	/* pipe file handle.  got this from an SMBOpenX. */
	DEBUG(5,
	      ("cli_send_trans_data: data_len: %d cmd:%x fnum:%x\n",
	       data_len, cmd, fnum));
	/* send the data: receive a response. */
	if (!cli_api_pipe(cli, pipe_name, pipe_len, setup, setup_len, 0,	/* Setup, length, max */
			  NULL, 0, 0,	/* Params, length, max */
			  pdata, data_len, max_data_len,	/* data, length, max */
			  &rparam, &rparam_len,	/* return param, length */
			  &rdata_t, &rdata_len))	/* return data, len */
	{
		fstring errstr;
		cli_safe_errstr(cli, errstr, sizeof(errstr) - 1);
		DEBUG(0,
		      ("cli_pipe: return critical error. Error was %s\n",
		       errstr)); return False;
	}

	safe_free(rparam);
	if (rdata_len != 0)
	{
		BOOL ret = prs_append_data(rdata, rdata_t, rdata_len);
		safe_free(rdata_t);
		return ret;
	}

	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...
 ****************************************************************************/
BOOL cli_send_and_rcv_pdu_trans(struct cli_connection *con,
				struct cli_state *cli,
				uint16 fnum, prs_struct *data,
				prs_struct *rdata, int max_send_pdu)
{
	int len;
	cli_auth_fns *auth = cli_conn_get_authfns(con);
	BOOL first = True;
	BOOL last = True;
	RPC_HDR rhdr;
	size_t data_len = data->data_size;
	int max_data_len = MAX(data_len, 2048);
	DEBUG(5, ("cli_send_and_rcv_pdu_trans: fnum:%x\n", fnum));
	DEBUG(10, ("cli_send_and_rcv_pdu_trans: len: %d\n", data_len));
	if (!cli_send_trans_data(cli, fnum, data, max_data_len, rdata))
	{
		return False;
	}

	if (rdata->data == NULL)
		return False;
	/**** parse the header: check it's a response record */
	rdata->start = 0;
	rdata->end = rdata->data_size;
	rdata->offset = 0;
	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len))
	{
		return False;
	}

	prs_set_packtype(rdata, rhdr.pack_type);
	if (rhdr.pkt_type == RPC_BINDACK)
	{
		if (!last && !first)
		{
			DEBUG(5,
			      ("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
			first = True;
			last = True;
		}
	}


	DEBUG(5, ("cli_pipe: len left: %d smbtrans read: %d\n",
		  len, rdata->data_size));
	/* check if data to be sent back was too large for one SMB. */
	/* err status is only informational: the _real_ check is on the length */
	if (len > 0)		/* || err == (0x80000000 | STATUS_BUFFER_OVERFLOW)) */
	{
		if (!rpc_read(cli, fnum, rdata, len, rdata->data_size, False))
		{
			return False;
		}

		if (rhdr.auth_len != 0 &&
		    (auth->cli_decode_pdu == NULL ||
		     !auth->cli_decode_pdu(con, rdata,
					   rhdr.frag_len, rhdr.auth_len)))
		{
			return False;
		}

	}

	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...
 ****************************************************************************/

BOOL cli_send_and_rcv_pdu_rw(struct cli_connection *con,
			     struct cli_state *cli,
			     uint16 fnum, prs_struct *data,
			     prs_struct *rdata, int max_send_pdu)
{
	int len;
	int data_offset = 0;
	cli_auth_fns *auth = cli_conn_get_authfns(con);
	BOOL first = True;
	BOOL last = True;
	RPC_HDR rhdr;
	int max_data_len = 2048;
	int write_mode = 0x000c;
	char *d = NULL;
	size_t data_left = data->data_size;
	size_t data_len = data->data_size;
	DEBUG(5, ("cli_send_and_rcv_pdu_rw: fnum:%x\n", fnum));
	while (data_offset < data_len)
	{
		DEBUG(10,
		      ("cli_send_and_rcv_pdu_rw: off: %d len: %d left: %d\n",
		       data_offset, data_len, data_left));
		if (d == NULL)
		{
			d = (char *)malloc(data_left + 2);
			if (d == NULL)
			{
				return False;
			}
			SSVAL(d, 0, data_len);
			memcpy(d + 2, data->data, data_len);
			data_len += 2;
		}
		max_data_len = MIN(max_data_len, data_len - data_offset);
		if (cli_write
		    (cli, fnum, write_mode, d, data_offset,
		     max_data_len, data_left) != max_data_len)
		{
			return False;
		}
		write_mode = 0x0004;
		d += max_data_len;
		data_offset += max_data_len;
		data_left -= max_data_len;
	}
	if (!rpc_read(cli, fnum, rdata, max_send_pdu, 0, True))
	{
		return False;
	}

	if (rdata->data == NULL)
		return False;
	/**** parse the header: check it's a response record */
	rdata->start = 0;
	rdata->end = rdata->data_size;
	rdata->offset = 0;
	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len))
	{
		return False;
	}

	prs_set_packtype(rdata, rhdr.pack_type);
	if (rhdr.pkt_type == RPC_BINDACK)
	{
		if (!last && !first)
		{
			DEBUG(5,
			      ("cli_pipe: bug in AS/U, setting fragment first/last ON\n"));
			first = True;
			last = True;
		}
	}

	if (rhdr.pkt_type == RPC_RESPONSE)
	{
		RPC_HDR_RESP rhdr_resp;
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0);
	}

	DEBUG(5, ("cli_pipe: len left: %d smbtrans read: %d\n",
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

	if (rhdr.auth_len != 0 &&
	    (auth->cli_decode_pdu == NULL ||
	     !auth->cli_decode_pdu(con, rdata, rhdr.frag_len, rhdr.auth_len)))
	{
		return False;
	}

	return True;
}

/****************************************************************************
 send data on an rpc pipe, which *must* be in one fragment.
 receive response data from an rpc pipe, which may be large...
 ****************************************************************************/
BOOL cli_send_and_rcv_pdu(struct cli_connection *con,
			  struct cli_state *cli, uint16 fnum,
			  prs_struct *data, prs_struct *rdata,
			  int max_send_pdu)
{
	if (True)
	{
		return cli_send_and_rcv_pdu_trans(con, cli, fnum,
						  data, rdata, max_send_pdu);}
	else
	{
		return cli_send_and_rcv_pdu_rw(con, cli, fnum, data,
					       rdata, max_send_pdu);}
}

BOOL cli_rcv_pdu(struct cli_connection *con,
		 struct cli_state *cli, uint16 fnum, prs_struct *rdata)
{
	RPC_HDR_RESP rhdr_resp;
	RPC_HDR rhdr;
	char readbuf[0x19];
	int num_read;
	BOOL first = True;
	BOOL last = True;
	int len;
	cli_auth_fns *auth = cli_conn_get_authfns(con);
	/* with a little help by Scummer */
	num_read = cli_read_one(cli, fnum, readbuf, 0, 0x18);
	DEBUG(5, ("cli_pipe: read header (size:%d)\n", num_read));
	prs_append_data(rdata, readbuf, num_read);
	if (num_read != 0x18)
		return False;
	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len))
	{
		return False;
	}

	prs_set_packtype(rdata, rhdr.pack_type);
	smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0);
	if (!rpc_read(cli, fnum, rdata, len, rdata->data_size, False))
	{
		return False;
	}

	if (rhdr.auth_len != 0 &&
	    (auth->cli_decode_pdu == NULL ||
	     !auth->cli_decode_pdu(con, rdata, rhdr.frag_len, rhdr.auth_len)))
	{
		return False;
	}

	return True;
}


/****************************************************************************
do an rpc bind
****************************************************************************/

static BOOL rpc_pipe_set_hnd_state(struct cli_state *cli,
				   uint16 fnum,
				   const char *pipe_name, uint16 device_state)
{
	BOOL state_set = False;
	char param[2];
	uint16 setup[2];	/* only need 2 uint16 setup parameters */
	char *rparam = NULL;
	char *rdata = NULL;
	uint32 rparam_len, rdata_len;
	if (pipe_name == NULL)
		return False;
	DEBUG(5, ("Set Handle state Pipe[%x]: %s - device state:%x\n",
		  fnum, pipe_name, device_state));
	/* create parameters: device state */
	SSVAL(param, 0, device_state);
	/* create setup parameters. */
	setup[0] = 0x0001;
	setup[1] = fnum;	/* pipe file handle.  got this from an SMBOpenX. */
	/* send the data on \PIPE\ */
	if (cli_api_pipe(cli, "\\PIPE\\\0\0\0", 8, setup, 2, 0,	/* setup, length, max */
			 param, 2, 0,	/* param, length, max */
			 NULL, 0, 1024,	/* data, length, max */
			 &rparam, &rparam_len,	/* return param, length */
			 &rdata, &rdata_len))	/* return data, length */
	{
		DEBUG(5, ("Set Handle state: return OK\n"));
		state_set = True;
	}

	safe_free(rparam);
	safe_free(rdata);
	return state_set;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

static BOOL valid_pipe_name(const char *pipe_name,
			    RPC_IFACE * abstract, RPC_IFACE * transfer)
{
	int pipe_idx = 0;
	while (pipe_names[pipe_idx].client_pipe != NULL)
	{
		if (strequal(pipe_name, pipe_names[pipe_idx].client_pipe))
		{
			DEBUG(5, ("Bind Abstract Syntax:\n"));
			dump_data(5,
				  (char *)
				  &(pipe_names[pipe_idx].abstr_syntax),
				  sizeof(pipe_names[pipe_idx].abstr_syntax));
			DEBUG(5, ("Bind Transfer Syntax:\n"));
			dump_data(5,
				  (char *)
				  &(pipe_names[pipe_idx].trans_syntax),
				  sizeof(pipe_names[pipe_idx].trans_syntax));
			/* copy the required syntaxes out so we can do the right bind */
			memcpy(transfer,
			       &(pipe_names[pipe_idx].trans_syntax),
			       sizeof(pipe_names[pipe_idx].trans_syntax));
			memcpy(abstract,
			       &(pipe_names[pipe_idx].abstr_syntax),
			       sizeof(pipe_names[pipe_idx].abstr_syntax));
			return True;
		}
		pipe_idx++;
	};
	DEBUG(5, ("Bind RPC Pipe[%s] unsupported\n", pipe_name));
	return False;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

static BOOL check_bind_response(RPC_HDR_BA * hdr_ba,
				const char *pipe_name, RPC_IFACE * transfer)
{
	int i = 0;
	while ((pipe_names[i].client_pipe != NULL) && hdr_ba->addr.len > 0)
	{
		DEBUG(6,
		      ("bind_rpc_pipe: searching pipe name: client:%s server:%s\n",
		       pipe_names[i].client_pipe, pipe_names[i].server_pipe));
		if ((strequal(pipe_name, pipe_names[i].client_pipe)))
		{
			if (strequal
			    (hdr_ba->addr.str, pipe_names[i].server_pipe))
			{
				DEBUG(5,
				      ("bind_rpc_pipe: server pipe_name found: %s\n",
				       pipe_names[i].server_pipe));
				break;
			}
			else
			{
				DEBUG(4,
				      ("bind_rpc_pipe: pipe_name %s != expected pipe %s.  oh well!\n",
				       pipe_names[i].server_pipe,
				       hdr_ba->addr.str)); break;
			}
		}
		else
		{
			i++;
		}
	}

	if (pipe_names[i].server_pipe == NULL)
	{
		DEBUG(2,
		      ("bind_rpc_pipe: pipe name %s unsupported\n",
		       hdr_ba->addr.str)); return False;
	}

	/* check the transfer syntax */
	if (!((hdr_ba->transfer.version == transfer->version) &&
	      (memcmp(&hdr_ba->transfer.uuid, &transfer->uuid,
		      sizeof(transfer->uuid)) == 0)))
	{
		DEBUG(0, ("bind_rpc_pipe: transfer syntax differs\n"));
		return False;
	}

	/* lkclXXXX only accept one result: check the result(s) */
	if (hdr_ba->res.num_results != 0x1 || hdr_ba->res.result != 0)
	{
		DEBUG(2,
		      ("bind_rpc_pipe: bind denied results: %d reason: %x\n",
		       hdr_ba->res.num_results, hdr_ba->res.reason));
	}

	DEBUG(5, ("bind_rpc_pipe: accepted!\n"));
	return True;
}

/****************************************************************************
do an rpc bind
****************************************************************************/

BOOL rpc_pipe_bind(struct cli_connection *con,
		   const char *pipe_name,
		   RPC_IFACE * abstract, RPC_IFACE * transfer)
{
	prs_struct data;
	prs_struct rdata;
	BOOL valid_ack = False;
	uint32 rpc_call_id;
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	cli_auth_fns *auth = cli_conn_get_authfns(con);
	if (con == NULL || auth == NULL)
	{
		DEBUG(0, ("rpc_pipe_bind: invalid connection\n"));
		return False;
	}

	if (pipe_name == NULL || abstract == NULL || transfer == NULL)
	{
		return False;
	}

	DEBUG(5, ("Bind RPC Pipe: %s\n", pipe_name));
	if (!valid_pipe_name(pipe_name, abstract, transfer))
		return False;
	prs_init(&rdata, 0, 4, True);
	rpc_call_id = get_rpc_call_id();
	SMB_ASSERT(auth->create_bind_req != NULL);
	if (!auth->create_bind_req(con, &data, rpc_call_id, abstract,
				   transfer))
	{
		return False;
	}

	nt->max_recv_frag = 0x1000;
	nt->max_xmit_frag = 0x1000;
	/* send data on \PIPE\.  receive a response */
	if (rpc_api_pipe_bind(con, &data, &rdata))
	{
		RPC_HDR_BA hdr_ba;
		DEBUG(5, ("rpc_api_pipe: return OK\n"));
		smb_io_rpc_hdr_ba("", &hdr_ba, &rdata, 0);
		if (rdata.offset != 0)
		{
			valid_ack =
				check_bind_response(&hdr_ba, pipe_name,
						    transfer);}

		if (valid_ack)
		{
			nt->max_xmit_frag = hdr_ba.bba.max_tsize;
			nt->max_recv_frag = hdr_ba.bba.max_rsize;
		}

		if (valid_ack && auth->decode_bind_resp != NULL)
		{
			valid_ack = auth->decode_bind_resp(con, &rdata);
		}

		if (valid_ack && auth->create_bind_cont != NULL)
		{
			prs_struct dataa;
			prs_init(&dataa, 0, 4, False);
			valid_ack =
				auth->create_bind_cont(con, &dataa,
						       rpc_call_id);
			if (valid_ack)
			{
				valid_ack = rpc_api_write(con, &dataa);
			}
			prs_free_data(&dataa);
		}
	}

	prs_free_data(&data);
	prs_free_data(&rdata);
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

BOOL cli_nt_session_open(struct cli_state *cli,
			 const char *pipe_name, uint16 *fnum)
{
	/******************* open the pipe *****************/
	if (IS_BITS_SET_ALL(cli->capabilities, CAP_NT_SMBS))
	{
		int f;
		f = cli_nt_create(cli, &(pipe_name[5]));
		if (f == -1)
		{
			fstring errstr;
			cli_safe_errstr(cli, errstr, sizeof(errstr) - 1);
			DEBUG(0,
			      ("cli_nt_session_open: cli_nt_create failed on pipe %s to machine %s.  Error was %s\n",
			       &(pipe_name[5]), cli->desthost, errstr));
			return False;
		}
		*fnum = (uint16)f;
	}
	else
	{
		int f;
		f = cli_open(cli, pipe_name, O_CREAT | O_RDWR, DENY_NONE);
		if (f == -1)
		{
			fstring errstr;
			cli_safe_errstr(cli, errstr, sizeof(errstr) - 1);
			DEBUG(0,
			      ("cli_nt_session_open: cli_open failed on pipe %s to machine %s.  Error was %s\n",
			       pipe_name, cli->desthost, errstr));
			return False;
		}
		*fnum = (uint16)f;
		/**************** Set Named Pipe State ***************/
		if (!rpc_pipe_set_hnd_state(cli, *fnum, pipe_name, 0x4300))
		{
			fstring errstr;
			cli_safe_errstr(cli, errstr, sizeof(errstr) - 1);
			DEBUG(0,
			      ("cli_nt_session_open: pipe hnd state failed.  Error was %s\n",
			       errstr)); cli_close(cli, *fnum);
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
