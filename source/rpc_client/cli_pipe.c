
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                       1998.
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

/********************************************************************
 rpc pipe call id 
 ********************************************************************/
uint32 get_rpc_call_id(void)
{
	static uint32 call_id = 1;
	return ++call_id;
}

/*******************************************************************
 uses SMBreadX to get rest of rpc data
 ********************************************************************/
static BOOL rpc_read(struct cli_state *cli, int t_idx, uint16 fnum,
				prs_struct *rdata, uint32 data_to_read, uint32 rdata_offset)
{
	int size = 0x1630;
	int file_offset = rdata_offset;
	int num_read;
	char *data = rdata->data->data;
	uint32 err;
	uint32 new_data_size = rdata->data->data_used + data_to_read;
	data += rdata_offset;

	file_offset -= rdata_offset;

	DEBUG(5,("rpc_read: data_to_read: %d data offset: %d file offset: %d\n",
	          data_to_read, rdata_offset, file_offset));

	if (new_data_size > rdata->data->data_size)
	{
		mem_grow_data(&rdata->data, True, new_data_size, True);
		DEBUG(5,("rpc_read: grow buffer to %d\n", rdata->data->data_used));
	}

	do /* read data using SMBreadX */
	{
		if (size > data_to_read) size = data_to_read;

		new_data_size = rdata->data->data_used + size;

		if (new_data_size > rdata->data->data_size)
		{
			mem_grow_data(&rdata->data, True, new_data_size, True);
			DEBUG(5,("rpc_read: grow buffer to %d\n", rdata->data->data_used));
		}

		num_read = cli_readx(cli, t_idx, fnum, data, file_offset + 0x100000, size);

		DEBUG(5,("rpc_read: read offset: %d read: %d to read: %d\n",
				  file_offset, num_read, data_to_read));

		data_to_read -= num_read;
		file_offset  += num_read;
		data         += num_read;

		if (cli_error(cli, NULL, &err)) return False;

	} while (num_read > 0 && data_to_read > 0); /* && err == (0x80000000 | STATUS_BUFFER_OVERFLOW)); */

	mem_realloc_data(rdata->data, file_offset + rdata_offset);
	rdata->data->offset.end = file_offset + rdata_offset;

	DEBUG(5,("rpc_read: data supposedly left to read:0x%x\n", data_to_read));

	return data_to_read == 0;
}

/****************************************************************************
 checks the header
 ****************************************************************************/
static BOOL rpc_check_hdr(prs_struct *rdata, uint8 *pkt_type,
				BOOL *first, BOOL *last, int *len)
{
	RPC_HDR    rhdr;

	DEBUG(5,("rpc_check_hdr: rdata->data->data_used: %d\n", rdata->data->data_used));

	smb_io_rpc_hdr   ("rpc_hdr   ", &rhdr   , rdata, 0);

	if (!rdata->offset || rdata->offset != 0x10)
	{
		DEBUG(5,("cli_pipe: error in rpc header\n"));
		return False;
	}

	DEBUG(5,("rpc_check_hdr: (after smb_io_rpc_hdr call) rdata->data->data_used: %d\n", rdata->data->data_used));

	(*first   ) = IS_BITS_SET_ALL(rhdr.flags, RPC_FLG_FIRST);
	(*last    ) = IS_BITS_SET_ALL(rhdr.flags, RPC_FLG_LAST );
	(*len     ) = rhdr.frag_len - rdata->data->data_used;
	(*pkt_type) = rhdr.pkt_type;

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
BOOL rpc_api_pipe(struct cli_state *cli, int t_idx,
				uint16 cmd, uint16 fnum,
				prs_struct *param , prs_struct *data,
				prs_struct *rparam, prs_struct *rdata)
{
	int len;

	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	uint32 err;
	uint8 pkt_type = 0xff;
	BOOL first = True;
	BOOL last  = True;

	/* prepare return data and params */

	/* create setup parameters. */
	setup[0] = cmd; 
	setup[1] = fnum; /* pipe file handle.  got this from an SMBcreateX. */

	/* send the data: receive a response. */
	if (!cli_api_pipe(cli, t_idx, "\\PIPE\\\0\0\0", 8,

	            param != NULL ? param->data->data_used : 0,
	            data  != NULL ? data ->data->data_used : 0,
	            2,

	            0,
	            data  != NULL ? 1024 : 0 ,

	            param != NULL ? param->data->data : NULL,
	            data  != NULL ? data ->data->data : NULL,
	            setup,

	            rparam != NULL ? rparam->data : NULL,
	            rdata  != NULL ? rdata ->data : NULL))
	{
		DEBUG(5, ("cli_pipe: return critical error\n"));
		return False;
	}

	if (cli_error(cli, NULL, &err)) return False;

	if (rdata->data->data == NULL) return False;

	/**** parse the header: check it's a response record */

	rdata->data->offset.start = 0;
	rdata->data->offset.end   = rdata->data->data_used;
	rdata->offset = 0;

	if (!rpc_check_hdr(rdata, &pkt_type, &first, &last, &len)) return False;
	
	if (pkt_type == RPC_RESPONSE)
	{
		RPC_HDR_RESP rhdr_resp;
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0);
	}

	DEBUG(5,("rpc_api_pipe: len left: %d smbtrans read: %d\n",
			len, rdata->data->data_used));

	/* check if data to be sent back was too large for one SMB. */
	/* err status is only informational: the _real_ check is on the length */
	if (len > 0) /* || err == (0x80000000 | STATUS_BUFFER_OVERFLOW)) */
	{
		if (!rpc_read(cli, t_idx, fnum, rdata, len, rdata->data->data_used)) return False;
	}

	/* only one rpc fragment, and it has been read */
	if (first && last)
	{
		DEBUG(6,("rpc_api_pipe: fragment first and last both set\n"));
		return True;
	}

	while (!last) /* read more fragments until we get the last one */
	{
		RPC_HDR      rhdr;
		RPC_HDR_RESP rhdr_resp;
		int num_read;
		prs_struct hps;

		prs_init(&hps, 0x18, 4, 0, True);
		
		num_read = cli_readx(cli, t_idx, fnum, hps.data->data, 0, 0x18);
		DEBUG(5,("rpc_api_pipe: read header (size:%d)\n", num_read));

		if (num_read != 0x18) return False;

		smb_io_rpc_hdr     ("rpc_hdr     ", &rhdr     , &hps, 0);
		smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, &hps, 0);

		prs_mem_free(&hps);

		if (cli_error(cli, NULL, &err)) return False;

		first = IS_BITS_SET_ALL(rhdr.flags, RPC_FLG_FIRST);
		last  = IS_BITS_SET_ALL(rhdr.flags, RPC_FLG_LAST );

		if (first)
		{
			DEBUG(4,("rpc_api_pipe: wierd rpc header received\n"));
			return False;
		}

		len = rhdr.frag_len - hps.offset;
		if (!rpc_read(cli, t_idx, fnum, rdata, len, rdata->data->data_used)) return False;
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
				prs_struct *auth_req,
				RPC_IFACE *abstract, RPC_IFACE *transfer,
				char *my_name, char *domain)
{
	RPC_HDR_RB        hdr_rb;
	RPC_HDR           hdr;
	RPC_AUTH_NTLMSSP_REQ ntlmssp_req;

	/* create the bind request RPC_HDR_RB */
	make_rpc_hdr_rb(&hdr_rb, 
	                0x1630, 0x1630, 0x0,
	                0x1, 0x0, 0x1,
					abstract, transfer);

	/* stream the bind request data */
	smb_io_rpc_hdr_rb("", &hdr_rb,  rhdr_rb, 0);
	mem_realloc_data(rhdr_rb->data, rhdr_rb->offset);

	if (auth_req != NULL)
	{
		make_rpc_auth_ntlmssp_req(&ntlmssp_req,
		                         "NTLMSSP", 0x1,
		                         0x0000b2b3, 
		                         my_name, domain);
		smb_io_rpc_auth_ntlmssp_req("", &ntlmssp_req, auth_req, 0);
		mem_realloc_data(auth_req->data, auth_req->offset);
	}

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BIND, 0x0, get_rpc_call_id(),
	             rhdr_rb->offset,
	             auth_req != NULL ? auth_req->offset : 0);

	smb_io_rpc_hdr("hdr"   , &hdr   , rhdr, 0);
	mem_realloc_data(rhdr->data, rhdr->offset);

	if (rhdr->data == NULL || rhdr_rb->data == NULL) return False;

    /***/
	/*** link rpc header, bind acknowledgment and authentication responses ***/
    /***/

	rhdr->data->offset.start = 0;
	rhdr->data->offset.end   = rhdr->offset;
	rhdr->data->next         = rhdr_rb->data;

	if (auth_req != NULL)
	{
		rhdr_rb->data->offset.start = rhdr->offset;
		rhdr_rb->data->offset.end   = rhdr->offset + rhdr_rb->offset;
		rhdr_rb->data->next         = auth_req->data;

		auth_req->data->offset.start = rhdr->offset + rhdr_rb->offset;
		auth_req->data->offset.end   = rhdr->offset + auth_req->offset + rhdr_rb->offset;
		auth_req->data->next         = NULL;
	}
	else
	{
		rhdr_rb->data->offset.start = rhdr->offset;
		rhdr_rb->data->offset.end   = rhdr->offset + rhdr_rb->offset;
		rhdr_rb->data->next         = NULL;
	}

	return True;
}


/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_rpc_request(prs_struct *rhdr, uint8 op_num, int data_len)
{
	RPC_HDR_REQ hdr_req;
	RPC_HDR     hdr;

	DEBUG(5,("create_rpc_request: opnum: 0x%x data_len: 0x%x\n",
	          op_num, data_len));

	/* create the rpc header RPC_HDR */
	make_rpc_hdr(&hdr   , RPC_REQUEST, RPC_FLG_FIRST | RPC_FLG_LAST,
	             get_rpc_call_id(), data_len + 0x18, 0);

	/* create the rpc request RPC_HDR_REQ */
	make_rpc_hdr_req(&hdr_req, data_len, op_num);

	/* stream-time... */
	smb_io_rpc_hdr    ("hdr    ", &hdr    , rhdr, 0);
	smb_io_rpc_hdr_req("hdr_req", &hdr_req, rhdr, 0);

	if (rhdr->data == NULL || rhdr->offset != 0x18) return False;

	rhdr->data->offset.start = 0;
	rhdr->data->offset.end   = rhdr->offset;

	return True;
}


/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
BOOL rpc_api_pipe_req(struct cli_state *cli, int t_idx, uint16 fnum,
				uint8 op_num,
				prs_struct *data, prs_struct *rdata)
{
	/* fudge this, at the moment: create the header; memcpy the data.  oops. */
	prs_struct rparam;
	prs_struct hdr;
	int data_len;
	BOOL ret;

	data_len               = data->offset + 0x18;
	data->data->offset.end = data->offset;

	prs_init(&hdr   , data_len, 4, SAFETY_MARGIN, False);
	prs_init(&rparam, 0       , 4, 0            , True );

	create_rpc_request(&hdr, op_num, data_len);

	mem_realloc_data(hdr.data, data_len);
	hdr.data->offset.end = data_len;
	mem_buf_copy(mem_data(&(hdr.data), 0x18), data->data, 0, data->offset);

	ret = rpc_api_pipe(cli, t_idx, 0x0026, fnum, NULL, &hdr, &rparam, rdata);

	prs_mem_free(&rparam);
	prs_mem_free(&hdr);

	return ret;
}


/****************************************************************************
do an rpc bind
****************************************************************************/
BOOL rpc_pipe_set_hnd_state(struct cli_state *cli, int t_idx,
				char *pipe_name, uint16 fnum, uint16 device_state)
{
	prs_struct param;
	prs_struct rdata;
	prs_struct rparam;
	BOOL state_set = False;
	uint16 setup[2]; /* only need 2 uint16 setup parameters */

	if (pipe_name == NULL) return False;

	prs_init(&param , 2, 4, 0            , False);
	prs_init(&rdata , 0, 4, SAFETY_MARGIN, True );
	prs_init(&rparam, 0, 4, SAFETY_MARGIN, True );

	param.data->offset.start = 0;
	param.data->offset.end   = 2;

	DEBUG(5,("Set Handle state Pipe[%x]: %s - device state:%x\n",
	          fnum, pipe_name, device_state));

	/* create data parameters: device state */
	SSVAL(param.data->data, 0, device_state);

	/* create setup parameters. */
	setup[0] = 0x0001; 
	setup[1] = fnum; /* pipe file handle.  got this from an SMBcreateX. */

	/* send the data on \PIPE\ */
	if (cli_api_pipe(cli, t_idx, "\\PIPE\\\0\0\0", 8,

	            2, 0, 2,

	            0, 1024,

	            param.data->data, NULL, setup,

	            rparam.data, rdata.data))
	{
		DEBUG(5, ("Set Handle state: return OK\n"));
		state_set = True;
	}

	prs_mem_free(&param );
	prs_mem_free(&rparam);
	prs_mem_free(&rdata );

	return state_set;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/
static BOOL valid_pipe_name(char *pipe_name,
				RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	int pipe_idx = 0;

	while (pipe_names[pipe_idx].client_pipe != NULL)
	{
		if (strcmp(pipe_name, pipe_names[pipe_idx].client_pipe ) == 0)
		{
			DEBUG(5,("Bind Abstract Syntax: "));	
			dump_data(5, (uchar*)&(pipe_names[pipe_idx].abstr_syntax), sizeof(pipe_names[pipe_idx].abstr_syntax));
			DEBUG(5,("Bind Transfer Syntax: "));
			dump_data(5, (uchar*)&(pipe_names[pipe_idx].trans_syntax), sizeof(pipe_names[pipe_idx].trans_syntax));

			/* copy the required syntaxes out so we can do the right bind */
			memcpy(transfer, &(pipe_names[pipe_idx].trans_syntax), sizeof(pipe_names[pipe_idx].trans_syntax));
			memcpy(abstract, &(pipe_names[pipe_idx].abstr_syntax), sizeof(pipe_names[pipe_idx].abstr_syntax));

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
static BOOL check_bind_response(RPC_HDR_BA *hdr_ba, char *pipe_name, RPC_IFACE *transfer)
{
	int i = 0;

	while ((pipe_names[i].client_pipe != NULL))
	{
		DEBUG(6,("bind_rpc_pipe: searching pipe name: client:%s server:%s\n",
				  pipe_names[i].client_pipe , pipe_names[i].server_pipe ));

		if ((strcmp(pipe_name, pipe_names[i].client_pipe ) == 0))
		{
			if (strcmp(hdr_ba->addr.str, pipe_names[i].server_pipe ) == 0)
			{
				DEBUG(5,("bind_rpc_pipe: server pipe_name found: %s\n",
						pipe_names[i].server_pipe ));
				break;
			}
			else
			{
				DEBUG(2,("bind_rpc_pipe: pipe_name %s != expected pipe %s\n",
						pipe_names[i].server_pipe , hdr_ba->addr.str));
				return False;
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
		DEBUG(2,("bind_rpc_pipe: transfer syntax differs\n"));
		return False;
	}
	
	/* lkclXXXX only accept one result: check the result(s) */
	if (hdr_ba->res.num_results != 0x1 || hdr_ba->res.result != 0)
	{
		DEBUG(2,("bind_rpc_pipe: bind denied results: %d reason: %x\n",
					  hdr_ba->res.num_results,
					  hdr_ba->res.reason));
	}
		
	DEBUG(5,("bind_rpc_pipe: accepted!\n"));
	return True;
}

/****************************************************************************
do an rpc bind
****************************************************************************/
BOOL rpc_pipe_bind(struct cli_state *cli, int t_idx, char *pipe_name, uint16 fnum, 
				RPC_IFACE *abstract, RPC_IFACE *transfer, BOOL ntlmssp_auth,
				char *my_name, char *domain)
{
	prs_struct hdr;
	prs_struct hdr_rb;
	prs_struct auth_req;
	prs_struct data;
	prs_struct rdata;
	prs_struct rparam;

    BOOL valid_ack = False;

	if (pipe_name == NULL || abstract == NULL || transfer == NULL) return False;

	DEBUG(5,("Bind RPC Pipe[%x]: %s\n", fnum, pipe_name));

	if (!valid_pipe_name(pipe_name, abstract, transfer)) return False;

	prs_init(&hdr     , 0x10                   , 4, 0x0          , False);
	prs_init(&hdr_rb  , 1024                   , 4, SAFETY_MARGIN, False);
	prs_init(&auth_req, ntlmssp_auth ? 1024 : 0, 4, SAFETY_MARGIN, False);

	prs_init(&rdata , 0   , 4, SAFETY_MARGIN, True );
	prs_init(&rparam, 0   , 4, SAFETY_MARGIN, True );

	create_rpc_bind_req(&hdr, &hdr_rb, ntlmssp_auth ? &auth_req : NULL,
	                    abstract, transfer,
	                    my_name, domain);

	/* this is a hack due to limitations in rpc_api_pipe */
	prs_init(&data, mem_buf_len(hdr.data), 4, 0x0, False);
	mem_buf_copy(data.data->data, hdr.data, 0, mem_buf_len(hdr.data));

	/* send data on \PIPE\.  receive a response */
	if (rpc_api_pipe(cli, t_idx, 0x0026, fnum, NULL, &data, &rparam, &rdata))
	{
		RPC_HDR_BA hdr_ba;

		DEBUG(5, ("rpc_api_pipe: return OK\n"));

		smb_io_rpc_hdr_ba("", &hdr_ba, &rdata, 0);

		if (rdata.offset != 0) valid_ack = check_bind_response(&hdr_ba, pipe_name, transfer);
	}

	prs_mem_free(&data    );
	prs_mem_free(&hdr     );
	prs_mem_free(&hdr_rb  );
	prs_mem_free(&auth_req);
	prs_mem_free(&rdata   );
	prs_mem_free(&rparam  );

	return valid_ack;
}

/****************************************************************************
 open a session
 ****************************************************************************/
BOOL do_session_open(struct cli_state *cli, int t_idx,
				char *pipe_name, uint16 *fnum)
{
	RPC_IFACE abstract;
	RPC_IFACE transfer;


	/******************* open the pipe *****************/
	if (((*fnum) = cli_open(cli, t_idx, pipe_name, O_CREAT|O_WRONLY, DENY_NONE,
	                         NULL, NULL, NULL)) == 0xffff)
	{
		DEBUG(1,("do_session_open: cli_open failed\n"));
		return False;
	}

	/**************** Set Named Pipe State ***************/
	if (!rpc_pipe_set_hnd_state(cli, t_idx, pipe_name, (*fnum), 0x4300))
	{
		DEBUG(1,("do_session_open: pipe hnd state failed\n"));
		return False;
	}

	/******************* bind request on pipe *****************/
	if (!rpc_pipe_bind(cli, t_idx, pipe_name, (*fnum),
	                   &abstract, &transfer,
	                   False, NULL, NULL))
	{
		DEBUG(1,("do_session_open: rpc bind failed\n"));
		return False;
	}

	return True;
}


/****************************************************************************
 open an encrypted session
 ****************************************************************************/
BOOL do_ntlm_session_open(struct cli_state *cli, int t_idx,
				char *pipe_name, uint16 *fnum,
				char *my_name, char *domain)
{
	RPC_IFACE abstract;
	RPC_IFACE transfer;

	/******************* open the pipe *****************/
	if (((*fnum) = cli_open(cli, t_idx, pipe_name, O_CREAT|O_WRONLY, DENY_NONE,
	                         NULL, NULL, NULL)) == 0xffff)
	{
		DEBUG(1,("do_ntlm_session_open: cli_open failed\n"));
		return False;
	}

	/**************** Set Named Pipe State ***************/
	if (!rpc_pipe_set_hnd_state(cli, t_idx, pipe_name, (*fnum), 0x4300))
	{
		DEBUG(1,("do_ntlm_session_open: pipe hnd state failed\n"));
		return False;
	}

	/******************* bind request on pipe *****************/
	if (!rpc_pipe_bind(cli, t_idx, pipe_name, (*fnum),
	                   &abstract, &transfer,
	                   True, my_name, domain))
	{
		DEBUG(1,("do_ntlm_session_open: rpc bind failed\n"));
		return False;
	}

	return True;
}


/****************************************************************************
close the session
****************************************************************************/
void do_session_close(struct cli_state *cli, int t_idx, uint16 fnum)
{
	if (fnum != 0xffff)
	{
		cli_close(cli, t_idx, fnum, 0);
	}
}

