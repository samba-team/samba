/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Inter-process communication and named pipe handling
   Copyright (C) Andrew Tridgell 1992-1998

   SMB Version handling
   Copyright (C) John H Terpstra 1995-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   */
/*
   This file handles the named pipe and mailslot calls
   in the SMBtrans protocol
   */

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;
extern int max_send;

extern fstring local_machine;

#define NERR_notsupported 50


extern int smb_read_error;
extern uint32 global_client_caps;

/*******************************************************************
 copies parameters and data, as needed, into the smb buffer

 *both* the data and params sections should be aligned.  this
 is fudged in the rpc pipes by 
 at present, only the data section is.  this may be a possible
 cause of some of the ipc problems being experienced.  lkcl26dec97

 ******************************************************************/
static void copy_trans_params_and_data(char *outbuf, int align,
				       prs_struct *rparam, prs_struct *rdata,
				       int param_offset, int data_offset,
				       int param_len, int data_len)
{
	char *copy_into = smb_buf(outbuf) + 1;

	DEBUG(5, ("copy_trans_params_and_data: params[%d..%d] data[%d..%d]\n",
		  param_offset, param_offset + param_len,
		  data_offset, data_offset + data_len));

	if (param_len)
		prs_buf_copy(copy_into, rparam, param_offset, param_len);
	copy_into += param_len + align;
	if (data_len)
		prs_buf_copy(copy_into, rdata, data_offset, data_len);
}

/****************************************************************************
  send a trans reply
  ****************************************************************************/
void send_trans_reply(char *outbuf,
		      prs_struct *rdata,
		      prs_struct *rparam,
		      uint16 *setup, int lsetup, int max_data_ret,
		      BOOL pipe_data_outstanding)
{
	int i;
	int this_ldata, this_lparam;
	int tot_data = 0, tot_param = 0;
	int align;

	int ldata = rdata ? prs_buf_len(rdata) : 0;
	int lparam = rparam ? prs_buf_len(rparam) : 0;

	BOOL buffer_too_large = max_data_ret ? ldata > max_data_ret : False;

	DEBUG(10,
	      ("send_trans_reply: max_data_ret: %d datalen: %d plen: %d\n",
	       max_data_ret, ldata, lparam));

	if (buffer_too_large)
	{
		DEBUG(5,
		      ("send_trans_reply: buffer %d too large %d\n", ldata,
		       max_data_ret));
		ldata = max_data_ret;
	}

	this_lparam = MIN(lparam, max_send - (500 + lsetup * SIZEOFWORD));	/* hack */
	this_ldata =
		MIN(ldata,
		    max_send - (500 + lsetup * SIZEOFWORD + this_lparam));

	align = ((this_lparam) % 4);

	set_message(outbuf, 10 + lsetup, 1 + align + this_ldata + this_lparam,
		    True);

	if (buffer_too_large || pipe_data_outstanding)
	{
		if (global_client_caps & CAP_STATUS32)
		{
			/* issue a buffer size warning.  on a DCE/RPC pipe, expect an SMBreadX... */
			SIVAL(outbuf, smb_flg2, FLAGS2_32_BIT_ERROR_CODES);
			SIVAL(outbuf, smb_rcls, 0x80000005);	/* STATUS_BUFFER_OVERFLOW */
		}
		else
		{
			SCVAL(outbuf, smb_rcls, ERRDOS);
			SSVAL(outbuf, smb_err, ERRmoredata);
		}
	}

	copy_trans_params_and_data(outbuf, align,
				   rparam, rdata,
				   tot_param, tot_data,
				   this_lparam, this_ldata);

	SSVAL(outbuf, smb_vwv0, lparam);
	SSVAL(outbuf, smb_vwv1, ldata);
	SSVAL(outbuf, smb_vwv3, this_lparam);
	SSVAL(outbuf, smb_vwv4, smb_offset(smb_buf(outbuf) + 1, outbuf));
	SSVAL(outbuf, smb_vwv5, 0);
	SSVAL(outbuf, smb_vwv6, this_ldata);
	SSVAL(outbuf, smb_vwv7,
	      smb_offset(smb_buf(outbuf) + 1 + this_lparam + align, outbuf));
	SSVAL(outbuf, smb_vwv8, 0);
	SSVAL(outbuf, smb_vwv9, lsetup);

	for (i = 0; i < lsetup; i++)
	{
		SSVAL(outbuf, smb_vwv10 + i * SIZEOFWORD, setup[i]);
	}

	show_msg(outbuf);
	send_smb(smbd_server_fd(), outbuf);

	tot_data = this_ldata;
	tot_param = this_lparam;

	while (tot_data < ldata || tot_param < lparam)
	{
		this_lparam = MIN(lparam - tot_param, max_send - 500);	/* hack */
		this_ldata =
			MIN(ldata - tot_data, max_send - (500 + this_lparam));

		align = (this_lparam % 4);

		set_message(outbuf, 10, 1 + this_ldata + this_lparam + align,
			    False);

		copy_trans_params_and_data(outbuf, align,
					   rparam, rdata,
					   tot_param, tot_data,
					   this_lparam, this_ldata);

		SSVAL(outbuf, smb_vwv3, this_lparam);
		SSVAL(outbuf, smb_vwv4,
		      smb_offset(smb_buf(outbuf) + 1, outbuf));
		SSVAL(outbuf, smb_vwv5, tot_param);
		SSVAL(outbuf, smb_vwv6, this_ldata);
		SSVAL(outbuf, smb_vwv7,
		      smb_offset(smb_buf(outbuf) + 1 + this_lparam + align,
				 outbuf));
		SSVAL(outbuf, smb_vwv8, tot_data);
		SSVAL(outbuf, smb_vwv9, 0);

		show_msg(outbuf);
		send_smb(smbd_server_fd(), outbuf);

		tot_data += this_ldata;
		tot_param += this_lparam;
	}
}

static void api_rpc_trans_reply(char *outbuf, char *rdata, int rlen,
				BOOL pipe_data_outstanding)
{
	prs_struct ps;
	prs_create(&ps, rdata, rlen, 0, False);
	prs_debug_out(&ps, "api_rpc_trans_reply", 200);
	send_trans_reply(outbuf, &ps, NULL, NULL, 0, rlen,
			 pipe_data_outstanding);
}

/****************************************************************************
 WaitNamedPipeHandleState 
****************************************************************************/
static BOOL api_WNPHS(char *outbuf, pipes_struct * p, char *param, int mdrcnt)
{
	uint16 priority;

	if (!param)
		return False;

	priority = param[0] + (param[1] << 8);
	DEBUG(4, ("WaitNamedPipeHandleState priority %x\n", priority));

	if (wait_rpc_pipe_hnd_state(p, priority))
	{
		/* now send the reply */
		send_trans_reply(outbuf, NULL, NULL, NULL, 0, mdrcnt, False);

		return True;
	}
	return False;
}


/****************************************************************************
 SetNamedPipeHandleState 
****************************************************************************/
static BOOL api_SNPHS(char *outbuf, pipes_struct * p, char *param, int mdrcnt)
{
	uint16 id;

	if (!param)
		return False;

	id = param[0] + (param[1] << 8);
	DEBUG(4, ("SetNamedPipeHandleState to code %x\n", id));

	if (set_rpc_pipe_hnd_state(p, id))
	{
		/* now send the reply */
		send_trans_reply(outbuf, NULL, NULL, NULL, 0, mdrcnt, False);

		return True;
	}
	return False;
}


/****************************************************************************
 when no reply is generated, indicate unsupported.
 ****************************************************************************/
static BOOL api_no_reply(char *outbuf, int max_rdata_len)
{
	prs_struct rparam;

	prs_init(&rparam, 4, 0, False);

	rparam.start = 0;
	rparam.end = 4;

	/* unsupported */
	SSVAL(rparam.data, 0, NERR_notsupported);
	SSVAL(rparam.data, 2, 0);	/* converter word */

	DEBUG(3, ("Unsupported API fd command\n"));

	/* now send the reply */
	send_trans_reply(outbuf, NULL, &rparam, NULL, 0, max_rdata_len,
			 False);

	prs_free_data(&rparam);

	return (-1);
}

/****************************************************************************
  handle remote api calls delivered to a named pipe already opened.
  ****************************************************************************/
static int api_fd_reply(connection_struct * conn, uint16 vuid, char *outbuf,
			uint16 *setup, char *data, char *params,
			int suwcnt, int tdscnt, int tpscnt, int mdrcnt,
			int mprcnt)
{
	BOOL reply = False;

	uint16 pnum;
	uint16 subcommand;
	pipes_struct *p = NULL;

	DEBUG(5, ("api_fd_reply\n"));

	/* First find out the name of this file. */
	if (suwcnt != 2)
	{
		DEBUG(0, ("Unexpected named pipe transaction.\n"));
		return (-1);
	}

	/* Get the file handle and hence the file name. */
	pnum = setup[1];
	subcommand = setup[0];
	p = get_rpc_pipe(pnum);

	if (p != NULL)
	{
		DEBUG(3, ("Got API command 0x%x on pipe \"%s\" (pnum %x)",
			  subcommand, p->name, pnum));

		/* record maximum data length that can be transmitted in an SMBtrans */
		DEBUG(10, ("api_fd_reply: p:%p mdrcnt: %d\n", p, mdrcnt));

		switch (subcommand)
		{
			case 0x26:
			{
				BOOL pipe_outstanding = False;
				char *rdata = NULL;
				int rlen = mdrcnt;
				reply = readwrite_pipe(p, data, tdscnt,
						       &rdata, &rlen,
						       &pipe_outstanding);
				if (reply)
				{
					api_rpc_trans_reply(outbuf, rdata,
							    rlen,
							    pipe_outstanding);
				}
				break;
			}
			case 0x53:
			{
				/* Wait Named Pipe Handle state */
				reply = api_WNPHS(outbuf, p, params, mdrcnt);
				break;
			}
			case 0x01:
			{
				/* Set Named Pipe Handle state */
				reply = api_SNPHS(outbuf, p, params, mdrcnt);
				break;
			}
		}
	}
	else
	{
		DEBUG(1, ("api_fd_reply: INVALID PIPE HANDLE: %x\n", pnum));
	}

	if (!reply)
	{
		return api_no_reply(outbuf, mdrcnt);
	}
	return -1;
}

/****************************************************************************
  handle named pipe commands
  ****************************************************************************/
static int named_pipe(connection_struct * conn, uint16 vuid, char *outbuf,
		      char *name, uint16 *setup, char *data, char *params,
		      int suwcnt, int tdscnt, int tpscnt, int msrcnt,
		      int mdrcnt, int mprcnt)
{
	DEBUG(3, ("named pipe command on <%s> name\n", name));

	if (strequal(name, "LANMAN"))
	{
		return api_reply(conn, vuid, outbuf, data, params, tdscnt,
				 tpscnt, mdrcnt, mprcnt);
	}

	if (strequal(name, "WKSSVC") ||
	    strequal(name, "SRVSVC") ||
	    strequal(name, "WINREG") ||
	    strequal(name, "SAMR") || strequal(name, "LSARPC"))
	{
		DEBUG(4, ("named pipe command from Win95 (wow!)\n"));
		return api_fd_reply(conn, vuid, outbuf, setup, data, params,
				    suwcnt, tdscnt, tpscnt, mdrcnt, mprcnt);
	}

	if (strlen(name) < 1)
	{
		return api_fd_reply(conn, vuid, outbuf, setup, data, params,
				    suwcnt, tdscnt, tpscnt, mdrcnt, mprcnt);
	}

	if (setup)
	{
		DEBUG(3,
		      ("unknown named pipe: setup 0x%X setup1=%d\n",
		       (int)setup[0], (int)setup[1]));
	}

	return 0;
}


/****************************************************************************
  reply to a SMBtrans
  ****************************************************************************/
int reply_trans(connection_struct * conn, char *inbuf, char *outbuf, int size,
		int bufsize)
{
	fstring name;
	int name_offset = 0;
	char *data = NULL, *params = NULL;
	uint16 *setup = NULL;
	int outsize = 0;
	uint16 vuid = SVAL(inbuf, smb_uid);
	int tpscnt = SVAL(inbuf, smb_vwv0);
	int tdscnt = SVAL(inbuf, smb_vwv1);
	int mprcnt = SVAL(inbuf, smb_vwv2);
	int mdrcnt = SVAL(inbuf, smb_vwv3);
	int msrcnt = CVAL(inbuf, smb_vwv4);
	BOOL close_on_completion = BITSETW(inbuf + smb_vwv5, 0);
	BOOL one_way = BITSETW(inbuf + smb_vwv5, 1);
	int pscnt = SVAL(inbuf, smb_vwv9);
	int psoff = SVAL(inbuf, smb_vwv10);
	int dscnt = SVAL(inbuf, smb_vwv11);
	int dsoff = SVAL(inbuf, smb_vwv12);
	int suwcnt = CVAL(inbuf, smb_vwv13);

	ZERO_STRUCT(name);
	fstrcpy(name, smb_buf(inbuf));

	if (dscnt > tdscnt || pscnt > tpscnt)
	{
		exit_server("invalid trans parameters\n");
	}

	if (tdscnt)
	{
		if ((data = (char *)malloc(tdscnt)) == NULL)
		{
			DEBUG(0,
			      ("reply_trans: data malloc fail for %d bytes !\n",
			       tdscnt));
			return (ERROR(ERRDOS, ERRnomem));
		}
		memcpy(data, smb_base(inbuf) + dsoff, dscnt);
	}

	if (tpscnt)
	{
		if ((params = (char *)malloc(tpscnt)) == NULL)
		{
			DEBUG(0,
			      ("reply_trans: param malloc fail for %d bytes !\n",
			       tpscnt));
			return (ERROR(ERRDOS, ERRnomem));
		}
		memcpy(params, smb_base(inbuf) + psoff, pscnt);
	}

	if (suwcnt)
	{
		int i;
		if ((setup = (uint16 *)malloc(suwcnt * sizeof(uint16))) ==
		    NULL)
		{
			DEBUG(0,
			      ("reply_trans: setup malloc fail for %d bytes !\n",
			       suwcnt * sizeof(uint16)));
			return (ERROR(ERRDOS, ERRnomem));
		}
		for (i = 0; i < suwcnt; i++)
			setup[i] = SVAL(inbuf, smb_vwv14 + i * SIZEOFWORD);
	}


	if (pscnt < tpscnt || dscnt < tdscnt)
	{
		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		outsize = set_message(outbuf, 0, 0, True);
		show_msg(outbuf);
		send_smb(smbd_server_fd(), outbuf);
	}

	/* receive the rest of the trans packet */
	while (pscnt < tpscnt || dscnt < tdscnt)
	{
		BOOL ret;
		int pcnt, poff, dcnt, doff, pdisp, ddisp;

		ret = receive_next_smb(inbuf, bufsize, SMB_SECONDARY_WAIT);

		show_msg(inbuf);

		if ((ret && (CVAL(inbuf, smb_com) != SMBtrans &&
			     CVAL(inbuf, smb_com) != SMBtranss)) || !ret)
		{
			if (ret)
			{
				DEBUG(0,
				      ("reply_trans: Invalid secondary trans packet\n"));
			}
			else
			{
				DEBUG(0,
				      ("reply_trans: %s in getting secondary trans response.\n",
				       (smb_read_error ==
					READ_ERROR) ? "error" : "timeout"));
			}
			if (params)
				free(params);
			if (data)
				free(data);
			if (setup)
				free(setup);
			return (ERROR(ERRSRV, ERRerror));
		}

		tpscnt = SVAL(inbuf, smb_vwv0);
		tdscnt = SVAL(inbuf, smb_vwv1);

		pcnt = SVAL(inbuf, smb_vwv2);
		poff = SVAL(inbuf, smb_vwv3);
		pdisp = SVAL(inbuf, smb_vwv4);

		dcnt = SVAL(inbuf, smb_vwv5);
		doff = SVAL(inbuf, smb_vwv6);
		ddisp = SVAL(inbuf, smb_vwv7);

		pscnt += pcnt;
		dscnt += dcnt;

		if (dscnt > tdscnt || pscnt > tpscnt)
		{
			exit_server("invalid trans parameters\n");
		}

		if (pcnt)
			memcpy(params + pdisp, smb_base(inbuf) + poff, pcnt);
		if (dcnt)
			memcpy(data + ddisp, smb_base(inbuf) + doff, dcnt);
	}


	DEBUG(3, ("trans <%s> data=%d params=%d setup=%d\n",
		  name, tdscnt, tpscnt, suwcnt));

	/*
	 * WinCE wierdness....
	 */

	if (name[0] == '\\' && (StrnCaseCmp(&name[1], local_machine,
					    strlen(local_machine)) == 0))
	{
		name_offset = strlen(local_machine) + 1;
	}

	if (strncmp(&name[name_offset], "\\PIPE\\", strlen("\\PIPE\\")) == 0)
	{
		DEBUG(5, ("calling named_pipe\n"));
		outsize = named_pipe(conn, vuid, outbuf,
				     name + name_offset + strlen("\\PIPE\\"),
				     setup, data, params, suwcnt, tdscnt,
				     tpscnt, msrcnt, mdrcnt, mprcnt);
	}
	else
	{
		DEBUG(3, ("invalid pipe name\n"));
		outsize = 0;
	}


	if (data)
		free(data);
	if (params)
		free(params);
	if (setup)
		free(setup);

	if (close_on_completion)
		close_cnum(conn, vuid);

	if (one_way)
		return (-1);

	if (outsize == 0)
		return (ERROR(ERRSRV, ERRnosupport));

	return (outsize);
}
