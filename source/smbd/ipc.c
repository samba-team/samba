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
				char *rparam, int param_offset, int param_len,
				char *rdata, int data_offset, int data_len)
{
	char *copy_into = smb_buf(outbuf)+1;

	if(param_len < 0)
		param_len = 0;

	if(data_len < 0)
		data_len = 0;

	DEBUG(5,("copy_trans_params_and_data: params[%d..%d] data[%d..%d]\n",
			param_offset, param_offset + param_len,
			data_offset , data_offset  + data_len));

	if (param_len)
		memcpy(copy_into, &rparam[param_offset], param_len);

	copy_into += param_len + align;

	if (data_len )
		memcpy(copy_into, &rdata[data_offset], data_len);
}

/****************************************************************************
 Send a trans reply.
 ****************************************************************************/

void send_trans_reply(char *outbuf,
				char *rparam, int rparam_len,
				char *rdata, int rdata_len,
				BOOL buffer_too_large)
{
	int this_ldata,this_lparam;
	int tot_data_sent = 0;
	int tot_param_sent = 0;
	int align;

	int ldata  = rdata  ? rdata_len : 0;
	int lparam = rparam ? rparam_len : 0;

	if (buffer_too_large)
		DEBUG(5,("send_trans_reply: buffer %d too large\n", ldata ));

	this_lparam = MIN(lparam,max_send - 500); /* hack */
	this_ldata  = MIN(ldata,max_send - (500+this_lparam));

	align = ((this_lparam)%4);

	set_message(outbuf,10,1+align+this_ldata+this_lparam,True);

	if (buffer_too_large) {
		/* issue a buffer size warning.  on a DCE/RPC pipe, expect an SMBreadX... */
		if (!(global_client_caps & CAP_STATUS32 )) { 
			/* Win9x version. */
			SSVAL(outbuf, smb_err, ERRmoredata);
			SCVAL(outbuf, smb_rcls, ERRDOS);
		} else {
			SIVAL(outbuf, smb_flg2, SVAL(outbuf, smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);
			SIVAL(outbuf, smb_rcls, NT_STATUS_V(STATUS_BUFFER_OVERFLOW));
		}
	}

	copy_trans_params_and_data(outbuf, align,
								rparam, tot_param_sent, this_lparam,
								rdata, tot_data_sent, this_ldata);

	SSVAL(outbuf,smb_vwv0,lparam);
	SSVAL(outbuf,smb_vwv1,ldata);
	SSVAL(outbuf,smb_vwv3,this_lparam);
	SSVAL(outbuf,smb_vwv4,smb_offset(smb_buf(outbuf)+1,outbuf));
	SSVAL(outbuf,smb_vwv5,0);
	SSVAL(outbuf,smb_vwv6,this_ldata);
	SSVAL(outbuf,smb_vwv7,smb_offset(smb_buf(outbuf)+1+this_lparam+align,outbuf));
	SSVAL(outbuf,smb_vwv8,0);
	SSVAL(outbuf,smb_vwv9,0);

	show_msg(outbuf);
	if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("send_trans_reply: send_smb failed.\n");

	tot_data_sent = this_ldata;
	tot_param_sent = this_lparam;

	while (tot_data_sent < ldata || tot_param_sent < lparam)
	{
		this_lparam = MIN(lparam-tot_param_sent, max_send - 500); /* hack */
		this_ldata  = MIN(ldata -tot_data_sent, max_send - (500+this_lparam));

		if(this_lparam < 0)
			this_lparam = 0;

		if(this_ldata < 0)
			this_ldata = 0;

		align = (this_lparam%4);

		set_message(outbuf,10,1+this_ldata+this_lparam+align,False);

		copy_trans_params_and_data(outbuf, align,
									rparam, tot_param_sent, this_lparam,
									rdata, tot_data_sent, this_ldata);

		SSVAL(outbuf,smb_vwv3,this_lparam);
		SSVAL(outbuf,smb_vwv4,smb_offset(smb_buf(outbuf)+1,outbuf));
		SSVAL(outbuf,smb_vwv5,tot_param_sent);
		SSVAL(outbuf,smb_vwv6,this_ldata);
		SSVAL(outbuf,smb_vwv7,smb_offset(smb_buf(outbuf)+1+this_lparam+align,outbuf));
		SSVAL(outbuf,smb_vwv8,tot_data_sent);
		SSVAL(outbuf,smb_vwv9,0);

		show_msg(outbuf);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("send_trans_reply: send_smb failed.\n");

		tot_data_sent  += this_ldata;
		tot_param_sent += this_lparam;
	}
}

/****************************************************************************
 Start the first part of an RPC reply which began with an SMBtrans request.
****************************************************************************/

static BOOL api_rpc_trans_reply(char *outbuf, pipes_struct *p)
{
	char *rdata = malloc(p->max_trans_reply);
	int data_len;

	if(rdata == NULL) {
		DEBUG(0,("api_rpc_trans_reply: malloc fail.\n"));
		return False;
	}

	if((data_len = read_from_pipe( p, rdata, p->max_trans_reply)) < 0) {
		SAFE_FREE(rdata);
		return False;
	}

	send_trans_reply(outbuf, NULL, 0, rdata, data_len, p->out_data.current_pdu_len > data_len);

	SAFE_FREE(rdata);
	return True;
}

/****************************************************************************
 WaitNamedPipeHandleState 
****************************************************************************/

static BOOL api_WNPHS(char *outbuf, pipes_struct *p, char *param, int param_len)
{
	uint16 priority;

	if (!param || param_len < 2)
		return False;

	priority = SVAL(param,0);
	DEBUG(4,("WaitNamedPipeHandleState priority %x\n", priority));

	if (wait_rpc_pipe_hnd_state(p, priority)) {
		/* now send the reply */
		send_trans_reply(outbuf, NULL, 0, NULL, 0, False);
		return True;
	}
	return False;
}


/****************************************************************************
 SetNamedPipeHandleState 
****************************************************************************/

static BOOL api_SNPHS(char *outbuf, pipes_struct *p, char *param, int param_len)
{
	uint16 id;

	if (!param || param_len < 2)
		return False;

	id = SVAL(param,0);
	DEBUG(4,("SetNamedPipeHandleState to code %x\n", id));

	if (set_rpc_pipe_hnd_state(p, id)) {
		/* now send the reply */
		send_trans_reply(outbuf, NULL, 0, NULL, 0, False);
		return True;
	}
	return False;
}


/****************************************************************************
 When no reply is generated, indicate unsupported.
 ****************************************************************************/

static BOOL api_no_reply(char *outbuf, int max_rdata_len)
{
	char rparam[4];

	/* unsupported */
	SSVAL(rparam,0,NERR_notsupported);
	SSVAL(rparam,2,0); /* converter word */

	DEBUG(3,("Unsupported API fd command\n"));

	/* now send the reply */
	send_trans_reply(outbuf, rparam, 4, NULL, 0, False);

	return -1;
}

/****************************************************************************
 Handle remote api calls delivered to a named pipe already opened.
 ****************************************************************************/

static int api_fd_reply(connection_struct *conn,uint16 vuid,char *outbuf,
		 	uint16 *setup,char *data,char *params,
		 	int suwcnt,int tdscnt,int tpscnt,int mdrcnt,int mprcnt)
{
	BOOL reply = False;
	pipes_struct *p = NULL;
	int pnum;
	int subcommand;

	DEBUG(5,("api_fd_reply\n"));

	/* First find out the name of this file. */
	if (suwcnt != 2) {
		DEBUG(0,("Unexpected named pipe transaction.\n"));
		return(-1);
	}

	/* Get the file handle and hence the file name. */
	/* 
	 * NB. The setup array has already been transformed
	 * via SVAL and so is in gost byte order.
	 */
	pnum = ((int)setup[1]) & 0xFFFF;
	subcommand = ((int)setup[0]) & 0xFFFF;

	if(!(p = get_rpc_pipe(pnum))) {
		DEBUG(1,("api_fd_reply: INVALID PIPE HANDLE: %x\n", pnum));
		return api_no_reply(outbuf, mdrcnt);
	}

	DEBUG(3,("Got API command 0x%x on pipe \"%s\" (pnum %x)", subcommand, p->name, pnum));

	/* record maximum data length that can be transmitted in an SMBtrans */
	p->max_trans_reply = mdrcnt;

	DEBUG(10,("api_fd_reply: p:%p max_trans_reply: %d\n", p, p->max_trans_reply));

	switch (subcommand) {
	case 0x26:
		/* dce/rpc command */
		reply = write_to_pipe(p, data, tdscnt);
		if (reply)
			reply = api_rpc_trans_reply(outbuf, p);
		break;
	case 0x53:
		/* Wait Named Pipe Handle state */
		reply = api_WNPHS(outbuf, p, params, tpscnt);
		break;
	case 0x01:
		/* Set Named Pipe Handle state */
		reply = api_SNPHS(outbuf, p, params, tpscnt);
		break;
	}

	if (!reply)
		return api_no_reply(outbuf, mdrcnt);

	return -1;
}

/****************************************************************************
  handle named pipe commands
  ****************************************************************************/
static int named_pipe(connection_struct *conn,uint16 vuid, char *outbuf,char *name,
		      uint16 *setup,char *data,char *params,
		      int suwcnt,int tdscnt,int tpscnt,
		      int msrcnt,int mdrcnt,int mprcnt)
{
	DEBUG(3,("named pipe command on <%s> name\n", name));

	if (strequal(name,"LANMAN"))
		return api_reply(conn,vuid,outbuf,data,params,tdscnt,tpscnt,mdrcnt,mprcnt);

	if (strequal(name,"WKSSVC") ||
	    strequal(name,"SRVSVC") ||
	    strequal(name,"WINREG") ||
	    strequal(name,"SAMR") ||
	    strequal(name,"LSARPC"))
	{
		DEBUG(4,("named pipe command from Win95 (wow!)\n"));
		return api_fd_reply(conn,vuid,outbuf,setup,data,params,suwcnt,tdscnt,tpscnt,mdrcnt,mprcnt);
	}

	if (strlen(name) < 1)
		return api_fd_reply(conn,vuid,outbuf,setup,data,params,suwcnt,tdscnt,tpscnt,mdrcnt,mprcnt);

	if (setup)
		DEBUG(3,("unknown named pipe: setup 0x%X setup1=%d\n", (int)setup[0],(int)setup[1]));

	return 0;
}


/****************************************************************************
 Reply to a SMBtrans.
 ****************************************************************************/

int reply_trans(connection_struct *conn, char *inbuf,char *outbuf, int size, int bufsize)
{
	fstring name;
	int name_offset = 0;
	char *data=NULL,*params=NULL;
	uint16 *setup=NULL;
	int outsize = 0;
	uint16 vuid = SVAL(inbuf,smb_uid);
	unsigned int tpscnt = SVAL(inbuf,smb_vwv0);
	unsigned int tdscnt = SVAL(inbuf,smb_vwv1);
	unsigned int mprcnt = SVAL(inbuf,smb_vwv2);
	unsigned int mdrcnt = SVAL(inbuf,smb_vwv3);
	unsigned int msrcnt = CVAL(inbuf,smb_vwv4);
	BOOL close_on_completion = BITSETW(inbuf+smb_vwv5,0);
	BOOL one_way = BITSETW(inbuf+smb_vwv5,1);
	unsigned int pscnt = SVAL(inbuf,smb_vwv9);
	unsigned int psoff = SVAL(inbuf,smb_vwv10);
	unsigned int dscnt = SVAL(inbuf,smb_vwv11);
	unsigned int dsoff = SVAL(inbuf,smb_vwv12);
	unsigned int suwcnt = CVAL(inbuf,smb_vwv13);
	START_PROFILE(SMBtrans);

	memset(name, '\0',sizeof(name));
	fstrcpy(name,smb_buf(inbuf));

	if (dscnt > tdscnt || pscnt > tpscnt)
		goto bad_param;
  
	if (tdscnt)  {
		if((data = (char *)malloc(tdscnt)) == NULL) {
			DEBUG(0,("reply_trans: data malloc fail for %u bytes !\n", tdscnt));
			END_PROFILE(SMBtrans);
			return(ERROR_DOS(ERRDOS,ERRnomem));
		} 
		if ((dsoff+dscnt < dsoff) || (dsoff+dscnt < dscnt))
			goto bad_param;
		if (smb_base(inbuf)+dsoff+dscnt > inbuf + size)
			goto bad_param;

		memcpy(data,smb_base(inbuf)+dsoff,dscnt);
	}

	if (tpscnt) {
		if((params = (char *)malloc(tpscnt)) == NULL) {
			DEBUG(0,("reply_trans: param malloc fail for %u bytes !\n", tpscnt));
			SAFE_FREE(data);
			END_PROFILE(SMBtrans);
			return(ERROR_DOS(ERRDOS,ERRnomem));
		} 
		if ((psoff+pscnt < psoff) || (psoff+pscnt < pscnt))
			goto bad_param;
		if (smb_base(inbuf)+psoff+pscnt > inbuf + size)
			goto bad_param;

		memcpy(params,smb_base(inbuf)+psoff,pscnt);
	}

	if (suwcnt) {
		int i;
		if((setup = (uint16 *)malloc(suwcnt*sizeof(uint16))) == NULL) {
			DEBUG(0,("reply_trans: setup malloc fail for %u bytes !\n", (unsigned int)(suwcnt * sizeof(uint16))));
			SAFE_FREE(data);
			SAFE_FREE(params);
			END_PROFILE(SMBtrans);
			return(ERROR_DOS(ERRDOS,ERRnomem));
		} 
		if (inbuf+smb_vwv14+(suwcnt*SIZEOFWORD) > inbuf + size)
			goto bad_param;
		if ((smb_vwv14+(suwcnt*SIZEOFWORD) < smb_vwv14) || (smb_vwv14+(suwcnt*SIZEOFWORD) < (suwcnt*SIZEOFWORD)))
			goto bad_param;

		for (i=0;i<suwcnt;i++)
			setup[i] = SVAL(inbuf,smb_vwv14+i*SIZEOFWORD);
	}


	if (pscnt < tpscnt || dscnt < tdscnt) {
		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		outsize = set_message(outbuf,0,0,True);
		show_msg(outbuf);
		if (!send_smb(smbd_server_fd(),outbuf))
			exit_server("reply_trans: send_smb failed.");
	}

	/* receive the rest of the trans packet */
	while (pscnt < tpscnt || dscnt < tdscnt) {
		BOOL ret;
		unsigned int pcnt,poff,dcnt,doff,pdisp,ddisp;
      
		ret = receive_next_smb(inbuf,bufsize,SMB_SECONDARY_WAIT);

		if ((ret && (CVAL(inbuf, smb_com) != SMBtranss)) || !ret) {
			if(ret) {
				DEBUG(0,("reply_trans: Invalid secondary trans packet\n"));
			} else {
				DEBUG(0,("reply_trans: %s in getting secondary trans response.\n",
					 (smb_read_error == READ_ERROR) ? "error" : "timeout" ));
			}
			SAFE_FREE(params);
			SAFE_FREE(data);
			SAFE_FREE(setup);
			END_PROFILE(SMBtrans);
			return(ERROR_DOS(ERRSRV,ERRerror));
		}

		show_msg(inbuf);
      
		/* Revise total_params and total_data in case they have changed downwards */
		if (SVAL(inbuf,smb_vwv0) < tpscnt)
			tpscnt = SVAL(inbuf,smb_vwv0);
		if (SVAL(inbuf,smb_vwv1) < tdscnt)
			tdscnt = SVAL(inbuf,smb_vwv1);

		pcnt = SVAL(inbuf,smb_vwv2);
		poff = SVAL(inbuf,smb_vwv3);
		pdisp = SVAL(inbuf,smb_vwv4);
		
		dcnt = SVAL(inbuf,smb_vwv5);
		doff = SVAL(inbuf,smb_vwv6);
		ddisp = SVAL(inbuf,smb_vwv7);
		
		pscnt += pcnt;
		dscnt += dcnt;
		
		if (dscnt > tdscnt || pscnt > tpscnt)
			goto bad_param;
		
		if (pcnt) {
			if (pdisp+pcnt >= tpscnt)
				goto bad_param;
			if ((pdisp+pcnt < pdisp) || (pdisp+pcnt < pcnt))
				goto bad_param;
			if (smb_base(inbuf) + poff + pcnt >= inbuf + bufsize)
				goto bad_param;
			if (params + pdisp < params)
				goto bad_param;

			memcpy(params+pdisp,smb_base(inbuf)+poff,pcnt);
		}

		if (dcnt) {
			if (ddisp+dcnt >= tdscnt)
				goto bad_param;
			if ((ddisp+dcnt < ddisp) || (ddisp+dcnt < dcnt))
				goto bad_param;
			if (smb_base(inbuf) + doff + dcnt >= inbuf + bufsize)
				goto bad_param;
			if (data + ddisp < data)
				goto bad_param;

			memcpy(data+ddisp,smb_base(inbuf)+doff,dcnt);      
		}
	}
	
	
	DEBUG(3,("trans <%s> data=%u params=%u setup=%u\n",
		 name,tdscnt,tpscnt,suwcnt));
	
	/*
	 * WinCE wierdness....
	 */

	if (name[0] == '\\' && (StrnCaseCmp(&name[1],local_machine, strlen(local_machine)) == 0) &&
			(name[strlen(local_machine)+1] == '\\'))
		name_offset = strlen(local_machine)+1;

	if (strnequal(&name[name_offset], "\\PIPE", strlen("\\PIPE"))) {
		name_offset += strlen("\\PIPE");

		/* Win9x weirdness.  When talking to a unicode server Win9x
		   only sends \PIPE instead of \PIPE\ */

		if (name[name_offset] == '\\')
			name_offset++;

		DEBUG(5,("calling named_pipe\n"));
		outsize = named_pipe(conn,vuid,outbuf,
				     name+name_offset,setup,data,params,
				     suwcnt,tdscnt,tpscnt,msrcnt,mdrcnt,mprcnt);
	} else {
		DEBUG(3,("invalid pipe name\n"));
		outsize = 0;
	}

	
	SAFE_FREE(data);
	SAFE_FREE(params);
	SAFE_FREE(setup);
	
	if (close_on_completion)
		close_cnum(conn,vuid);

	if (one_way) {
		END_PROFILE(SMBtrans);
		return(-1);
	}
	
	if (outsize == 0) {
		END_PROFILE(SMBtrans);
		return(ERROR_DOS(ERRSRV,ERRnosupport));
	}
	
	END_PROFILE(SMBtrans);
	return(outsize);


  bad_param:

	DEBUG(0,("reply_trans: invalid trans parameters\n"));
	SAFE_FREE(data);
	SAFE_FREE(params);
	SAFE_FREE(setup);
	END_PROFILE(SMBtrans);
	return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
}
