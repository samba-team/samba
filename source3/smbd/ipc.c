/* 
   Unix SMB/CIFS implementation.
   Inter-process communication and named pipe handling
   Copyright (C) Andrew Tridgell 1992-1998

   SMB Version handling
   Copyright (C) John H Terpstra 1995-1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
   */
/*
   This file handles the named pipe and mailslot calls
   in the SMBtrans protocol
   */

#include "includes.h"

extern int max_send;

#define NERR_notsupported 50

extern int smb_read_error;

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

void send_trans_reply(const char *inbuf,
			char *outbuf,
			char *rparam,
			int rparam_len,
			char *rdata,
			int rdata_len,
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

	if (buffer_too_large) {
		ERROR_BOTH(STATUS_BUFFER_OVERFLOW,ERRDOS,ERRmoredata);
	}

	set_message(inbuf,outbuf,10,1+align+this_ldata+this_lparam,True);

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
		exit_server_cleanly("send_trans_reply: send_smb failed.");

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

		set_message(inbuf,outbuf,10,1+this_ldata+this_lparam+align,False);

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
			exit_server_cleanly("send_trans_reply: send_smb failed.");

		tot_data_sent  += this_ldata;
		tot_param_sent += this_lparam;
	}
}

/****************************************************************************
 Start the first part of an RPC reply which began with an SMBtrans request.
****************************************************************************/

static BOOL api_rpc_trans_reply(const char *inbuf,
				char *outbuf,
				smb_np_struct *p)
{
	BOOL is_data_outstanding;
	char *rdata = (char *)SMB_MALLOC(p->max_trans_reply);
	int data_len;

	if(rdata == NULL) {
		DEBUG(0,("api_rpc_trans_reply: malloc fail.\n"));
		return False;
	}

	if((data_len = read_from_pipe( p, rdata, p->max_trans_reply,
					&is_data_outstanding)) < 0) {
		SAFE_FREE(rdata);
		return False;
	}

	send_trans_reply(inbuf, outbuf, NULL, 0, rdata, data_len, is_data_outstanding);

	SAFE_FREE(rdata);
	return True;
}

/****************************************************************************
 WaitNamedPipeHandleState 
****************************************************************************/

static BOOL api_WNPHS(const char *inbuf,
			char *outbuf,
			smb_np_struct *p,
			char *param,
			int param_len)
{
	uint16 priority;

	if (!param || param_len < 2)
		return False;

	priority = SVAL(param,0);
	DEBUG(4,("WaitNamedPipeHandleState priority %x\n", priority));

	if (wait_rpc_pipe_hnd_state(p, priority)) {
		/* now send the reply */
		send_trans_reply(inbuf, outbuf, NULL, 0, NULL, 0, False);
		return True;
	}
	return False;
}


/****************************************************************************
 SetNamedPipeHandleState 
****************************************************************************/

static BOOL api_SNPHS(const char *inbuf,
			char *outbuf,
			smb_np_struct *p,
			char *param,
			int param_len)
{
	uint16 id;

	if (!param || param_len < 2)
		return False;

	id = SVAL(param,0);
	DEBUG(4,("SetNamedPipeHandleState to code %x\n", id));

	if (set_rpc_pipe_hnd_state(p, id)) {
		/* now send the reply */
		send_trans_reply(inbuf, outbuf, NULL, 0, NULL, 0, False);
		return True;
	}
	return False;
}


/****************************************************************************
 When no reply is generated, indicate unsupported.
 ****************************************************************************/

static BOOL api_no_reply(const char *inbuf, char *outbuf, int max_rdata_len)
{
	char rparam[4];

	/* unsupported */
	SSVAL(rparam,0,NERR_notsupported);
	SSVAL(rparam,2,0); /* converter word */

	DEBUG(3,("Unsupported API fd command\n"));

	/* now send the reply */
	send_trans_reply(inbuf, outbuf, rparam, 4, NULL, 0, False);

	return -1;
}

/****************************************************************************
 Handle remote api calls delivered to a named pipe already opened.
 ****************************************************************************/

static int api_fd_reply(connection_struct *conn,
			uint16 vuid,
			const char *inbuf,
			char *outbuf,
			uint16 *setup,
			char *data,
			char *params,
		 	int suwcnt,
			int tdscnt,
			int tpscnt,
			int mdrcnt,
			int mprcnt)
{
	BOOL reply = False;
	smb_np_struct *p = NULL;
	int pnum;
	int subcommand;

	DEBUG(5,("api_fd_reply\n"));

	/* First find out the name of this file. */
	if (suwcnt != 2) {
		DEBUG(0,("Unexpected named pipe transaction.\n"));
		return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	/* Get the file handle and hence the file name. */
	/* 
	 * NB. The setup array has already been transformed
	 * via SVAL and so is in gost byte order.
	 */
	pnum = ((int)setup[1]) & 0xFFFF;
	subcommand = ((int)setup[0]) & 0xFFFF;

	if(!(p = get_rpc_pipe(pnum))) {
		if (subcommand == TRANSACT_WAITNAMEDPIPEHANDLESTATE) {
			/* Win9x does this call with a unicode pipe name, not a pnum. */
			/* Just return success for now... */
			DEBUG(3,("Got TRANSACT_WAITNAMEDPIPEHANDLESTATE on text pipe name\n"));
			send_trans_reply(inbuf, outbuf, NULL, 0, NULL, 0, False);
			return -1;
		}

		DEBUG(1,("api_fd_reply: INVALID PIPE HANDLE: %x\n", pnum));
		return ERROR_NT(NT_STATUS_INVALID_HANDLE);
	}

	if (vuid != p->vuid) {
		DEBUG(1, ("Got pipe request (pnum %x) using invalid VUID %d, "
			  "expected %d\n", pnum, vuid, p->vuid));
		return ERROR_NT(NT_STATUS_INVALID_HANDLE);
	}

	DEBUG(3,("Got API command 0x%x on pipe \"%s\" (pnum %x)\n", subcommand, p->name, pnum));

	/* record maximum data length that can be transmitted in an SMBtrans */
	p->max_trans_reply = mdrcnt;

	DEBUG(10,("api_fd_reply: p:%p max_trans_reply: %d\n", p, p->max_trans_reply));

	switch (subcommand) {
	case TRANSACT_DCERPCCMD:
		/* dce/rpc command */
		reply = write_to_pipe(p, data, tdscnt);
		if (reply)
			reply = api_rpc_trans_reply(inbuf, outbuf, p);
		break;
	case TRANSACT_WAITNAMEDPIPEHANDLESTATE:
		/* Wait Named Pipe Handle state */
		reply = api_WNPHS(inbuf, outbuf, p, params, tpscnt);
		break;
	case TRANSACT_SETNAMEDPIPEHANDLESTATE:
		/* Set Named Pipe Handle state */
		reply = api_SNPHS(inbuf, outbuf, p, params, tpscnt);
		break;
	default:
		return ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	if (!reply)
		return api_no_reply(inbuf, outbuf, mdrcnt);

	return -1;
}

/****************************************************************************
 Handle named pipe commands.
****************************************************************************/

static int named_pipe(connection_struct *conn,
			uint16 vuid,
			const char *inbuf,
			char *outbuf,
			char *name,
			uint16 *setup,
			char *data,
			char *params,
			int suwcnt,
			int tdscnt,
			int tpscnt,
			int msrcnt,
			int mdrcnt,
			int mprcnt)
{
	DEBUG(3,("named pipe command on <%s> name\n", name));

	if (strequal(name,"LANMAN")) {
		return api_reply(conn,
				vuid,
				inbuf,
				outbuf,
				data,
				params,
				tdscnt,
				tpscnt,
				mdrcnt,
				mprcnt);
	}

	if (strequal(name,"WKSSVC") ||
	    strequal(name,"SRVSVC") ||
	    strequal(name,"WINREG") ||
	    strequal(name,"SAMR") ||
	    strequal(name,"LSARPC")) {
		DEBUG(4,("named pipe command from Win95 (wow!)\n"));
		return api_fd_reply(conn,
					vuid,
					inbuf,
					outbuf,
					setup,
					data,
					params,
					suwcnt,
					tdscnt,
					tpscnt,
					mdrcnt,
					mprcnt);
	}

	if (strlen(name) < 1) {
		return api_fd_reply(conn,
					vuid,
					inbuf,
					outbuf,
					setup,
					data,
					params,
					suwcnt,
					tdscnt,
					tpscnt,
					mdrcnt,
					mprcnt);
	}

	if (setup)
		DEBUG(3,("unknown named pipe: setup 0x%X setup1=%d\n", (int)setup[0],(int)setup[1]));

	return 0;
}

static NTSTATUS handle_trans(connection_struct *conn,
				struct trans_state *state,
				const char *inbuf,
				char *outbuf,
				int *outsize)
{
	char *local_machine_name;
	int name_offset = 0;

	DEBUG(3,("trans <%s> data=%u params=%u setup=%u\n",
		 state->name,(unsigned int)state->total_data,(unsigned int)state->total_param,
		 (unsigned int)state->setup_count));

	/*
	 * WinCE wierdness....
	 */

	local_machine_name = talloc_asprintf(state, "\\%s\\",
					     get_local_machine_name());

	if (local_machine_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (strnequal(state->name, local_machine_name,
		      strlen(local_machine_name))) {
		name_offset = strlen(local_machine_name)-1;
	}

	if (!strnequal(&state->name[name_offset], "\\PIPE",
		       strlen("\\PIPE"))) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	
	name_offset += strlen("\\PIPE");

	/* Win9x weirdness.  When talking to a unicode server Win9x
	   only sends \PIPE instead of \PIPE\ */

	if (state->name[name_offset] == '\\')
		name_offset++;

	DEBUG(5,("calling named_pipe\n"));
	*outsize = named_pipe(conn,
				state->vuid,
				inbuf,
				outbuf,
				state->name+name_offset,
				state->setup,state->data,
				state->param,
				state->setup_count,state->total_data,
				state->total_param,
				state->max_setup_return,
				state->max_data_return,
				state->max_param_return);

	if (*outsize == 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (state->close_on_completion)
		close_cnum(conn,state->vuid);

	return NT_STATUS_OK;
}

/****************************************************************************
 Reply to a SMBtrans.
 ****************************************************************************/

void reply_trans(connection_struct *conn, struct smb_request *req)
{
	int outsize = 0;
	unsigned int dsoff;
	unsigned int dscnt;
	unsigned int psoff;
	unsigned int pscnt;
	struct trans_state *state;
	NTSTATUS result;
	char *inbuf, *outbuf;
	int size, bufsize;

	START_PROFILE(SMBtrans);

	if (SVAL(req->inbuf, smb_wct) < 10) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtrans);
		return;
	}

	size = smb_len(req->inbuf) + 4;
	dsoff = SVAL(req->inbuf, smb_dsoff);
	dscnt = SVAL(req->inbuf, smb_dscnt);
	psoff = SVAL(req->inbuf, smb_psoff);
	pscnt = SVAL(req->inbuf, smb_pscnt);

	result = allow_new_trans(conn->pending_trans, req->mid);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(2, ("Got invalid trans request: %s\n",
			  nt_errstr(result)));
		reply_nterror(req, result);
		END_PROFILE(SMBtrans);
		return;
	}

	if ((state = TALLOC_P(conn->mem_ctx, struct trans_state)) == NULL) {
		DEBUG(0, ("talloc failed\n"));
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBtrans);
		return;
	}

	state->cmd = SMBtrans;

	state->mid = req->mid;
	state->vuid = req->vuid;
	state->setup_count = CVAL(req->inbuf, smb_suwcnt);
	state->setup = NULL;
	state->total_param = SVAL(req->inbuf, smb_tpscnt);
	state->param = NULL;
	state->total_data = SVAL(req->inbuf, smb_tdscnt);
	state->data = NULL;
	state->max_param_return = SVAL(req->inbuf, smb_mprcnt);
	state->max_data_return = SVAL(req->inbuf, smb_mdrcnt);
	state->max_setup_return = CVAL(req->inbuf, smb_msrcnt);
	state->close_on_completion = BITSETW(req->inbuf+smb_vwv5,0);
	state->one_way = BITSETW(req->inbuf+smb_vwv5,1);

	memset(state->name, '\0',sizeof(state->name));
	srvstr_pull_buf(req->inbuf, req->flags2, state->name,
			smb_buf(req->inbuf), sizeof(state->name),
			STR_TERMINATE);
	
	if ((dscnt > state->total_data) || (pscnt > state->total_param))
		goto bad_param;

	if (state->total_data)  {
		/* Can't use talloc here, the core routines do realloc on the
		 * params and data. Out of paranoia, 100 bytes too many. */
		state->data = (char *)SMB_MALLOC(state->total_data+100);
		if (state->data == NULL) {
			DEBUG(0,("reply_trans: data malloc fail for %u "
				 "bytes !\n", (unsigned int)state->total_data));
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtrans);
			return;
		} 
		/* null-terminate the slack space */
		memset(&state->data[state->total_data], 0, 100);
		if ((dsoff+dscnt < dsoff) || (dsoff+dscnt < dscnt))
			goto bad_param;
		if ((smb_base(req->inbuf)+dsoff+dscnt
		     > (char *)req->inbuf + size) ||
		    (smb_base(req->inbuf)+dsoff+dscnt < smb_base(req->inbuf)))
			goto bad_param;

		memcpy(state->data,smb_base(req->inbuf)+dsoff,dscnt);
	}

	if (state->total_param) {
		/* Can't use talloc here, the core routines do realloc on the
		 * params and data. Out of paranoia, 100 bytes too many */
		state->param = (char *)SMB_MALLOC(state->total_param+100);
		if (state->param == NULL) {
			DEBUG(0,("reply_trans: param malloc fail for %u "
				 "bytes !\n", (unsigned int)state->total_param));
			SAFE_FREE(state->data);
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtrans);
			return;
		} 
		/* null-terminate the slack space */
		memset(&state->param[state->total_param], 0, 100);
		if ((psoff+pscnt < psoff) || (psoff+pscnt < pscnt))
			goto bad_param;
		if ((smb_base(req->inbuf)+psoff+pscnt
		     > (char *)req->inbuf + size) ||
		    (smb_base(req->inbuf)+psoff+pscnt < smb_base(req->inbuf)))
			goto bad_param;

		memcpy(state->param,smb_base(req->inbuf)+psoff,pscnt);
	}

	state->received_data  = dscnt;
	state->received_param = pscnt;

	if (state->setup_count) {
		unsigned int i;
		if((state->setup = TALLOC_ARRAY(
			    state, uint16, state->setup_count)) == NULL) {
			DEBUG(0,("reply_trans: setup malloc fail for %u "
				 "bytes !\n", (unsigned int)
				 (state->setup_count * sizeof(uint16))));
			SAFE_FREE(state->data);
			SAFE_FREE(state->param);
			TALLOC_FREE(state);
			reply_nterror(req, NT_STATUS_NO_MEMORY);
			END_PROFILE(SMBtrans);
			return;
		} 
		if (req->inbuf+smb_vwv14+(state->setup_count*SIZEOFWORD) >
		    req->inbuf + size)
			goto bad_param;
		if ((smb_vwv14+(state->setup_count*SIZEOFWORD) < smb_vwv14) ||
		    (smb_vwv14+(state->setup_count*SIZEOFWORD) <
		     (state->setup_count*SIZEOFWORD)))
			goto bad_param;

		for (i=0;i<state->setup_count;i++)
			state->setup[i] = SVAL(req->inbuf,
					       smb_vwv14+i*SIZEOFWORD);
	}

	state->received_param = pscnt;

	if ((state->received_param != state->total_param) ||
	    (state->received_data != state->total_data)) {
		DLIST_ADD(conn->pending_trans, state);

		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		reply_outbuf(req, 0, 0);
		show_msg((char *)req->outbuf);
		END_PROFILE(SMBtrans);
		return;
	}

	if (!(reply_prep_legacy(req, &inbuf, &outbuf, &size, &bufsize))) {
		SAFE_FREE(state->data);
		SAFE_FREE(state->param);
		TALLOC_FREE(state);
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBtrans);
		return;
	}

	result = handle_trans(conn, state, inbuf, outbuf, &outsize);

	if (NT_STATUS_IS_OK(result)) {
		reply_post_legacy(req, outsize);
	}

	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);

	if (!NT_STATUS_IS_OK(result)) {
		reply_nterror(req, result);
		END_PROFILE(SMBtrans);
		return;
	}

	if (outsize == 0) {
		reply_nterror(req, NT_STATUS_INTERNAL_ERROR);
		END_PROFILE(SMBtrans);
		return;
	}

	END_PROFILE(SMBtrans);
	return;

  bad_param:

	DEBUG(0,("reply_trans: invalid trans parameters\n"));
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	END_PROFILE(SMBtrans);
	reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
	return;
}

/****************************************************************************
 Reply to a secondary SMBtrans.
 ****************************************************************************/

void reply_transs(connection_struct *conn, struct smb_request *req)
{
	int outsize = 0;
	unsigned int pcnt,poff,dcnt,doff,pdisp,ddisp;
	struct trans_state *state;
	NTSTATUS result;
	char *inbuf, *outbuf;
	int size, bufsize;

	START_PROFILE(SMBtranss);

	show_msg((char *)req->inbuf);

	if (req->wct < 10) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtranss);
		return;
	}

	for (state = conn->pending_trans; state != NULL;
	     state = state->next) {
		if (state->mid == req->mid) {
			break;
		}
	}

	if ((state == NULL) || (state->cmd != SMBtrans)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBtranss);
		return;
	}

	/* Revise total_params and total_data in case they have changed
	 * downwards */

	if (SVAL(req->inbuf, smb_vwv0) < state->total_param)
		state->total_param = SVAL(req->inbuf,smb_vwv0);
	if (SVAL(req->inbuf, smb_vwv1) < state->total_data)
		state->total_data = SVAL(req->inbuf,smb_vwv1);

	size = smb_len(req->inbuf) + 4;

	pcnt = SVAL(req->inbuf, smb_spscnt);
	poff = SVAL(req->inbuf, smb_spsoff);
	pdisp = SVAL(req->inbuf, smb_spsdisp);

	dcnt = SVAL(req->inbuf, smb_sdscnt);
	doff = SVAL(req->inbuf, smb_sdsoff);
	ddisp = SVAL(req->inbuf, smb_sdsdisp);

	state->received_param += pcnt;
	state->received_data += dcnt;
		
	if ((state->received_data > state->total_data) ||
	    (state->received_param > state->total_param))
		goto bad_param;
		
	if (pcnt) {
		if (pdisp+pcnt > state->total_param)
			goto bad_param;
		if ((pdisp+pcnt < pdisp) || (pdisp+pcnt < pcnt))
			goto bad_param;
		if (pdisp > state->total_param)
			goto bad_param;
		if ((smb_base(req->inbuf) + poff + pcnt
		     > (char *)req->inbuf + size) ||
		    (smb_base(req->inbuf) + poff + pcnt
		     < smb_base(req->inbuf)))
			goto bad_param;
		if (state->param + pdisp < state->param)
			goto bad_param;

		memcpy(state->param+pdisp,smb_base(req->inbuf)+poff,
		       pcnt);
	}

	if (dcnt) {
		if (ddisp+dcnt > state->total_data)
			goto bad_param;
		if ((ddisp+dcnt < ddisp) || (ddisp+dcnt < dcnt))
			goto bad_param;
		if (ddisp > state->total_data)
			goto bad_param;
		if ((smb_base(req->inbuf) + doff + dcnt
		     > (char *)inbuf + size) ||
		    (smb_base(req->inbuf) + doff + dcnt
		     < smb_base(req->inbuf)))
			goto bad_param;
		if (state->data + ddisp < state->data)
			goto bad_param;

		memcpy(state->data+ddisp, smb_base(req->inbuf)+doff,
		       dcnt);      
	}

	if ((state->received_param < state->total_param) ||
	    (state->received_data < state->total_data)) {
		END_PROFILE(SMBtranss);
		return;
	}

	if (!reply_prep_legacy(req, &inbuf, &outbuf, &size, &bufsize)) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBtranss);
		return;
	}

	/* construct_reply_common has done us the favor to pre-fill the
	 * command field with SMBtranss which is wrong :-)
	 */
	SCVAL(req->outbuf,smb_com,SMBtrans);

	result = handle_trans(conn, state, inbuf, outbuf, &outsize);

	if (NT_STATUS_IS_OK(result)) {
		reply_post_legacy(req, outsize);
	}

	DLIST_REMOVE(conn->pending_trans, state);
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);

	if ((outsize == 0) || !NT_STATUS_IS_OK(result)) {
		reply_doserror(req, ERRSRV, ERRnosupport);
		END_PROFILE(SMBtranss);
		return;
	}
	
	END_PROFILE(SMBtranss);
	return;

  bad_param:

	DEBUG(0,("reply_transs: invalid trans parameters\n"));
	DLIST_REMOVE(conn->pending_trans, state);
	SAFE_FREE(state->data);
	SAFE_FREE(state->param);
	TALLOC_FREE(state);
	reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
	END_PROFILE(SMBtranss);
	return;
}
