/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client transaction calls
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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

#define NO_SYSLOG

#include "includes.h"


/****************************************************************************
  send a SMB trans or trans2 request
  ****************************************************************************/
BOOL cli_send_trans(struct cli_state *cli, int trans, 
                           char *name, int pipe_name_len, 
                           int fid, int flags,
                           uint16 *setup, int lsetup, int msetup,
                           char *param, int lparam, int mparam,
                           char *data, int ldata, int mdata)
{
	int i;
	int this_ldata,this_lparam;
	int tot_data=0,tot_param=0;
	char *outdata,*outparam;
	char *p;

	this_lparam = MIN(lparam,cli->max_xmit - (500+lsetup*2)); /* hack */
	this_ldata = MIN(ldata,cli->max_xmit - (500+lsetup*2+this_lparam));

	memset(cli->outbuf, 0, smb_size);
	set_message(cli->outbuf,14+lsetup,0,True);
	CVAL(cli->outbuf,smb_com) = trans;
	SSVAL(cli->outbuf,smb_tid, cli->cnum);
	cli_setup_packet(cli);

	outparam = smb_buf(cli->outbuf)+(trans==SMBtrans ? pipe_name_len+1 : 3);
	outdata = outparam+this_lparam;

	/* primary request */
	SSVAL(cli->outbuf,smb_tpscnt,lparam);	/* tpscnt */
	SSVAL(cli->outbuf,smb_tdscnt,ldata);	/* tdscnt */
	SSVAL(cli->outbuf,smb_mprcnt,mparam);	/* mprcnt */
	SSVAL(cli->outbuf,smb_mdrcnt,mdata);	/* mdrcnt */
	SCVAL(cli->outbuf,smb_msrcnt,msetup);	/* msrcnt */
	SSVAL(cli->outbuf,smb_flags,flags);	/* flags */
	SIVAL(cli->outbuf,smb_timeout,0);		/* timeout */
	SSVAL(cli->outbuf,smb_pscnt,this_lparam);	/* pscnt */
	SSVAL(cli->outbuf,smb_psoff,smb_offset(outparam,cli->outbuf)); /* psoff */
	SSVAL(cli->outbuf,smb_dscnt,this_ldata);	/* dscnt */
	SSVAL(cli->outbuf,smb_dsoff,smb_offset(outdata,cli->outbuf)); /* dsoff */
	SCVAL(cli->outbuf,smb_suwcnt,lsetup);	/* suwcnt */
	for (i=0;i<lsetup;i++)		/* setup[] */
		SSVAL(cli->outbuf,smb_setup+i*2,setup[i]);
	p = smb_buf(cli->outbuf);
	if (trans==SMBtrans) {
		memcpy(p,name, pipe_name_len + 1);  /* name[] */
	} else {
		*p++ = 0;  /* put in a null smb_name */
		*p++ = 'D'; *p++ = ' ';	/* observed in OS/2 */
	}
	if (this_lparam)			/* param[] */
		memcpy(outparam,param,this_lparam);
	if (this_ldata)			/* data[] */
		memcpy(outdata,data,this_ldata);
	set_message(cli->outbuf,14+lsetup,		/* wcnt, bcc */
		    PTR_DIFF(outdata+this_ldata,smb_buf(cli->outbuf)),False);

	show_msg(cli->outbuf);
	cli_send_smb(cli);

	if (this_ldata < ldata || this_lparam < lparam) {
		/* receive interim response */
		if (!cli_receive_smb(cli) || 
		    CVAL(cli->inbuf,smb_rcls) != 0) {
			return(False);
		}      

		tot_data = this_ldata;
		tot_param = this_lparam;
		
		while (tot_data < ldata || tot_param < lparam)  {
			this_lparam = MIN(lparam-tot_param,cli->max_xmit - 500); /* hack */
			this_ldata = MIN(ldata-tot_data,cli->max_xmit - (500+this_lparam));

			set_message(cli->outbuf,trans==SMBtrans?8:9,0,True);
			CVAL(cli->outbuf,smb_com) = trans==SMBtrans ? SMBtranss : SMBtranss2;
			
			outparam = smb_buf(cli->outbuf);
			outdata = outparam+this_lparam;
			
			/* secondary request */
			SSVAL(cli->outbuf,smb_tpscnt,lparam);	/* tpscnt */
			SSVAL(cli->outbuf,smb_tdscnt,ldata);	/* tdscnt */
			SSVAL(cli->outbuf,smb_spscnt,this_lparam);	/* pscnt */
			SSVAL(cli->outbuf,smb_spsoff,smb_offset(outparam,cli->outbuf)); /* psoff */
			SSVAL(cli->outbuf,smb_spsdisp,tot_param);	/* psdisp */
			SSVAL(cli->outbuf,smb_sdscnt,this_ldata);	/* dscnt */
			SSVAL(cli->outbuf,smb_sdsoff,smb_offset(outdata,cli->outbuf)); /* dsoff */
			SSVAL(cli->outbuf,smb_sdsdisp,tot_data);	/* dsdisp */
			if (trans==SMBtrans2)
				SSVALS(cli->outbuf,smb_sfid,fid);		/* fid */
			if (this_lparam)			/* param[] */
				memcpy(outparam,param+tot_param,this_lparam);
			if (this_ldata)			/* data[] */
				memcpy(outdata,data+tot_data,this_ldata);
			set_message(cli->outbuf,trans==SMBtrans?8:9, /* wcnt, bcc */
				    PTR_DIFF(outdata+this_ldata,smb_buf(cli->outbuf)),False);
			
			show_msg(cli->outbuf);
			cli_send_smb(cli);
			
			tot_data += this_ldata;
			tot_param += this_lparam;
		}
	}

	return(True);
}


/****************************************************************************
  receive a SMB trans or trans2 response allocating the necessary memory
  ****************************************************************************/
BOOL cli_receive_trans(struct cli_state *cli,int trans,
                              char **param, int *param_len,
                              char **data, int *data_len)
{
	int total_data=0;
	int total_param=0;
	int this_data,this_param;
	
	*data_len = *param_len = 0;

	if (!cli_receive_smb(cli))
		return False;

	show_msg(cli->inbuf);
	
	/* sanity check */
	if (CVAL(cli->inbuf,smb_com) != trans) {
		DEBUG(0,("Expected %s response, got command 0x%02x\n",
			 trans==SMBtrans?"SMBtrans":"SMBtrans2", 
			 CVAL(cli->inbuf,smb_com)));
		return(False);
	}

	if (cli_error(cli, NULL, NULL))
	{
		return(False);
	}

	/* parse out the lengths */
	total_data = SVAL(cli->inbuf,smb_tdrcnt);
	total_param = SVAL(cli->inbuf,smb_tprcnt);

	/* allocate it */
	*data = Realloc(*data,total_data);
	*param = Realloc(*param,total_param);

	while (1)  {
		this_data = SVAL(cli->inbuf,smb_drcnt);
		this_param = SVAL(cli->inbuf,smb_prcnt);

		if (this_data + *data_len > total_data ||
		    this_param + *param_len > total_param) {
			DEBUG(1,("Data overflow in cli_receive_trans\n"));
			return False;
		}

		if (this_data)
			memcpy(*data + SVAL(cli->inbuf,smb_drdisp),
			       smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_droff),
			       this_data);
		if (this_param)
			memcpy(*param + SVAL(cli->inbuf,smb_prdisp),
			       smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_proff),
			       this_param);
		*data_len += this_data;
		*param_len += this_param;

		/* parse out the total lengths again - they can shrink! */
		total_data = SVAL(cli->inbuf,smb_tdrcnt);
		total_param = SVAL(cli->inbuf,smb_tprcnt);
		
		if (total_data <= *data_len && total_param <= *param_len)
			break;
		
		if (!cli_receive_smb(cli))
			return False;

		show_msg(cli->inbuf);
		
		/* sanity check */
		if (CVAL(cli->inbuf,smb_com) != trans) {
			DEBUG(0,("Expected %s response, got command 0x%02x\n",
				 trans==SMBtrans?"SMBtrans":"SMBtrans2", 
				 CVAL(cli->inbuf,smb_com)));
			return(False);
		}

		if (cli_error(cli, NULL, NULL))
		{
			return(False);
		}
	}
	
	return(True);
}
