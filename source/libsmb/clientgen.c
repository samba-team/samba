/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1999
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
#include "nterr.h"
#include "trans2.h"

extern int DEBUGLEVEL;

static void cli_process_oplock(struct cli_state *cli);

/* 
 * Change the port number used to call on 
 */
int cli_set_port(struct cli_state *cli, int port)
{
	if (port > 0)
	  cli->port = port;

	return cli->port;
}

/****************************************************************************
recv an smb
****************************************************************************/
BOOL cli_receive_smb(struct cli_state *cli)
{
	BOOL ret;
 again:
	ret = client_receive_smb(cli->fd,cli->inbuf,cli->timeout);
	
	if (ret) {
		/* it might be an oplock break request */
		if (!(CVAL(cli->inbuf, smb_flg) & FLAG_REPLY) &&
		    CVAL(cli->inbuf,smb_com) == SMBlockingX &&
		    SVAL(cli->inbuf,smb_vwv6) == 0 &&
		    SVAL(cli->inbuf,smb_vwv7) == 0) {
			if (cli->use_oplocks) cli_process_oplock(cli);
			/* try to prevent loops */
			CVAL(cli->inbuf,smb_com) = 0xFF;
			goto again;
		}
	}

	return ret;
}

/****************************************************************************
  send an smb to a fd and re-establish if necessary
****************************************************************************/
BOOL cli_send_smb(struct cli_state *cli)
{
	size_t len;
	size_t nwritten=0;
	ssize_t ret;
	BOOL reestablished=False;

	len = smb_len(cli->outbuf) + 4;

	while (nwritten < len) {
		ret = write_socket(cli->fd,cli->outbuf+nwritten,len - nwritten);
		if (ret <= 0 && errno == EPIPE && !reestablished) {
			if (cli_reestablish_connection(cli)) {
				reestablished = True;
				nwritten=0;
				continue;
			}
		}
		if (ret <= 0) {
			DEBUG(0,("Error writing %d bytes to client. %d\n",
				 (int)len,(int)ret));
			return False;
		}
		nwritten += ret;
	}
	
	return True;
}

/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
void cli_setup_packet(struct cli_state *cli)
{
	uint16 flgs2 = 0;
	flgs2 |= FLAGS2_LONG_PATH_COMPONENTS;
	flgs2 |= FLAGS2_32_BIT_ERROR_CODES;
	flgs2 |= FLAGS2_EXT_SEC;
#if 0
	flgs2 |= FLAGS2_UNICODE_STRINGS;
#endif

        cli->rap_error = 0;
        cli->nt_error = 0;
	SSVAL(cli->outbuf,smb_pid,cli->pid);
	SSVAL(cli->outbuf,smb_uid,cli->vuid);
	SSVAL(cli->outbuf,smb_mid,cli->mid);

	if (cli->protocol > PROTOCOL_CORE)
	{
		SCVAL(cli->outbuf,smb_flg,0x8);
		SSVAL(cli->outbuf,smb_flg2,flgs2);
	}
}

/****************************************************************************
process an oplock break request from the server
****************************************************************************/
static void cli_process_oplock(struct cli_state *cli)
{
	char *oldbuf = cli->outbuf;
	pstring buf;
	int fnum;

	fnum = SVAL(cli->inbuf,smb_vwv2);

	/* damn, we really need to keep a record of open files so we
	   can detect a oplock break and a close crossing on the
	   wire. for now this swallows the errors */
	if (fnum == 0) return;

	cli->outbuf = buf;

        memset(buf,'\0',smb_size);
        set_message(buf,8,0,True);

        CVAL(buf,smb_com) = SMBlockingX;
	SSVAL(buf,smb_tid, cli->cnum);
        cli_setup_packet(cli);
	SSVAL(buf,smb_vwv0,0xFF);
	SSVAL(buf,smb_vwv1,0);
	SSVAL(buf,smb_vwv2,fnum);
	SSVAL(buf,smb_vwv3,2); /* oplock break ack */
	SIVAL(buf,smb_vwv4,0); /* timoeut */
	SSVAL(buf,smb_vwv6,0); /* unlockcount */
	SSVAL(buf,smb_vwv7,0); /* lockcount */

        cli_send_smb(cli);	

	cli->outbuf = oldbuf;
}

/****************************************************************************
  return a description of an SMB error
****************************************************************************/
void cli_safe_smb_errstr(struct cli_state *cli, char *msg, size_t len)
{
	smb_safe_errstr(cli->inbuf, msg, len);
}

/****************************************************************************
  return a description of an SMB error
****************************************************************************/
void cli_safe_errstr(struct cli_state *cli, char *err_msg, size_t msglen)
{   
	uint8 errclass;
	uint32 errnum;

	/*  
	 * Errors are of three kinds - smb errors,
	 * dealt with by cli_smb_errstr, NT errors,
	 * whose code is in cli.nt_error, and rap
	 * errors, whose error code is in cli.rap_error.
	 */ 

	cli_error(cli, &errclass, &errnum);

	if (errclass != 0)
	{
		cli_safe_smb_errstr(cli, err_msg, msglen);
	}
	else if (cli->nt_error)
	{
		/*
		 * Was it an NT error ?
		 */

		(void)get_safe_nt_error_msg(cli->nt_error, err_msg, msglen);
	}
	else
	{
		/*
		 * Must have been a rap error.
		 */
		(void)get_safe_rap_errstr(cli->rap_error, err_msg, msglen);
	}
}

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
static BOOL cli_receive_trans(struct cli_state *cli,int trans,
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

/****************************************************************************
Call a remote api on an arbitrary pipe.  takes param, data and setup buffers.
****************************************************************************/
BOOL cli_api_pipe(struct cli_state *cli, char *pipe_name, int pipe_name_len,
                  uint16 *setup, uint32 setup_count, uint32 max_setup_count,
                  char *params, uint32 param_count, uint32 max_param_count,
                  char *data, uint32 data_count, uint32 max_data_count,
                  char **rparam, uint32 *rparam_count,
                  char **rdata, uint32 *rdata_count)
{
  if (pipe_name_len == 0)
    pipe_name_len = strlen(pipe_name);

  cli_send_trans(cli, SMBtrans, 
                 pipe_name, pipe_name_len,
                 0,0,                         /* fid, flags */
                 setup, setup_count, max_setup_count,
                 params, param_count, max_param_count,
                 data, data_count, max_data_count);

  return (cli_receive_trans(cli, SMBtrans, 
                            rparam, (int *)rparam_count,
                            rdata, (int *)rdata_count));
}

/****************************************************************************
call a remote api
****************************************************************************/
BOOL cli_api(struct cli_state *cli,
	     char *param, int prcnt, int mprcnt,
	     char *data, int drcnt, int mdrcnt,
	     char **rparam, int *rprcnt,
	     char **rdata, int *rdrcnt)
{
  cli_send_trans(cli,SMBtrans,
                 PIPE_LANMAN,strlen(PIPE_LANMAN), /* Name, length */
                 0,0,                             /* fid, flags */
                 NULL,0,0,                /* Setup, length, max */
                 param, prcnt, mprcnt,    /* Params, length, max */
                 data, drcnt, mdrcnt      /* Data, length, max */ 
                );

  return (cli_receive_trans(cli,SMBtrans,
                            rparam, rprcnt,
                            rdata, rdrcnt));
}


/****************************************************************************
perform a NetWkstaUserLogon
****************************************************************************/
BOOL cli_NetWkstaUserLogon(struct cli_state *cli,char *user, char *workstation)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt,rprcnt;
	pstring param;

	memset(param, 0, sizeof(param));
	
	/* send a SMBtrans command with api NetWkstaUserLogon */
	p = param;
	SSVAL(p,0,132); /* api number */
	p += 2;
	pstrcpy(p,"OOWb54WrLh");
	p = skip_string(p,1);
	pstrcpy(p,"WB21BWDWWDDDDDDDzzzD");
	p = skip_string(p,1);
	SSVAL(p,0,1);
	p += 2;
	pstrcpy(p,user);
	strupper(p);
	p += 21;
	p++;
	p += 15;
	p++; 
	pstrcpy(p, workstation); 
	strupper(p);
	p += 16;
	SSVAL(p, 0, CLI_BUFFER_SIZE);
	p += 2;
	SSVAL(p, 0, CLI_BUFFER_SIZE);
	p += 2;
	
	if (cli_api(cli, 
                    param, PTR_DIFF(p,param),1024,  /* param, length, max */
                    NULL, 0, CLI_BUFFER_SIZE,           /* data, length, max */
                    &rparam, &rprcnt,               /* return params, return size */
                    &rdata, &rdrcnt                 /* return data, return size */
                   )) {
		cli->rap_error = SVAL(rparam,0);
		p = rdata;
		
		if (cli->rap_error == 0) {
			DEBUG(4,("NetWkstaUserLogon success\n"));
			cli->privileges = SVAL(p, 24);
			fstrcpy(cli->eff_name,p+2);
		} else {
			DEBUG(1,("NetwkstaUserLogon gave error %d\n", cli->rap_error));
		}
	}
	
	if (rparam)
      free(rparam);
	if (rdata)
      free(rdata);
	return (cli->rap_error == 0);
}

/****************************************************************************
call a NetShareEnum - try and browse available connections on a host
****************************************************************************/
int cli_RNetShareEnum(struct cli_state *cli, void (*fn)(const char *, uint32, const char *))
{
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt,rprcnt;
  pstring param;
  int count = -1;

  /* now send a SMBtrans command with api RNetShareEnum */
  p = param;
  SSVAL(p,0,0); /* api number */
  p += 2;
  pstrcpy(p,"WrLeh");
  p = skip_string(p,1);
  pstrcpy(p,"B13BWz");
  p = skip_string(p,1);
  SSVAL(p,0,1);
  /*
   * Win2k needs a *smaller* buffer than 0xFFFF here -
   * it returns "out of server memory" with 0xFFFF !!! JRA.
   */
  SSVAL(p,2,0xFFE0);
  p += 4;

  if (cli_api(cli, 
              param, PTR_DIFF(p,param), 1024,  /* Param, length, maxlen */
              NULL, 0, 0xFFE0,            /* data, length, maxlen - Win2k needs a small buffer here too ! */
              &rparam, &rprcnt,                /* return params, length */
              &rdata, &rdrcnt))                /* return data, length */
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);
      int i;
      
      if (res == 0 || res == ERRmoredata) {
	      count=SVAL(rparam,4);
	      p = rdata;

	      for (i=0;i<count;i++,p+=20) {
		      char *sname = p;
		      int type = SVAL(p,14);
		      int comment_offset = IVAL(p,16) & 0xFFFF;
		      char *cmnt = comment_offset?(rdata+comment_offset-converter):"";
			  dos_to_unix(sname,True);
			  dos_to_unix(cmnt,True);
		      fn(sname, type, cmnt);
	      }
      } else {
	      DEBUG(4,("NetShareEnum res=%d\n", res));
      }      
    } else {
	      DEBUG(4,("NetShareEnum failed\n"));
    }
  
  if (rparam)
    free(rparam);
  if (rdata)
    free(rdata);

  return count;
}


/****************************************************************************
call a NetServerEnum for the specified workgroup and servertype mask.
This function then calls the specified callback function for each name returned.

The callback function takes 3 arguments: the machine name, the server type and
the comment.
****************************************************************************/
BOOL cli_NetServerEnum(struct cli_state *cli, char *workgroup, uint32 stype,
		       void (*fn)(const char *, uint32, const char *))
{
	char *rparam = NULL;
	char *rdata = NULL;
	int rdrcnt,rprcnt;
	char *p;
	pstring param;
	int uLevel = 1;
	int count = -1;
  
	/* send a SMBtrans command with api NetServerEnum */
	p = param;
	SSVAL(p,0,0x68); /* api number */
	p += 2;
	pstrcpy(p,"WrLehDz");
	p = skip_string(p,1);
  
	pstrcpy(p,"B16BBDz");
  
	p = skip_string(p,1);
	SSVAL(p,0,uLevel);
	SSVAL(p,2,CLI_BUFFER_SIZE);
	p += 4;
	SIVAL(p,0,stype);
	p += 4;
	
	pstrcpy(p, workgroup);
	p = skip_string(p,1);
	
	if (cli_api(cli, 
                    param, PTR_DIFF(p,param), 8,        /* params, length, max */
                    NULL, 0, CLI_BUFFER_SIZE,               /* data, length, max */
                    &rparam, &rprcnt,                   /* return params, return size */
                    &rdata, &rdrcnt                     /* return data, return size */
                   )) {
		int res = -1;
		int converter = 0;
		int i;
			
		if (rparam != NULL)
		{
			res = SVAL(rparam,0);
			converter=SVAL(rparam,2);
		}

		if (res == 0 || res == ERRmoredata) {
			count=SVAL(rparam,4);
			p = rdata;
					
			for (i = 0;i < count;i++, p += 26) {
				char *sname = p;
				int comment_offset = (IVAL(p,22) & 0xFFFF)-converter;
				char *cmnt = comment_offset?(rdata+comment_offset):"";
				if (comment_offset < 0 || comment_offset > rdrcnt) continue;

				stype = IVAL(p,18) & ~SV_TYPE_LOCAL_LIST_ONLY;

				dos_to_unix(sname, True);
				dos_to_unix(cmnt, True);
				fn(sname, stype, cmnt);
			}
		}
	}
  
	if (rparam)
      free(rparam);
	if (rdata)
      free(rdata);
	
	return(count > 0);
}





/****************************************************************************
open a file
****************************************************************************/
int cli_nt_create(struct cli_state *cli, const char *fname)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,24,1 + strlen(fname),True);

	CVAL(cli->outbuf,smb_com) = SMBntcreateX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SIVAL(cli->outbuf,smb_ntcreate_Flags, 0x06);
	SIVAL(cli->outbuf,smb_ntcreate_RootDirectoryFid, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_DesiredAccess, 0x2019f);
	SIVAL(cli->outbuf,smb_ntcreate_FileAttributes, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_ShareAccess, 0x03);
	SIVAL(cli->outbuf,smb_ntcreate_CreateDisposition, 0x01);
	SIVAL(cli->outbuf,smb_ntcreate_CreateOptions, 0x0);
	SIVAL(cli->outbuf,smb_ntcreate_ImpersonationLevel, 0x02);
	SSVAL(cli->outbuf,smb_ntcreate_NameLength, strlen(fname));

	p = smb_buf(cli->outbuf);
	pstrcpy(p,fname);
    unix_to_dos(p,True);
	p = skip_string(p,1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return -1;
	}

	return SVAL(cli->inbuf,smb_vwv2 + 1);
}


/****************************************************************************
open a file
****************************************************************************/
int cli_open(struct cli_state *cli, const char *fname,
				int flags, int share_mode)
{
	char *p;
	unsigned openfn=0;
	unsigned accessmode=0;

	/* you must open for RW not just write - otherwise getattrE doesn't
	   work! */
	if ((flags & O_ACCMODE) == O_WRONLY && strncmp(cli->dev, "LPT", 3)) {
		flags = (flags & ~O_ACCMODE) | O_RDWR;
	}

	if (flags & O_CREAT)
		openfn |= (1<<4);
	if (!(flags & O_EXCL)) {
		if (flags & O_TRUNC)
			openfn |= (1<<1);
		else
			openfn |= (1<<0);
	}

	accessmode = (share_mode<<4);

	if ((flags & O_ACCMODE) == O_RDWR) {
		accessmode |= 2;
	} else if ((flags & O_ACCMODE) == O_WRONLY) {
		accessmode |= 1;
	} 

#if defined(O_SYNC)
	if ((flags & O_SYNC) == O_SYNC) {
		accessmode |= (1<<14);
	}
#endif /* O_SYNC */

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,15,1 + strlen(fname),True);

	CVAL(cli->outbuf,smb_com) = SMBopenX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,0);  /* no additional info */
	SSVAL(cli->outbuf,smb_vwv3,accessmode);
	SSVAL(cli->outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
	SSVAL(cli->outbuf,smb_vwv5,0);
	SSVAL(cli->outbuf,smb_vwv8,openfn);
  
	if (cli->use_oplocks) {
		/* if using oplocks then ask for a batch oplock via
                   core and extended methods */
		CVAL(cli->outbuf,smb_flg) |= 
			FLAG_REQUEST_OPLOCK|FLAG_REQUEST_BATCH_OPLOCK;
		SSVAL(cli->outbuf,smb_vwv2,SVAL(cli->outbuf,smb_vwv2) | 6);
	}
  
	p = smb_buf(cli->outbuf);
	pstrcpy(p,fname);
	unix_to_dos(p,True);
	p = skip_string(p,1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return -1;
	}

	return SVAL(cli->inbuf,smb_vwv2);
}




/****************************************************************************
  close a file
****************************************************************************/
BOOL cli_close(struct cli_state *cli, int fnum)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,3,0,True);

	CVAL(cli->outbuf,smb_com) = SMBclose;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	SIVALS(cli->outbuf,smb_vwv1,-1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}


/****************************************************************************
  lock a file
****************************************************************************/
BOOL cli_lock(struct cli_state *cli, int fnum, 
	      uint32 offset, uint32 len, int timeout, enum brl_type lock_type)
{
	char *p;
        int saved_timeout = cli->timeout;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	set_message(cli->outbuf,8,10,True);

	CVAL(cli->outbuf,smb_com) = SMBlockingX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	CVAL(cli->outbuf,smb_vwv3) = (lock_type == READ_LOCK? 1 : 0);
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);
	cli_send_smb(cli);

        cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);

	if (!cli_receive_smb(cli)) {
                cli->timeout = saved_timeout;
		return False;
	}

	cli->timeout = saved_timeout;

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
  unlock a file
****************************************************************************/
BOOL cli_unlock(struct cli_state *cli, int fnum, uint32 offset, uint32 len)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,10,True);

	CVAL(cli->outbuf,smb_com) = SMBlockingX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	CVAL(cli->outbuf,smb_vwv3) = 0;
	SIVALS(cli->outbuf, smb_vwv4, 0);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}



/****************************************************************************
issue a single SMBread and don't wait for a reply
****************************************************************************/
static void cli_issue_read(struct cli_state *cli, int fnum, off_t offset, 
			   size_t size, int i)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,10,0,True);
		
	CVAL(cli->outbuf,smb_com) = SMBreadX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SIVAL(cli->outbuf,smb_vwv3,offset);
	SSVAL(cli->outbuf,smb_vwv5,size);
	SSVAL(cli->outbuf,smb_vwv6,size);
	SSVAL(cli->outbuf,smb_mid,cli->mid + i);

	cli_send_smb(cli);
}

/****************************************************************************
  read from a file
****************************************************************************/
size_t cli_read_one(struct cli_state *cli, int fnum, char *buf, off_t offset, size_t size)
{
	char *p;
	int size2;

	if (size == 0) return 0;

	if (buf == NULL)
	{
		DEBUG(1, ("cli_read_one: NULL buf\n"));
		return 0;
	}

	cli_issue_read(cli, fnum, offset, size, 0);

	if (!cli_receive_smb(cli))
	{
		return -1;
	}

	size2 = SVAL(cli->inbuf, smb_vwv5);

	if (cli_error(cli, NULL, NULL))
	{
		return -1;
	}

	if (size2 > size)
	{
		DEBUG(0,("server returned more than we wanted!\n"));
		exit(1);
	}

	p = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);
	memcpy(buf, p, size2);

	return size2;
}

/****************************************************************************
  read from a file
****************************************************************************/
size_t cli_read(struct cli_state *cli, int fnum, char *buf, off_t offset, size_t size, BOOL overlap)
{
	char *p;
	int total = -1;
	int issued=0;
	int received=0;
	int mpx = overlap ? MIN(MAX(cli->max_mux-1, 1), MAX_MAX_MUX_LIMIT) : 1;
	int block = (cli->max_xmit - (smb_size+32)) & ~2047;
	int mid;
	int blocks = (size + (block-1)) / block;

	if (size == 0) return 0;

	while (received < blocks)
	{
		int size2;

		while (issued - received < mpx && issued < blocks)
		{
			int size1 = MIN(block, size-issued*block);
			cli_issue_read(cli, fnum, offset+issued*block, size1, issued);
			issued++;
		}

		if (!cli_receive_smb(cli)) {
			return total;
		}

		received++;
		mid = SVAL(cli->inbuf, smb_mid) - cli->mid;
		size2 = SVAL(cli->inbuf, smb_vwv5);

		if (cli_error(cli, NULL, NULL))
		{
			blocks = MIN(blocks, mid-1);
			continue;
		}

		if (size2 <= 0) {
			blocks = MIN(blocks, mid-1);
			/* this distinguishes EOF from an error */
			total = MAX(total, 0);
			continue;
		}

		if (size2 > block)
		{
			DEBUG(0,("server returned more than we wanted!\n"));
			exit(1);
		}
		if (mid >= issued)
		{
			DEBUG(0,("invalid mid from server!\n"));
			exit(1);
		}
		p = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);

		memcpy(buf+mid*block, p, size2);

		total = MAX(total, mid*block + size2);
	}

	while (received < issued)
	{
		cli_receive_smb(cli);
		received++;
	}
	
	return total;
}


/****************************************************************************
issue a single SMBwrite and don't wait for a reply
****************************************************************************/
static void cli_issue_write(struct cli_state *cli, int fnum, off_t offset, uint16 mode, char *buf,
			    size_t size, size_t bytes_left, int i)
{
	char *p;

	if (cli->outbuf == NULL || cli->inbuf == NULL)
	{
		DEBUG(1, ("cli_issue_write: cli->(in|out)buf is NULL\n"));
		/* XXX how to indicate a failure? */
		return;
	}

	memset(cli->outbuf, 0, smb_size);
	memset(cli->inbuf, 0, smb_size);

	set_message(cli->outbuf,12,size,True);
	
	CVAL(cli->outbuf,smb_com) = SMBwriteX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	
	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);

	SIVAL(cli->outbuf,smb_vwv3,offset);
	SIVAL(cli->outbuf,smb_vwv5,IS_BITS_SET_SOME(mode, 0x000C) ? 0xFFFFFFFF : 0);
	SSVAL(cli->outbuf,smb_vwv7,mode);

	SSVAL(cli->outbuf,smb_vwv8,IS_BITS_SET_SOME(mode, 0x000C) ? bytes_left : 0);
	SSVAL(cli->outbuf,smb_vwv10,size);
	SSVAL(cli->outbuf,smb_vwv11,
	      smb_buf(cli->outbuf) - smb_base(cli->outbuf));
	
	p = smb_base(cli->outbuf) + SVAL(cli->outbuf,smb_vwv11);
	memcpy(p, buf, size);

	SSVAL(cli->outbuf,smb_mid,cli->mid + i);
	
	cli_send_smb(cli);
}

/****************************************************************************
  write to a file
  write_mode: 0x0001 disallow write cacheing
              0x0002 return bytes remaining
              0x0004 use raw named pipe protocol
              0x0008 start of message mode named pipe protocol
****************************************************************************/
ssize_t cli_write(struct cli_state *cli,
		  int fnum, uint16 write_mode,
		  char *buf, off_t offset, size_t size, size_t bytes_left)
{
	int total = -1;
	int issued=0;
	int received=0;
	int mpx = MAX(cli->max_mux-1, 1);
	int block = (cli->max_xmit - (smb_size+32)) & ~1023;
	int mid;
	int blocks = (size + (block-1)) / block;

	if (size == 0) return 0;

	while (received < blocks)
	{
		int size2;

		while (issued - received < mpx && issued < blocks)
		{
			int size1 = MIN(block, size-issued*block);
			cli_issue_write(cli, fnum, offset+issued*block,
			                write_mode,
			                buf + issued*block,
					size1, bytes_left, issued);
			issued++;
			bytes_left -= size1;
		}

		if (!cli_receive_smb(cli)) {
			return total;
		}

		received++;
		mid = SVAL(cli->inbuf, smb_mid) - cli->mid;
		size2 = SVAL(cli->inbuf, smb_vwv2);

		if (CVAL(cli->inbuf,smb_rcls) != 0) {
			blocks = MIN(blocks, mid-1);
			continue;
		}

		if (size2 <= 0) {
			blocks = MIN(blocks, mid-1);
			/* this distinguishes EOF from an error */
			total = MAX(total, 0);
			continue;
		}

		total += size2;

		total = MAX(total, mid*block + size2);
	}

	while (received < issued) {
		cli_receive_smb(cli);
		received++;
	}
	
	return total;
}


/****************************************************************************
do a SMBgetattrE call
****************************************************************************/
BOOL cli_getattrE(struct cli_state *cli, int fd, 
		  uint16 *attr, size_t *size, 
		  time_t *c_time, time_t *a_time, time_t *m_time)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,2,0,True);

	CVAL(cli->outbuf,smb_com) = SMBgetattrE;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fd);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	if (size) {
		*size = IVAL(cli->inbuf, smb_vwv6);
	}

	if (attr) {
		*attr = SVAL(cli->inbuf,smb_vwv10);
	}

	if (c_time) {
		*c_time = make_unix_date3(cli->inbuf+smb_vwv0);
	}

	if (a_time) {
		*a_time = make_unix_date3(cli->inbuf+smb_vwv2);
	}

	if (m_time) {
		*m_time = make_unix_date3(cli->inbuf+smb_vwv4);
	}

	return True;
}


/****************************************************************************
do a SMBgetatr call
****************************************************************************/
BOOL cli_getatr(struct cli_state *cli, char *fname, 
		uint16 *attr, size_t *size, time_t *t)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,0,strlen(fname)+2,True);

	CVAL(cli->outbuf,smb_com) = SMBgetatr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p = 4;
	pstrcpy(p+1, fname);
    unix_to_dos(p+1,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	if (size) {
		*size = IVAL(cli->inbuf, smb_vwv3);
	}

	if (t) {
		*t = make_unix_date3(cli->inbuf+smb_vwv1);
	}

	if (attr) {
		*attr = SVAL(cli->inbuf,smb_vwv0);
	}


	return True;
}


/****************************************************************************
do a SMBsetatr call
****************************************************************************/
BOOL cli_setatr(struct cli_state *cli, char *fname, uint16 attr, time_t t)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	set_message(cli->outbuf,8,strlen(fname)+4,True);

	CVAL(cli->outbuf,smb_com) = SMBsetatr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0, attr);
	put_dos_date3(cli->outbuf,smb_vwv1, t);

	p = smb_buf(cli->outbuf);
	*p = 4;
	pstrcpy(p+1, fname);
    unix_to_dos(p+1,True);
	p = skip_string(p,1);
	*p = 4;

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}
	
	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
send a qpathinfo call
****************************************************************************/
BOOL cli_qpathinfo(struct cli_state *cli, const char *fname, 
		   time_t *c_time, time_t *a_time, time_t *m_time, 
		   size_t *size, uint16 *mode)
{
	int data_len = 0;
	int param_len = 0;
	uint16 setup = TRANSACT2_QPATHINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;
	int count=8;
	BOOL ret;
	time_t (*date_fn)(void *);

	param_len = strlen(fname) + 7;

	memset(param, 0, param_len);
	SSVAL(param, 0, SMB_INFO_STANDARD);
	pstrcpy(&param[6], fname);
    unix_to_dos(&param[6],True);

	do {
		ret = (cli_send_trans(cli, SMBtrans2, 
				      NULL, 0,        /* Name, length */
				      -1, 0,          /* fid, flags */
				      &setup, 1, 0,   /* setup, length, max */
				      param, param_len, 10, /* param, length, max */
				      NULL, data_len, cli->max_xmit /* data, length, max */
				      ) &&
		       cli_receive_trans(cli, SMBtrans2, 
					 &rparam, &param_len,
					 &rdata, &data_len));
		if (!ret) {
			/* we need to work around a Win95 bug - sometimes
			   it gives ERRSRV/ERRerror temprarily */
			uint8 eclass;
			uint32 ecode;
			cli_error(cli, &eclass, &ecode);
			if (eclass != ERRSRV || ecode != ERRerror) break;
			msleep(100);
		}
	} while (count-- && ret==False);

	if (!ret || !rdata || data_len < 22) {
		return False;
	}

	if (cli->win95) {
		date_fn = make_unix_date;
	} else {
		date_fn = make_unix_date2;
	}

	if (c_time) {
		*c_time = date_fn(rdata+0);
	}
	if (a_time) {
		*a_time = date_fn(rdata+4);
	}
	if (m_time) {
		*m_time = date_fn(rdata+8);
	}
	if (size) {
		*size = IVAL(rdata, 12);
	}
	if (mode) {
		*mode = SVAL(rdata,l1_attrFile);
	}

	if (rdata) free(rdata);
	if (rparam) free(rparam);
	return True;
}

/****************************************************************************
send a qpathinfo call with the SMB_QUERY_FILE_ALL_INFO info level
****************************************************************************/
BOOL cli_qpathinfo2(struct cli_state *cli, const char *fname, 
		    time_t *c_time, time_t *a_time, time_t *m_time, 
		    time_t *w_time, size_t *size, uint16 *mode,
		    SMB_INO_T *ino)
{
	int data_len = 0;
	int param_len = 0;
	uint16 setup = TRANSACT2_QPATHINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;

	param_len = strlen(fname) + 7;

	memset(param, 0, param_len);
	SSVAL(param, 0, SMB_QUERY_FILE_ALL_INFO);
	pstrcpy(&param[6], fname);
    unix_to_dos(&param[6],True);

	if (!cli_send_trans(cli, SMBtrans2, 
                            NULL, 0,                      /* name, length */
                            -1, 0,                        /* fid, flags */
                            &setup, 1, 0,                 /* setup, length, max */
                            param, param_len, 10,         /* param, length, max */
                            NULL, data_len, cli->max_xmit /* data, length, max */
                           )) {
		return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                               &rparam, &param_len,
                               &rdata, &data_len)) {
		return False;
	}

	if (!rdata || data_len < 22) {
		return False;
	}

	if (c_time) {
		*c_time = interpret_long_date(rdata+0) - cli->serverzone;
	}
	if (a_time) {
		*a_time = interpret_long_date(rdata+8) - cli->serverzone;
	}
	if (m_time) {
		*m_time = interpret_long_date(rdata+16) - cli->serverzone;
	}
	if (w_time) {
		*w_time = interpret_long_date(rdata+24) - cli->serverzone;
	}
	if (mode) {
		*mode = SVAL(rdata, 32);
	}
	if (size) {
		*size = IVAL(rdata, 40);
	}
	if (ino) {
		*ino = IVAL(rdata, 64);
	}

	if (rdata) free(rdata);
	if (rparam) free(rparam);
	return True;
}


/****************************************************************************
send a qfileinfo call
****************************************************************************/
BOOL cli_qfileinfo(struct cli_state *cli, int fnum, 
		   uint16 *mode, size_t *size,
		   time_t *c_time, time_t *a_time, time_t *m_time, 
		   time_t *w_time, SMB_INO_T *ino)
{
	int data_len = 0;
	int param_len = 0;
	uint16 setup = TRANSACT2_QFILEINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;

	/* if its a win95 server then fail this - win95 totally screws it
	   up */
	if (cli->win95) return False;

	param_len = 4;

	memset(param, 0, param_len);
	SSVAL(param, 0, fnum);
	SSVAL(param, 2, SMB_QUERY_FILE_ALL_INFO);

	if (!cli_send_trans(cli, SMBtrans2, 
                            NULL, 0,                        /* name, length */
                            -1, 0,                          /* fid, flags */
                            &setup, 1, 0,                   /* setup, length, max */
                            param, param_len, 2,            /* param, length, max */
                            NULL, data_len, cli->max_xmit   /* data, length, max */
                           )) {
		return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                               &rparam, &param_len,
                               &rdata, &data_len)) {
		return False;
	}

	if (!rdata || data_len < 68) {
		return False;
	}

	if (c_time) {
		*c_time = interpret_long_date(rdata+0) - cli->serverzone;
	}
	if (a_time) {
		*a_time = interpret_long_date(rdata+8) - cli->serverzone;
	}
	if (m_time) {
		*m_time = interpret_long_date(rdata+16) - cli->serverzone;
	}
	if (w_time) {
		*w_time = interpret_long_date(rdata+24) - cli->serverzone;
	}
	if (mode) {
		*mode = SVAL(rdata, 32);
	}
	if (size) {
		*size = IVAL(rdata, 40);
	}
	if (ino) {
		*ino = IVAL(rdata, 64);
	}

	if (rdata) free(rdata);
	if (rparam) free(rparam);
	return True;
}


/****************************************************************************
interpret a long filename structure - this is mostly guesses at the moment
The length of the structure is returned
The structure of a long filename depends on the info level. 260 is used
by NT and 2 is used by OS/2
****************************************************************************/
static int interpret_long_filename(int level,char *p,file_info *finfo)
{
	extern file_info def_finfo;

	if (finfo)
		memcpy(finfo,&def_finfo,sizeof(*finfo));

	switch (level)
		{
		case 1: /* OS/2 understands this */
			if (finfo) {
				/* these dates are converted to GMT by make_unix_date */
				finfo->ctime = make_unix_date2(p+4);
				finfo->atime = make_unix_date2(p+8);
				finfo->mtime = make_unix_date2(p+12);
				finfo->size = IVAL(p,16);
				finfo->mode = CVAL(p,24);
				pstrcpy(finfo->name,p+27);
				dos_to_unix(finfo->name,True);
			}
			return(28 + CVAL(p,26));

		case 2: /* this is what OS/2 uses mostly */
			if (finfo) {
				/* these dates are converted to GMT by make_unix_date */
				finfo->ctime = make_unix_date2(p+4);
				finfo->atime = make_unix_date2(p+8);
				finfo->mtime = make_unix_date2(p+12);
				finfo->size = IVAL(p,16);
				finfo->mode = CVAL(p,24);
				pstrcpy(finfo->name,p+31);
				dos_to_unix(finfo->name,True);
			}
			return(32 + CVAL(p,30));

			/* levels 3 and 4 are untested */
		case 3:
			if (finfo) {
				/* these dates are probably like the other ones */
				finfo->ctime = make_unix_date2(p+8);
				finfo->atime = make_unix_date2(p+12);
				finfo->mtime = make_unix_date2(p+16);
				finfo->size = IVAL(p,20);
				finfo->mode = CVAL(p,28);
				pstrcpy(finfo->name,p+33);
				dos_to_unix(finfo->name,True);
			}
			return(SVAL(p,4)+4);
			
		case 4:
			if (finfo) {
				/* these dates are probably like the other ones */
				finfo->ctime = make_unix_date2(p+8);
				finfo->atime = make_unix_date2(p+12);
				finfo->mtime = make_unix_date2(p+16);
				finfo->size = IVAL(p,20);
				finfo->mode = CVAL(p,28);
				pstrcpy(finfo->name,p+37);
				dos_to_unix(finfo->name,True);
			}
			return(SVAL(p,4)+4);
			
		case 260: /* NT uses this, but also accepts 2 */
			if (finfo) {
				int ret = SVAL(p,0);
				int namelen;
				p += 4; /* next entry offset */
				p += 4; /* fileindex */
				
				/* these dates appear to arrive in a
				   weird way. It seems to be localtime
				   plus the serverzone given in the
				   initial connect. This is GMT when
				   DST is not in effect and one hour
				   from GMT otherwise. Can this really
				   be right??

				   I suppose this could be called
				   kludge-GMT. Is is the GMT you get
				   by using the current DST setting on
				   a different localtime. It will be
				   cheap to calculate, I suppose, as
				   no DST tables will be needed */

				finfo->ctime = interpret_long_date(p); p += 8;
				finfo->atime = interpret_long_date(p); p += 8;
				finfo->mtime = interpret_long_date(p); p += 8; p += 8;
				finfo->size = IVAL(p,0); p += 8;
				p += 8; /* alloc size */
				finfo->mode = CVAL(p,0); p += 4;
				namelen = IVAL(p,0); p += 4;
				p += 4; /* EA size */
				p += 2; /* short name len? */
				p += 24; /* short name? */	  
				StrnCpy(finfo->name,p,MIN(sizeof(finfo->name)-1,namelen));
				dos_to_unix(finfo->name,True);
				return(ret);
			}
			return(SVAL(p,0));
		}
	
	DEBUG(1,("Unknown long filename format %d\n",level));
	return(SVAL(p,0));
}


/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
int cli_list(struct cli_state *cli,const char *Mask,uint16 attribute, 
	     void (*fn)(file_info *, const char *))
{
	int max_matches = 512;
	/* NT uses 260, OS/2 uses 2. Both accept 1. */
	int info_level = cli->protocol<PROTOCOL_NT1?1:260; 
	char *p, *p2;
	pstring mask;
	file_info finfo;
	int i;
	char *dirlist = NULL;
	int dirlist_len = 0;
	int total_received = -1;
	BOOL First = True;
	int ff_searchcount=0;
	int ff_eos=0;
	int ff_lastname=0;
	int ff_dir_handle=0;
	int loop_count = 0;
	char *rparam=NULL, *rdata=NULL;
	int param_len, data_len;
	
	uint16 setup;
	pstring param;
	
	pstrcpy(mask,Mask);
	unix_to_dos(mask,True);
	
	while (ff_eos == 0) {
		loop_count++;
		if (loop_count > 200) {
			DEBUG(0,("Error: Looping in FIND_NEXT??\n"));
			break;
		}

		param_len = 12+strlen(mask)+1;

		if (First) {
			setup = TRANSACT2_FINDFIRST;
			SSVAL(param,0,attribute); /* attribute */
			SSVAL(param,2,max_matches); /* max count */
			SSVAL(param,4,4+2);	/* resume required + close on end */
			SSVAL(param,6,info_level); 
			SIVAL(param,8,0);
			pstrcpy(param+12,mask);
		} else {
			setup = TRANSACT2_FINDNEXT;
			SSVAL(param,0,ff_dir_handle);
			SSVAL(param,2,max_matches); /* max count */
			SSVAL(param,4,info_level); 
			SIVAL(param,6,0); /* ff_resume_key */
			SSVAL(param,10,8+4+2);	/* continue + resume required + close on end */
			pstrcpy(param+12,mask);

			DEBUG(5,("hand=0x%X ff_lastname=%d mask=%s\n",
				 ff_dir_handle,ff_lastname,mask));
		}

		if (!cli_send_trans(cli, SMBtrans2, 
				    NULL, 0,                /* Name, length */
				    -1, 0,                  /* fid, flags */
				    &setup, 1, 0,           /* setup, length, max */
				    param, param_len, 10,   /* param, length, max */
				    NULL, 0, 
				    cli->max_xmit /* data, length, max */
				    )) {
			break;
		}

		if (!cli_receive_trans(cli, SMBtrans2, 
				       &rparam, &param_len,
				       &rdata, &data_len)) {
			/* we need to work around a Win95 bug - sometimes
			   it gives ERRSRV/ERRerror temprarily */
			uint8 eclass;
			uint32 ecode;
			cli_error(cli, &eclass, &ecode);
			if (eclass != ERRSRV || ecode != ERRerror) break;
			msleep(100);
			continue;
		}

		if (total_received == -1) total_received = 0;

		/* parse out some important return info */
		p = rparam;
		if (First) {
			ff_dir_handle = SVAL(p,0);
			ff_searchcount = SVAL(p,2);
			ff_eos = SVAL(p,4);
			ff_lastname = SVAL(p,8);
		} else {
			ff_searchcount = SVAL(p,0);
			ff_eos = SVAL(p,2);
			ff_lastname = SVAL(p,6);
		}

		if (ff_searchcount == 0) 
			break;

		/* point to the data bytes */
		p = rdata;

		/* we might need the lastname for continuations */
		if (ff_lastname > 0) {
			switch(info_level)
				{
				case 260:
					StrnCpy(mask,p+ff_lastname,
						MIN(sizeof(mask)-1,data_len-ff_lastname));
					break;
				case 1:
					pstrcpy(mask,p + ff_lastname + 1);
					break;
				}
		} else {
			pstrcpy(mask,"");
		}
  
		dos_to_unix(mask, True);
 
		/* and add them to the dirlist pool */
		dirlist = Realloc(dirlist,dirlist_len + data_len);

		if (!dirlist) {
			DEBUG(0,("Failed to expand dirlist\n"));
			break;
		}

		/* put in a length for the last entry, to ensure we can chain entries 
		   into the next packet */
		for (p2=p,i=0;i<(ff_searchcount-1);i++)
			p2 += interpret_long_filename(info_level,p2,NULL);
		SSVAL(p2,0,data_len - PTR_DIFF(p2,p));

		/* grab the data for later use */
		memcpy(dirlist+dirlist_len,p,data_len);
		dirlist_len += data_len;

		total_received += ff_searchcount;

		if (rdata) free(rdata); rdata = NULL;
		if (rparam) free(rparam); rparam = NULL;
		
		DEBUG(3,("received %d entries (eos=%d)\n",
			 ff_searchcount,ff_eos));

		if (ff_searchcount > 0) loop_count = 0;

		First = False;
	}

	for (p=dirlist,i=0;i<total_received;i++) {
		p += interpret_long_filename(info_level,p,&finfo);
		fn(&finfo, Mask);
	}

	/* free up the dirlist buffer */
	if (dirlist) free(dirlist);
	return(total_received);
}


/****************************************************************************
Send a SamOEMChangePassword command
****************************************************************************/

BOOL cli_oem_change_password(struct cli_state *cli, const char *user, const char *new_password,
                             const char *old_password)
{
  char param[16+sizeof(fstring)];
  char data[532];
  char *p = param;
  fstring upper_case_old_pw;
  fstring upper_case_new_pw;
  unsigned char old_pw_hash[16];
  unsigned char new_pw_hash[16];
  int data_len;
  int param_len = 0;
  char *rparam = NULL;
  char *rdata = NULL;
  int rprcnt, rdrcnt;

  if (strlen(user) >= sizeof(fstring)-1) {
    DEBUG(0,("cli_oem_change_password: user name %s is too long.\n", user));
    return False;
  }

  SSVAL(p,0,214); /* SamOEMChangePassword command. */
  p += 2;
  pstrcpy(p, "zsT");
  p = skip_string(p,1);
  pstrcpy(p, "B516B16");
  p = skip_string(p,1);
  pstrcpy(p,user);
  p = skip_string(p,1);
  SSVAL(p,0,532);
  p += 2;

  param_len = PTR_DIFF(p,param);

  /*
   * Get the Lanman hash of the old password, we
   * use this as the key to make_oem_passwd_hash().
   */
  memset(upper_case_old_pw, '\0', sizeof(upper_case_old_pw));
  fstrcpy(upper_case_old_pw, old_password);
  strupper(upper_case_old_pw);
  E_P16((uchar *)upper_case_old_pw, old_pw_hash);

	if (!make_oem_passwd_hash( data, new_password, 0, old_pw_hash, False))
	{
		return False;
	}

  /* 
   * Now place the old password hash in the data.
   */
  memset(upper_case_new_pw, '\0', sizeof(upper_case_new_pw));
  fstrcpy(upper_case_new_pw, new_password);
  strupper(upper_case_new_pw);

  E_P16((uchar *)upper_case_new_pw, new_pw_hash);

  E_old_pw_hash( new_pw_hash, old_pw_hash, (uchar *)&data[516]);

  data_len = 532;
    
  if (!cli_send_trans(cli,SMBtrans,
                    PIPE_LANMAN,strlen(PIPE_LANMAN),      /* name, length */
                    0,0,                                  /* fid, flags */
                    NULL,0,0,                             /* setup, length, max */
                    param,param_len,2,                    /* param, length, max */
                    data,data_len,0                       /* data, length, max */
                   ))
  {
    DEBUG(0,("cli_oem_change_password: Failed to send password change for user %s\n",
              user ));
    return False;
  }

  if (cli_receive_trans(cli,SMBtrans,
                       &rparam, &rprcnt,
                       &rdata, &rdrcnt)) {
    if (rparam)
      cli->rap_error = SVAL(rparam,0);
  }

  if (rparam)
    free(rparam);
  if (rdata)
    free(rdata);

  return (cli->rap_error == 0);
}

/****************************************************************************
initialise a client structure
****************************************************************************/
void cli_init_creds(struct cli_state *cli, const struct ntuser_creds *usr)
{
	copy_nt_creds(&cli->usr, usr);
	cli->nt.ntlmssp_cli_flgs = usr != NULL ? usr->ntlmssp_flags : 0;
	DEBUG(10,("cli_init_creds: ntlmssp_flgs: %x\n", 
	           cli->nt.ntlmssp_cli_flgs));
}

/****************************************************************************
initialise a client structure
****************************************************************************/
struct cli_state *cli_initialise(struct cli_state *cli)
{
	if (!cli) {
		cli = (struct cli_state *)malloc(sizeof(*cli));
		if (!cli)
			return NULL;
		ZERO_STRUCTP(cli);
	}

	if (cli->initialised) {
		cli_shutdown(cli);
	}

	ZERO_STRUCTP(cli);

	cli->port = 0;
	cli->fd = -1;
	cli->cnum = -1;
	cli->pid = (uint16)sys_getpid();
	cli->mid = 1;
	cli->vuid = UID_FIELD_INVALID;
	cli->protocol = PROTOCOL_NT1;
	cli->timeout = 20000; /* Timeout is in milliseconds. */
	cli->bufsize = CLI_BUFFER_SIZE+4;
	cli->max_xmit = cli->bufsize;
	cli->outbuf = (char *)malloc(cli->bufsize);
	cli->inbuf = (char *)malloc(cli->bufsize);
	if (!cli->outbuf || !cli->inbuf)
	{
		return False;
	}

	cli->initialised = 1;
	cli->capabilities = CAP_DFS | CAP_NT_SMBS | CAP_STATUS32;
	cli->use_ntlmv2 = lp_client_ntlmv2();

	cli_init_creds(cli, NULL);

	return cli;
}

/****************************************************************************
close the socket descriptor
****************************************************************************/
void cli_close_socket(struct cli_state *cli)
{
#ifdef WITH_SSL
	if (cli->fd != -1)
	{
		sslutil_disconnect(cli->fd);
	}
#endif /* WITH_SSL */
	if (cli->fd != -1) 
	{
		close(cli->fd);
	}
	cli->fd = -1;
}

/****************************************************************************
shutdown a client structure
****************************************************************************/
void cli_shutdown(struct cli_state *cli)
{
	DEBUG(10,("cli_shutdown\n"));
	if (cli->outbuf)
	{
		free(cli->outbuf);
	}
	if (cli->inbuf)
	{
		free(cli->inbuf);
	}
	cli_close_socket(cli);
	memset(cli, 0, sizeof(*cli));
}


/****************************************************************************
set socket options on a open connection
****************************************************************************/
void cli_sockopt(struct cli_state *cli, char *options)
{
	set_socket_options(cli->fd, options);
}

/****************************************************************************
set the PID to use for smb messages. Return the old pid.
****************************************************************************/
uint16 cli_setpid(struct cli_state *cli, uint16 pid)
{
	uint16 ret = cli->pid;
	cli->pid = pid;
	return ret;
}

/****************************************************************************
check for existance of a dir
****************************************************************************/
BOOL cli_chkpath(struct cli_state *cli, char *path)
{
	pstring path2;
	char *p;
	
	safe_strcpy(path2,path,sizeof(pstring));
	trim_string(path2,NULL,"\\");
	if (!*path2) *path2 = '\\';
	
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,4 + strlen(path2),True);
	SCVAL(cli->outbuf,smb_com,SMBchkpth);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	p = smb_buf(cli->outbuf);
	*p++ = 4;
	safe_strcpy(p,path2,strlen(path2));
	unix_to_dos(p,True);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_error(cli, NULL, NULL)) return False;

	return True;
}


/****************************************************************************
query disk space
****************************************************************************/
BOOL cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail)
{
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,0,True);
	CVAL(cli->outbuf,smb_com) = SMBdskattr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	*bsize = SVAL(cli->inbuf,smb_vwv1)*SVAL(cli->inbuf,smb_vwv2);
	*total = SVAL(cli->inbuf,smb_vwv0);
	*avail = SVAL(cli->inbuf,smb_vwv3);
	
	return True;
}

