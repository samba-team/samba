/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1997
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

#define CNV_LANG(s) dos2unix_format(s,False)

extern file_info def_finfo;

extern int DEBUGLEVEL;

/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
static void cli_setup_packet(struct cli_state *cli)
{
	SSVAL(cli->outbuf,smb_pid,cli->pid);
	SSVAL(cli->outbuf,smb_uid,cli->uid);
	SSVAL(cli->outbuf,smb_mid,cli->mid);
	if (cli->protocol > PROTOCOL_CORE) {
		SCVAL(cli->outbuf,smb_flg,0x8);
		SSVAL(cli->outbuf,smb_flg2,0x1);
	}
}


/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
static void cli_set_smb_cmd(struct cli_state *cli, int t_idx,
				uint8 cmd, int num_wds, int num_bytes, BOOL zero)
{
	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf ,smb_size);

	set_message(cli->outbuf, num_wds, num_bytes, zero);

	CVAL(cli->outbuf,smb_com) = cmd;
	SSVAL(cli->outbuf, smb_tid, cli->con[t_idx].cnum);

	cli_setup_packet(cli);
}


/****************************************************************************
  send a SMB trans or trans2 request
  ****************************************************************************/
BOOL cli_send_trans(struct cli_state *cli, int t_idx,
			   int trans, char *name, int pipe_name_len,
               int fid, int flags,
			   char *data,char *param,uint16 *setup, int ldata,int lparam,
			   int lsetup,int mdata,int mparam,int msetup)
{
	int i;
	int this_ldata,this_lparam;
	int tot_data=0,tot_param=0;
	char *outdata,*outparam;
	char *p;

	this_lparam = MIN(lparam,cli->max_xmit - (500+lsetup*SIZEOFWORD)); /* hack */
	this_ldata = MIN(ldata,cli->max_xmit - (500+lsetup*SIZEOFWORD+this_lparam));

	cli_set_smb_cmd(cli, t_idx,  trans, 14+lsetup, 0, True);

	outparam = smb_buf(cli->outbuf)+(trans==SMBtrans ? (pipe_name_len+1) : 3);
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
		SSVAL(cli->outbuf,smb_setup+i*SIZEOFWORD,setup[i]);
	p = smb_buf(cli->outbuf);
	if (trans==SMBtrans) {
		memcpy(p,name, pipe_name_len + 1);			/* name[] */
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
	send_smb(cli->fd,cli->outbuf);

	if (this_ldata < ldata || this_lparam < lparam) {
		/* receive interim response */
		if (!receive_smb(cli->fd,cli->inbuf,cli->timeout) || 
		    cli_error(cli, NULL, NULL)) {
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
				SSVAL(cli->outbuf,smb_sfid,fid);		/* fid */
			if (this_lparam)			/* param[] */
				memcpy(outparam,param,this_lparam);
			if (this_ldata)			/* data[] */
				memcpy(outdata,data,this_ldata);
			set_message(cli->outbuf,trans==SMBtrans?8:9, /* wcnt, bcc */
				    PTR_DIFF(outdata+this_ldata,smb_buf(cli->outbuf)),False);
			
			show_msg(cli->outbuf);
			send_smb(cli->fd,cli->outbuf);
			
			tot_data += this_ldata;
			tot_param += this_lparam;
		}
	}

	return(True);
}


/****************************************************************************
  receive a SMB trans or trans2 response allocating the necessary memory
  ****************************************************************************/
BOOL cli_receive_trans(struct cli_state *cli, int t_idx,
			      int trans,int *data_len,
			      int *param_len, char **data,char **param)
{
	int total_data=0;
	int total_param=0;
	int this_data,this_param;
	
	*data_len = *param_len = 0;
	
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

	show_msg(cli->inbuf);
	
	/* sanity check */
	if (CVAL(cli->inbuf,smb_com) != trans) {
		DEBUG(0,("Expected %s response, got command 0x%02x\n",
			 trans==SMBtrans?"SMBtrans":"SMBtrans2", 
			 CVAL(cli->inbuf,smb_com)));
		return(False);
	}
	if (cli_error(cli, NULL, NULL)) return(False);

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
		
		if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
			return False;

		show_msg(cli->inbuf);
		
		/* sanity check */
		if (CVAL(cli->inbuf,smb_com) != trans) {
			DEBUG(0,("Expected %s response, got command 0x%02x\n",
				 trans==SMBtrans?"SMBtrans":"SMBtrans2", 
				 CVAL(cli->inbuf,smb_com)));
			return(False);
		}
		if (cli_error(cli, NULL, NULL)) return(False);
	}
	
	return(True);
}

#ifdef NTDOMAIN
/****************************************************************************
call a remote api on an arbitrary pipe.  takes param, data and setup buffers.

parameters:

  char *pipe_name, int pipe_name_len,       pipe name, length
  int prcnt,int drcnt, int srcnt,           param, data, setup sizes
  int mprcnt,int mdrcnt,                    max param, data return sizes
  int *rprcnt,int *rdrcnt,                  actual param, data return sizes
  char *param, char *data, uint16 *setup,   params, data, setup buffers
  char **rparam,char **rdata                return params, data buffers

****************************************************************************/
BOOL cli_api_pipe(struct cli_state *cli, int t_idx,
	char *pipe_name, int pipe_name_len,
	int prcnt,int drcnt, int srcnt,
	int mprcnt,int mdrcnt,
	int *rprcnt,int *rdrcnt,
	char *param, char *data, uint16 *setup,
	char **rparam,char **rdata)
{
  if (pipe_name_len == 0) pipe_name_len = strlen(pipe_name);

  cli_send_trans(cli, t_idx,  SMBtrans, pipe_name, pipe_name_len, 0,0,
		     data, param, setup,
		     drcnt, prcnt, srcnt,
		     mdrcnt, mprcnt, 0);

  return (cli_receive_trans(cli, t_idx, SMBtrans,
                                 rdrcnt,rprcnt,
                                 rdata,rparam));
}
#endif

/****************************************************************************
call a remote api on the LANMAN pipe.  only takes param and data buffers
****************************************************************************/
static BOOL cli_api(struct cli_state *cli, int t_idx,
		    int prcnt,int drcnt,int mprcnt,int mdrcnt,int *rprcnt,
		    int *rdrcnt, char *param,char *data, 
		    char **rparam, char **rdata)
{
#ifdef NTDOMAIN
	return cli_api_pipe(cli, t_idx,  "\\PIPE\\LANMAN", 0,
				prcnt, drcnt, 0,
				mprcnt, mdrcnt,
				rprcnt, rdrcnt,
				param, data, NULL,
				rparam, rdata);
#else
  cli_send_trans(cli, t_idx, SMBtrans,"\\PIPE\\LANMAN",0,0,0,
		 data,param,NULL,
		 drcnt,prcnt,0,
		 mdrcnt,mprcnt,0);

  return (cli_receive_trans(cli, t_idx, SMBtrans,
				     rdrcnt,rprcnt,
				     rdata,rparam));
#endif
}


/****************************************************************************
perform a NetWkstaUserLogon
****************************************************************************/
BOOL cli_NetWkstaUserLogon(struct cli_state *cli, int t_idx,char *user, char *workstation)
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
	strcpy(p,"OOWb54WrLh");
	p = skip_string(p,1);
	strcpy(p,"WB21BWDWWDDDDDDDzzzD");
	p = skip_string(p,1);
	SSVAL(p,0,1);
	p += 2;
	strcpy(p,user);
	strupper(p);
	p += 21; p++; p += 15; p++; 
	strcpy(p, workstation); 
	strupper(p);
	p += 16;
	SSVAL(p, 0, BUFFER_SIZE);
	p += 2;
	SSVAL(p, 0, BUFFER_SIZE);
	p += 2;
	
	cli->error = -1;
	
	if (cli_api(cli, t_idx,  PTR_DIFF(p,param),0,
		    1024,BUFFER_SIZE,
		    &rprcnt,&rdrcnt,
		    param,NULL,
		    &rparam,&rdata)) {
		cli->error = SVAL(rparam,0);
		p = rdata;
		
		if (cli->error == 0) {
			DEBUG(4,("NetWkstaUserLogon success\n"));
			cli->privileges = SVAL(p, 24);
			fstrcpy(cli->eff_name,p+2);
		} else {
			DEBUG(1,("NetwkstaUserLogon gave error %d\n", cli->error));
		}
	}
	
	if (rparam) free(rparam);
	if (rdata) free(rdata);
	return cli->error == 0;
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
BOOL cli_NetShareEnum(struct cli_state *cli, int t_idx, BOOL sort, BOOL *long_share_name,
		       void (*fn)(char *, uint32, char *))
{
#ifdef NOSTRCASECMP
/* If strcasecmp is already defined, remove it. */
#ifdef strcasecmp
#undef strcasecmp
#endif /* strcasecmp */
#define strcasecmp StrCaseCmp
#endif /* NOSTRCASECMP */

	extern int strcasecmp();

	char *resp_param = NULL;
	char *resp_data  = NULL;
	char *p;
	int resp_data_len, resp_param_len;
	pstring param;
	int count = -1;

	/* now send a SMBtrans command with api RNetShareEnum */
	p = param;
	SSVAL(p,0,0); /* api number */
	p += 2;
	strcpy(p,"WrLeh");
	p = skip_string(p,1);
	strcpy(p,"B13BWz");
	p = skip_string(p,1);
	SSVAL(p,0,1);
	SSVAL(p,2,BUFFER_SIZE);
	p += 4;

	if (cli_api(cli, t_idx,  
		    PTR_DIFF(p,param), /* param count */
		    0, /*data count */
		    10, /* mprcount */
		    BUFFER_SIZE, /* mdrcount */
	        &resp_data_len, &resp_param_len,
		    param, NULL, 
	        &resp_data,     &resp_param))
	{
		int res = SVAL(resp_param,0);
		int converter=SVAL(resp_param,2);
		int i;

		if (res == 0)
		{
			count=SVAL(resp_param,4);
			p = resp_data;

			if (sort) qsort(p,count,20,QSORT_CAST strcasecmp);

			for (i = 0; i < count; i++)
			{
				char *sname = p;
				uint32 type = SVAL(p,14);
				int comment_offset = IVAL(p,16) & 0xFFFF;
				char *comment = NULL;

				if (comment_offset)
				{
					comment = resp_data+comment_offset-converter;
				}

				fn(sname, type, comment);

				if (long_share_name && strlen(sname) > 8) *long_share_name=True;

				p += 20;
			}
		}
	}

	if (resp_param) free(resp_param);
	if (resp_data) free(resp_data);

	return(count>0);
}


/****************************************************************************
call a NetServerEnum for the specified workgroup and servertype mask.
This function then calls the specified callback function for each name returned.

The callback function takes 3 arguments: the machine name, the server type and
the comment.
****************************************************************************/
BOOL cli_NetServerEnum(struct cli_state *cli, int t_idx, char *workgroup, uint32 stype,
		       void (*fn)(char *, uint32, char *))
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
	strcpy(p,"WrLehDz");
	p = skip_string(p,1);
  
	strcpy(p,"B16BBDz");
  
	p = skip_string(p,1);
	SSVAL(p,0,uLevel);
	SSVAL(p,2,BUFFER_SIZE);
	p += 4;
	SIVAL(p,0,stype);
	p += 4;
	
	pstrcpy(p, workgroup);
	p = skip_string(p,1);
	
	if (cli_api(cli, t_idx,  
		    PTR_DIFF(p,param), /* param count */
		    0, /*data count */
		    8, /* mprcount */
		    BUFFER_SIZE, /* mdrcount */
		    &rprcnt,&rdrcnt,
		    param, NULL, 
		    &rparam,&rdata)) {
		int res = SVAL(rparam,0);
		int converter=SVAL(rparam,2);
		int i;
			
		if (res == 0) {
			count=SVAL(rparam,4);
			p = rdata;
					
			for (i = 0;i < count;i++, p += 26) {
				char *sname = p;
				int comment_offset = IVAL(p,22) & 0xFFFF;
				char *cmnt = comment_offset?(rdata+comment_offset-converter):"";

				stype = IVAL(p,18) & ~SV_TYPE_LOCAL_LIST_ONLY;

				if (fn) fn(sname, stype, cmnt);
			}
		}
	}
  
	if (rparam) free(rparam);
	if (rdata) free(rdata);
	
	return(count > 0);
}




static  struct {
    int prot;
    char *name;
  }
prots[] = 
    {
      {PROTOCOL_CORE,"PC NETWORK PROGRAM 1.0"},
      {PROTOCOL_COREPLUS,"MICROSOFT NETWORKS 1.03"},
      {PROTOCOL_LANMAN1,"MICROSOFT NETWORKS 3.0"},
      {PROTOCOL_LANMAN1,"LANMAN1.0"},
      {PROTOCOL_LANMAN2,"LM1.2X002"},
      {PROTOCOL_LANMAN2,"Samba"},
      {PROTOCOL_NT1,"NT LANMAN 1.0"},
      {PROTOCOL_NT1,"NT LM 0.12"},
      {-1,NULL}
    };


/****************************************************************************
send a session setup

password-generating options:

- send two 16 byte hashes             (pass=LM16 ntpass=NT16)
- send a clear-text password          (pass=ct-pw ntpass=NULL)
- send different clear-text passwords (pass=ct-pw ntpass=ct-pw)
- send pre-computed OWFS              (pass=p24 ntpass=p24)

in all instances except the pre-computed OWFs, both the LM OWF and NT OWF
will be generated.

****************************************************************************/
BOOL cli_session_setup(struct cli_state *cli,
		       char *user, 
		       char *pass, int passlen,
		       char *ntpass, int ntpasslen,
		       char *workgroup)
{
	char *p;
	fstring pword;
	fstring ntpword;

	DEBUG(3,("cli_session_setup: protocol %d sec_mode: %x passlen %d\n",
	          cli->protocol, cli->sec_mode, passlen));

	if (cli->num_tcons != 0)
	{
		DEBUG(2,("cli_session_setup: connections appear to be already open\n"));
		return False;
	}

#ifdef DEBUG_PASSWORD
	if (pass)
	{
		DEBUG(100, ("password   : "));
		dump_data(100, pass, passlen);
	}
	if (ntpass)
	{
		DEBUG(100, ("nt-password: "));
		dump_data(100, ntpass, ntpasslen);
	}
#endif

	if (cli->protocol < PROTOCOL_LANMAN1)
		return False;

	if (passlen > sizeof(pword)-1) {
		return False;
	}

	if (IS_BITS_SET_ALL(cli->sec_mode, USE_CHALLENGE_RESPONSE))
	{
		DEBUG(5,("cli_session_setup: using challenge-response mode\n"));

		/* detect if two 16 byte hashes have been handed to us */
		if (pass && ntpass && passlen == 16 && ntpasslen == 16)
		{
			DEBUG(6,("cli_session_setup: OWF both lm and nt passwords\n"));

			passlen = 24;
			SMBOWFencrypt((uchar *)pass  ,(uchar *)cli->cryptkey,(uchar *)pword);
			ntpasslen = 24;
			SMBOWFencrypt((uchar *)ntpass,(uchar *)cli->cryptkey,(uchar *)ntpword);
		}
		else if (pass)
		{
			if (*pass && passlen != 24)
			{
				/* do a LM password encrypt */
				passlen = 24;
				SMBencrypt((uchar *)pass,(uchar *)cli->cryptkey,(uchar *)pword);

				if (!ntpass)
				{
					/* do an NT password encrypt */
					ntpasslen = 24;
					SMBNTencrypt((uchar *)pass,(uchar *)cli->cryptkey,(uchar *)ntpword);
				}
			}
			else
			{
				memcpy(pword, pass, passlen);
			}

			if (ntpass)
			{
				if (*ntpass && ntpasslen != 24)
				{
					ntpasslen = 24;
					SMBNTencrypt((uchar *)ntpass,(uchar *)cli->cryptkey,(uchar *)ntpword);
				}
				else
				{
					/* an already-OWF'd challenge has been handed to us */
					memcpy(ntpword, ntpass, ntpasslen);
				}
			}
		}
		else
		{
			/* blank password... */
			pword[0] = 0;
			passlen = 1;
		}
	}
	else
	{
		DEBUG(5,("cli_session_setup: using given password (probably pass-through mode)\n"));
		memcpy(pword  , pass  , passlen  );
		memcpy(ntpword, ntpass, ntpasslen);
	}

	/* if in share level security then don't send a password now */
	if (!IS_BITS_SET_ALL(cli->sec_mode, USE_USER_LEVEL_SECURITY))
	{
		DEBUG(5,("cli_session_setup: using share-level security mode\n"));
		fstrcpy(pword, "");
		passlen=1;
	} 

	/* send a session setup command */
	bzero(cli->outbuf,smb_size);

	if (cli->protocol < PROTOCOL_NT1)
	{
		set_message(cli->outbuf,10,1 + strlen(user) + passlen,True);
		CVAL(cli->outbuf,smb_com) = SMBsesssetupX;
		cli_setup_packet(cli);

		CVAL(cli->outbuf,smb_vwv0) = 0xFF;
		SSVAL(cli->outbuf,smb_vwv2,cli->max_xmit);
		SSVAL(cli->outbuf,smb_vwv3,2);
		SSVAL(cli->outbuf,smb_vwv4,1);
		SIVAL(cli->outbuf,smb_vwv5,cli->sesskey);
		SSVAL(cli->outbuf,smb_vwv7,passlen);
		p = smb_buf(cli->outbuf);
		memcpy(p,pword,passlen);
		p += passlen;
		strcpy(p,user);
		strupper(p);
	}
	else
	{
		cli_setpid(cli, 0xcafe);
		set_message(cli->outbuf,13,0,True);
		CVAL(cli->outbuf,smb_com) = SMBsesssetupX;
		cli_setup_packet(cli);
		
		CVAL(cli->outbuf,smb_vwv0) = 0xFF;
		SSVAL(cli->outbuf,smb_vwv2,BUFFER_SIZE);
		SSVAL(cli->outbuf,smb_vwv3,2);
		SSVAL(cli->outbuf,smb_vwv4,1);
		SIVAL(cli->outbuf,smb_vwv5,cli->sesskey);
		SSVAL(cli->outbuf,smb_vwv7,passlen);
		SSVAL(cli->outbuf,smb_vwv8,ntpasslen);
		SSVAL(cli->outbuf,smb_vwv11,CAP_STATUS32);
		p = smb_buf(cli->outbuf);
		memcpy(p,pword,passlen); 
		p += SVAL(cli->outbuf,smb_vwv7);
		if (ntpasslen != 0)
		{
			memcpy(p,ntpword,ntpasslen); 
			p += SVAL(cli->outbuf,smb_vwv8);
		}
		strcpy(p,user);
#if 0
		strupper(p);
#endif
		p = skip_string(p,1);
		strcpy(p,workgroup);
		strupper(p);
		p = skip_string(p,1);
		strcpy(p,"Windows NT 1381");p = skip_string(p,1);
		strcpy(p,"Windows NT 4.0");p = skip_string(p,1);
		set_message(cli->outbuf,13,PTR_DIFF(p,smb_buf(cli->outbuf)),False);
	}

      show_msg(cli->outbuf);

      send_smb(cli->fd,cli->outbuf);
      if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
	      return False;

      show_msg(cli->inbuf);

      if (cli_error(cli, NULL, NULL)) return(False);

      /* use the returned uid from now on */
      cli->uid = SVAL(cli->inbuf,smb_uid);

      return True;
}


/****************************************************************************
send a tconX
****************************************************************************/
BOOL cli_send_tconX(struct cli_state *cli, int *t_idx, 
		    char *share, char *dev, char *pass, int passlen)
{
	fstring pword;
	char *p;
	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	DEBUG(3,("cli_send_tconX: share:%s dev:%s passlen:%d\n",
			share, dev, passlen));

	if (cli->num_tcons == MAX_CLIENT_CONNECTIONS)
	{
		DEBUG(2,("cli_send_tconX: max number of client connections reached\n"));
		return False;
	}

	(*t_idx) = cli->num_tcons;
	cli->num_tcons++;

	if (!IS_BITS_SET_ALL(cli->sec_mode, USE_USER_LEVEL_SECURITY))
	{
		DEBUG(5,("cli_send_tconX: using share-level security mode\n"));
		passlen = 1;
		pass = "";
	}

	if (IS_BITS_SET_ALL(cli->sec_mode, USE_CHALLENGE_RESPONSE) && *pass && passlen != 24)
	{
		DEBUG(5,("cli_send_tconX: using challenge-response mode\n"));
		passlen = 24;
		SMBencrypt((uchar *)pass,(uchar *)cli->cryptkey,(uchar *)pword);
	}
	else
	{
		DEBUG(5,("cli_send_tconX: using given password (probably pass-through mode)\n"));
		memcpy(pword, pass, passlen);
	}

	sprintf(cli->con[(*t_idx)].full_share, "\\\\%s\\%s", cli->called_netbios_name, share);
	strcpy(cli->con[(*t_idx)].dev, dev);

	DEBUG(5,("cli_send_tconX: full share name:%s\n", cli->con[(*t_idx)].full_share));

	set_message(cli->outbuf,4,
		    2 + strlen(cli->con[(*t_idx)].full_share) + passlen + strlen(cli->con[(*t_idx)].dev),True);
	CVAL(cli->outbuf,smb_com) = SMBtconX;
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv3,passlen);

	p = smb_buf(cli->outbuf);
	memcpy(p,pword,passlen);
	p += passlen;
	strcpy(p,cli->con[(*t_idx)].full_share);
	p = skip_string(p,1);
	strcpy(p,cli->con[(*t_idx)].dev);

	SCVAL(cli->inbuf,smb_rcls, 1);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

    if (cli_error(cli, NULL, NULL)) return(False);

	cli->con[(*t_idx)].cnum = SVAL(cli->inbuf,smb_tid);
	return True;
}


/****************************************************************************
send a tree disconnect
****************************************************************************/
BOOL cli_tdis(struct cli_state *cli, int t_idx)
{
	cli_set_smb_cmd(cli, t_idx,  SMBtdis, 0,0,True);
	
	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;
	
    return !cli_error(cli, NULL, NULL);
}


/****************************************************************************
delete a directory
****************************************************************************/
BOOL cli_rmdir(struct cli_state *cli, int t_idx, char *dname)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBrmdir, 0, 2 + strlen(dname),True);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p,dname);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

    if (cli_error(cli, NULL, NULL)) return False;

	return True;
}


/****************************************************************************
delete a file
****************************************************************************/
BOOL cli_unlink(struct cli_state *cli, int t_idx, char *fname)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBunlink, 1, 2 + strlen(fname),True);


	SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN);
  
	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p,fname);
	p = skip_string(p,1);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

    if (cli_error(cli, NULL, NULL)) return False;

	return True;
}


/****************************************************************************
 send a message
 ****************************************************************************/
int cli_send_message(struct cli_state *cli, int t_idx, 
				char *username, char *desthost,
				char *message, int *total_len)
{
	int idx = 0;

	char *p;
	int grp_id;

	if (total_len == NULL) return False;
	*total_len = 0;

	/* send a SMBsendstrt command */
	cli_set_smb_cmd(cli, t_idx,  SMBsendstrt,0,0,True);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	strcpy(p,username);
	p = skip_string(p,1);
	*p++ = 4;
	strcpy(p,desthost);
	p = skip_string(p,1);

	set_message(cli->outbuf,0,PTR_DIFF(p,smb_buf(cli->outbuf)),False);

	send_smb(cli->fd,cli->outbuf);

	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli, NULL, NULL)) return False;

	grp_id = SVAL(cli->inbuf,smb_vwv0);

	while ((*total_len) < 1600)
	{
		int maxlen = MIN(1600 - (*total_len),127);
		pstring msg;
		int l=0;
		int c;

		bzero(msg, smb_size);

		for (l = 0; l < maxlen && (c = message[idx]) != EOF; l++, idx++)
		{
			msg[l] = c;   
		}

		cli_set_smb_cmd(cli, t_idx,  SMBsendtxt, 1,l+3,True);

		SSVAL(cli->outbuf,smb_vwv0,grp_id);

		p = smb_buf(cli->outbuf);
		*p = 1;
		SSVAL(p,1,l);
		memcpy(p+3,msg,l);

		send_smb(cli->fd,cli->outbuf);

		if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
		if (cli_error(cli,  NULL, NULL)) return False;

		(*total_len) += l;
	}

	cli_set_smb_cmd(cli, t_idx,  SMBsendend, 1,0,False);
	SSVAL(cli->outbuf,smb_vwv0,grp_id);

	send_smb(cli->fd,cli->outbuf);

	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL)) return False;

	return True;
}

/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
void cli_do_dir(struct cli_state *cli, int t_idx, struct client_info *info,
				char *Mask,int attribute, BOOL recurse_dir,
				void (*fn)(struct cli_state*, int, struct client_info*, file_info*))
{
  DEBUG(5,("do_dir(mask:%s, attrib:%x, recurse:%s)\n",
				Mask,attribute,BOOLSTR(recurse_dir)));

  if (cli->protocol >= PROTOCOL_LANMAN2)
    {
      if (cli_long_dir(cli, t_idx,  info, Mask, attribute, recurse_dir, fn) > 0)
	return;
    }

  expand_mask(Mask,False);
  cli_short_dir(cli, t_idx,  info, Mask,attribute, recurse_dir, fn);
  return;
}

/*******************************************************************
  decide if a file should be operated on
  ********************************************************************/
static BOOL do_this_one(file_info *finfo, struct client_info *info)
{
  if (finfo->mode & aDIR) return(True);

  if (info->newer_than && finfo->mtime < info->newer_than)
    return(False);

  if ((info->archive_level==1 || info->archive_level==2) && !(finfo->mode & aARCH))
    return(False);

  return(True);
}


/****************************************************************************
  act on the files in a dir listing
  ****************************************************************************/
static void dir_action(struct cli_state *cli, int t_idx, struct client_info *info,
				int attribute, BOOL recurse_dir,
				void (*fn)(struct cli_state*, int, struct client_info*, file_info*),
				file_info *finfo, BOOL longdir)
{

  if (!((finfo->mode & aDIR) == 0 && *info->file_sel && 
	!mask_match(finfo->name,info->file_sel,False,False)) &&
      !(recurse_dir && (strequal(finfo->name,".") || 
			strequal(finfo->name,".."))))
    {
      if (recurse_dir && (finfo->mode & aDIR))
	{
	  pstring mask2;
	  pstring sav_dir;
	  strcpy(sav_dir,info->cur_dir);
	  strcat(info->cur_dir,finfo->name);
	  strcat(info->cur_dir,"\\");
	  strcpy(mask2,info->cur_dir);

	  if (!fn)
	    DEBUG(0,("\n%s\n",CNV_LANG(info->cur_dir)));

	  strcat(mask2,"*");

	  if (longdir)
	    cli_long_dir(cli, t_idx,  info, mask2, attribute, recurse_dir, fn);
	  else
	    cli_dir(cli, t_idx,  info, mask2, attribute, recurse_dir, fn);

	  strcpy(info->cur_dir,sav_dir);
	}
      else
	{
	  if (fn && do_this_one(finfo, info))
	    fn(cli, t_idx,  info, finfo);
	}
    }
}

/****************************************************************************
interpret a long filename structure - this is mostly guesses at the moment
The length of the structure is returned
The structure of a long filename depends on the info level. 260 is used
by NT and 2 is used by OS/2
****************************************************************************/
static int interpret_long_filename(int level,char *p,file_info *finfo,
				struct client_info *info)
{
  if (finfo)
    memcpy(finfo,&def_finfo,sizeof(*finfo));

  switch (level)
    {
    case 1: /* OS/2 understands this */
      if (finfo)
	{
	  /* these dates are converted to GMT by make_unix_date */
	  finfo->ctime = make_unix_date2(p+4);
	  finfo->atime = make_unix_date2(p+8);
	  finfo->mtime = make_unix_date2(p+12);
	  finfo->size = IVAL(p,16);
	  finfo->mode = CVAL(p,24);
	  strcpy(finfo->name,p+27);
	}
      return(28 + CVAL(p,26));

    case 2: /* this is what OS/2 uses mostly */
      if (finfo)
	{
	  /* these dates are converted to GMT by make_unix_date */
	  finfo->ctime = make_unix_date2(p+4);
	  finfo->atime = make_unix_date2(p+8);
	  finfo->mtime = make_unix_date2(p+12);
	  finfo->size = IVAL(p,16);
	  finfo->mode = CVAL(p,24);
	  strcpy(finfo->name,p+31);
	}
      return(32 + CVAL(p,30));

      /* levels 3 and 4 are untested */
    case 3:
      if (finfo)
	{
	  /* these dates are probably like the other ones */
	  finfo->ctime = make_unix_date2(p+8);
	  finfo->atime = make_unix_date2(p+12);
	  finfo->mtime = make_unix_date2(p+16);
	  finfo->size = IVAL(p,20);
	  finfo->mode = CVAL(p,28);
	  strcpy(finfo->name,p+33);
	}
      return(SVAL(p,4)+4);

    case 4:
      if (finfo)
	{
	  /* these dates are probably like the other ones */
	  finfo->ctime = make_unix_date2(p+8);
	  finfo->atime = make_unix_date2(p+12);
	  finfo->mtime = make_unix_date2(p+16);
	  finfo->size = IVAL(p,20);
	  finfo->mode = CVAL(p,28);
	  strcpy(finfo->name,p+37);
	}
      return(SVAL(p,4)+4);

    case 260: /* NT uses this, but also accepts 2 */
      if (finfo)
	{
	  int ret = SVAL(p,0);
	  int namelen;
	  p += 4; /* next entry offset */
	  p += 4; /* fileindex */

	  /* these dates appear to arrive in a weird way. It seems to
	     be localtime plus the serverzone given in the initial
	     connect. This is GMT when DST is not in effect and one
	     hour from GMT otherwise. Can this really be right??

	     I suppose this could be called kludge-GMT. Is is the GMT
	     you get by using the current DST setting on a different
	     localtime. It will be cheap to calculate, I suppose, as
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
	  StrnCpy(finfo->name,p,namelen);
	  return(ret);
	}
      return(SVAL(p,0));
    }

  DEBUG(1,("Unknown long filename format %d\n",level));
  return(SVAL(p,0));
}


/****************************************************************************
  get info on a file
  ****************************************************************************/
BOOL cli_stat(struct cli_state *cli, int t_idx, char *file)
{
	BOOL ret;
	pstring param;
	char *resp_data=NULL;
	char *resp_param=NULL;
	int resp_data_len = 0;
	int resp_param_len=0;
	char *p;
	uint16 setup = TRANSACT2_QPATHINFO;

	bzero(param,6);
	SSVAL(param,0,4); /* level */
	p = param+6;
	strcat(p, file);

	cli_send_trans(cli, t_idx, SMBtrans2,NULL,0,FID_UNUSED,0,
	               NULL,param,&setup,
	               0,6 + strlen(p)+1,1,
	               BUFFER_SIZE,2,0);

	ret = cli_receive_trans(cli, t_idx,  SMBtrans2,
	                        &resp_data_len,&resp_param_len,
	                        &resp_data,&resp_param);

	if (resp_data ) free(resp_data); resp_data = NULL;
	if (resp_param) free(resp_param); resp_param = NULL;

	return ret;
}


/****************************************************************************
  print a file
  ****************************************************************************/
BOOL cli_print(struct cli_state *cli, int t_idx, struct client_info *info,
				FILE *f, char *lname, char *rname)
{
	uint16 fnum;
	uint32 nread=0;
	char *p;

	/* yes, you could potentially pass stdin as the input file */
	if (!f) f = fopen(lname,"r");

	if (!f)
	{
		DEBUG(0,("Error opening local file %s\n",lname));
		return False;
	}

	/* open for printing */

	cli_set_smb_cmd(cli, t_idx,  SMBsplopen, 2,2 + strlen(rname),True);

	SSVAL(cli->outbuf,smb_vwv0,0);
	SSVAL(cli->outbuf,smb_vwv1,info->print_mode);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p,rname);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL)) return False;

	fnum = SVAL(cli->inbuf,smb_vwv0);

	DEBUG(1,("cli_print: printing file %s as %s\n",lname,CNV_LANG(rname)));

	/* read file and send it */

	while (!feof(f))
	{
		int n;

		bzero(cli->outbuf,smb_size);
		set_message(cli->outbuf,1,3,True);

		/* for some strange reason the OS/2 print server can't handle large
		packets when printing. weird */
		n = MIN(1024, cli->max_xmit-(smb_len(cli->outbuf)+4));

		if (info->translation)
		{
			n = printread(info->translation, f,smb_buf(cli->outbuf)+3,(int)(0.95*n));
		}
		else
		{
			n = readfile(info->translation, smb_buf(cli->outbuf)+3,1,n,f);
		}

		if (n <= 0) 
		{
			DEBUG(0,("read gave %d\n",n));
			break;
		}

		smb_setlen(cli->outbuf,smb_len(cli->outbuf) + n);

		CVAL(cli->outbuf,smb_com) = SMBsplwr;
		SSVAL(cli->outbuf,smb_tid,cli->con[t_idx].cnum );
		cli_setup_packet(cli);

		SSVAL(cli->outbuf,smb_vwv0,fnum);
		SSVAL(cli->outbuf,smb_vwv1,n+3);
		CVAL(smb_buf(cli->outbuf),0) = 1;
		SSVAL(smb_buf(cli->outbuf),1,n);

		send_smb(cli->fd,cli->outbuf);
		if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
		if (cli_error(cli,  NULL, NULL))
		{
			DEBUG(0,("%s printing remote file\n", cli_errstr(cli)));
			break;
		}

		nread += n;
	}

	DEBUG(2,("%d bytes printed\n", nread));

	cli_set_smb_cmd(cli, t_idx,  SMBsplclose, 1,0,True);

	SSVAL(cli->outbuf,smb_vwv0,fnum);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL))
	{
		DEBUG(0,("%s closing print file\n", cli_errstr(cli)));
		if (f != stdin) fclose(f);
		return False;
	}

	if (f != stdin) fclose(f);

	return True;
}

/****************************************************************************
show a print queue - this is deprecated as it uses the old smb that
has limited support - the correct call is the cmd_p_queue_4() after this.
****************************************************************************/
int cli_queue(struct cli_state *cli, int t_idx, struct client_info *info,
				void (*fn)(uint16, char*, uint32, uint8))
{
	int count;
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBsplretq, 2,0,True);

	SSVAL(cli->outbuf, smb_vwv0, 32); /* a max of 20 entries is to be shown */
	SSVAL(cli->outbuf, smb_vwv1, 0); /* the index into the queue */

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL))
	{
		DEBUG(0,("%s obtaining print queue\n", cli_errstr(cli)));
		return -1;
	}

	count = SVAL(cli->inbuf,smb_vwv0);
	p = smb_buf(cli->inbuf) + 3;

	if (fn && count > 0)
	{
		int ct = count;

		while (ct--)
		{
			fn(SVAL(p,5), p+12, IVAL(p,7), CVAL(p, 4));
			p += 28;
		}
	}

	return count;
}

/****************************************************************************
  cancel a print job
  ****************************************************************************/
BOOL cli_cancel(struct cli_state *cli, int t_idx, uint16 job, uint16 *cancelled)
{
  BOOL ret = False;
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt,rprcnt;
  pstring param;

  bzero(param,sizeof(param));

  p = param;
  SSVAL(p,0,81);		/* DosPrintJobDel() */
  p += 2;
  strcpy(p,"W");
  p = skip_string(p,1);
  strcpy(p,"");
  p = skip_string(p,1);
  SSVAL(p,0,job);     
  p += 2;

	cli_send_trans(cli, t_idx, SMBtrans2,NULL,0,FID_UNUSED,0,
	         NULL,param,NULL,
	         0,PTR_DIFF(p,param),0,
	         BUFFER_SIZE,10,0);

	ret = cli_receive_trans(cli, t_idx,  SMBtrans2,
	                       &rdrcnt,&rprcnt,
	                       &rdata,&rparam);
    if (ret)
    {
      if (cancelled) *cancelled = SVAL(rparam,0);
    }

  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return ret;
}

/*****************************************************************************
 Convert a character pointer in a cli_call_api() response to a form we can use.
 This function contains code to prevent core dumps if the server returns 
 invalid data.
*****************************************************************************/
static char *fix_char_ptr(unsigned int datap, unsigned int converter, char *rdata, int rdrcnt)
{
if( datap == 0 )		/* turn NULL pointers */
  {				/* into zero length strings */
  return "";
  }
else
  {
  unsigned int offset = datap - converter;

  if( offset >= rdrcnt )
    {
      DEBUG(1,("bad char ptr: datap=%u, converter=%u, rdata=%lu, rdrcnt=%d>", datap, converter, (unsigned long)rdata, rdrcnt));
    return "<ERROR>";
    }
  else
    {
    return &rdata[offset];
    }
  }
}


/****************************************************************************
get information in a print queue
****************************************************************************/
int cli_pqueue_2(struct cli_state *cli, int t_idx, struct client_info *info,
			void (*fn)(char*, uint16, uint16, char *, time_t, uint32, char *))
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt, rprcnt;
	pstring param;
	int result_code = -1;

	bzero(param,sizeof(param));

	p = param;
	SSVAL(p,0,76);                            /* API fn 76 (DosPrintJobEnum) */
	p += 2;
	strcpy(p,"zWrLeh");                       /* parameter description? */
	p = skip_string(p,1);
	strcpy(p,"WWzWWDDzz");                    /* returned data format */
	p = skip_string(p,1);
	strcpy(p,strrchr(cli->con[t_idx].full_share,'\\')+1); /* name of queue */
	p = skip_string(p,1);
	SSVAL(p,0,2);                             /* API lvl2, PRJINFO_2 data */
	SSVAL(p,2,1000);                          /* size (bytes) of return buffer */
	p += 4;
	strcpy(p,"");                             /* subformat */
	p = skip_string(p,1);

	DEBUG(1,("Calling DosPrintJobEnum()...\n"));

	cli_send_trans(cli, t_idx, SMBtrans2,NULL,0,FID_UNUSED,0,
	         NULL,param,NULL,
	         0,PTR_DIFF(p,param),0,
	         BUFFER_SIZE,10,0);

	if (cli_receive_trans(cli, t_idx,  SMBtrans2,
	                       &rdrcnt,&rprcnt,
	                       &rdata,&rparam))
	{
		int converter;
		int i;
		char PrinterName[20];

		result_code = SVAL(rparam,0);
		converter = SVAL(rparam,2);             /* conversion factor */

		DEBUG(2,("returned %d bytes of parameters, %d bytes of data, %d records\n", rprcnt, rdrcnt, SVAL(rparam,4) ));

		if (result_code != 0) return result_code;

		strcpy(PrinterName,strrchr(cli->con[t_idx].full_share,'\\')+1); /* queue name */
		strlower(PrinterName);                              /* in lower case */

		p = rdata; /* received data */

		for (i = 0; i < SVAL(rparam,4); ++i)
		{
			uint16 JobId = SVAL(p,0);
			uint16 Priority = SVAL(p,2);
			char *UserName = fix_char_ptr(SVAL(p,4), converter, rdata, rdrcnt);
			time_t JobTime = make_unix_date3( p + 12);
			uint32 Size = IVAL(p,16);
			char *JobName = fix_char_ptr(SVAL(p,24), converter, rdata, rdrcnt);

			strlower(UserName);

			if (fn)
			{
				fn( PrinterName, JobId, Priority,
				    UserName,JobTime, Size, JobName);
			}

#if 0 /* DEBUG code */
			DEBUG(4,("Job Id: \"%u\"\n", SVAL(p,0)));
			DEBUG(4,("Priority: \"%u\"\n", SVAL(p,2)));

			DEBUG(4,("User Name: \"%s\"\n", fix_char_ptr(SVAL(p,4), converter, rdata, rdrcnt) ));
			DEBUG(4,("Position: \"%u\"\n", SVAL(p,8)));
			DEBUG(4,("Status: \"%u\"\n", SVAL(p,10)));

			JobTime = make_unix_date3( p + 12);
			DEBUG(4,("Submitted: \"%s\"\n", asctime(LocalTime(&JobTime))));
			DEBUG(4,("date: \"%u\"\n", SVAL(p,12)));

			DEBUG(4,("Size: \"%u\"\n", SVAL(p,16)));
			DEBUG(4,("Comment: \"%s\"\n", fix_char_ptr(SVAL(p,20), converter, rdata, rdrcnt) ));
			DEBUG(4,("Document: \"%s\"\n", fix_char_ptr(SVAL(p,24), converter, rdata, rdrcnt) ));
#endif /* DEBUG CODE */ 

			p += 28;
		}
	}
	else                  /* cli_call_api() failed */
	{
		printf("Failed, error = %d\n", result_code);
	}

	/* If any parameters or data were returned, free the storage. */
	if(rparam) free(rparam);
	if(rdata) free(rdata);

	return result_code;
}

/****************************************************************************
show information about a print queue
****************************************************************************/
BOOL cli_printq_info(struct cli_state *cli, int t_idx, struct client_info *info,
				char *name, uint16 *priority,
				uint16 *start_time, uint16 *until_time,
				char *separator_file, char *print_processor,
				char *params, char *comment,
				uint16 *status, uint16 *jobs,
				char *printers, char *driver_name,
				char **driver_data, int *driver_count)
{
	char *rparam = NULL;
	char *rdata = NULL;
	char *p;
	int rdrcnt, rprcnt;
	pstring param;
	int result_code = -1;

	bzero(param,sizeof(param));

	p = param;
	SSVAL(p,0,70); 			/* API function number 70 (DosPrintQGetInfo) */
	p += 2;
	strcpy(p,"zWrLh");			/* parameter description? */
	p = skip_string(p,1);
	strcpy(p,"zWWWWzzzzWWzzl");		/* returned data format */
	p = skip_string(p,1);
	strcpy(p,strrchr(cli->con[t_idx].full_share,'\\')+1);	/* name of queue */
	p = skip_string(p,1);
	SSVAL(p,0,3);				/* API function level 3, just queue info, no job info */
	SSVAL(p,2,1000);			/* size of bytes of returned data buffer */
	p += 4;
	strcpy(p,"");				/* subformat */
	p = skip_string(p,1);

	DEBUG(1,("Calling DosPrintQueueGetInfo()...\n"));

	cli_send_trans(cli, t_idx, SMBtrans2,NULL,0,FID_UNUSED,0,
			 NULL,param, NULL,
			 0,PTR_DIFF(p,param),1,
			 BUFFER_SIZE,10,0);

	if (cli_receive_trans(cli, t_idx,  SMBtrans2,
	                 &rprcnt, &rdrcnt,
	                 &rparam, &rdata) )
	{
		int converter;
		result_code = SVAL(rparam,0);
		converter = SVAL(rparam,2);		/* conversion factor */

		DEBUG(2,("returned %d bytes of parameters, %d bytes of data, %d records\n", rprcnt, rdrcnt, SVAL(rparam,4) ));

		if (result_code != 0) return result_code;

		p = rdata;				/* received data */

		fstrcpy(name, fix_char_ptr(SVAL(p,0), converter, rdata, rdrcnt) );
		*priority = SVAL(p,4);
		*start_time = SVAL(p,6);
		*until_time = SVAL(p,8);
		fstrcpy(separator_file, fix_char_ptr(SVAL(p,12), converter, rdata, rdrcnt) );
		fstrcpy(print_processor, fix_char_ptr(SVAL(p,16), converter, rdata, rdrcnt) );
		fstrcpy(params, fix_char_ptr(SVAL(p,20), converter, rdata, rdrcnt) );
		fstrcpy(comment, fix_char_ptr(SVAL(p,24), converter, rdata, rdrcnt) );
		*status = SVAL(p,28);
		*jobs = SVAL(p,30);
		fstrcpy(printers, fix_char_ptr(SVAL(p,32), converter, rdata, rdrcnt) );
		fstrcpy(driver_name, fix_char_ptr(SVAL(p,36), converter, rdata, rdrcnt) );

		(*driver_data) = rdata + SVAL(p,40) - converter;
		if( SVAL(p,40) == 0 )
		{
			*driver_count = 0;
		}
		else
		{
			*driver_count = IVAL((*driver_data),0);
		}
	}

	/* If any parameters or data were returned, free the storage. */
	if(rparam) free(rparam);
	if(rdata) free(rdata);

	return result_code;
}

/****************************************************************************
  display info about a file
  ****************************************************************************/
static void display_finfo(struct cli_state *cli, int t_idx, struct client_info *info,
				file_info *finfo)
{
  if (do_this_one(finfo, info))
  {
    time_t t = finfo->mtime; /* the time is assumed to be passed as GMT */
    DEBUG(0,("  %-30s%7.7s%10d  %s",
  	   CNV_LANG(finfo->name),
	   attrib_string(finfo->mode),
	   finfo->size,
	   asctime(LocalTime(&t))));
	if (info->dir_total)
	{
    	info->dir_total += finfo->size;
	}
  }
}


/****************************************************************************
  do a directory listing, calling fn on each file found. Use the TRANSACT2
  call for long filenames
  ****************************************************************************/
int cli_long_dir(struct cli_state *cli, int t_idx, struct client_info *info,
				char *Mask,int attribute, BOOL recurse_dir,
				void (*fn)(struct cli_state*, int, struct client_info*, file_info*))
{
  int max_matches = 512;
  int info_level = cli->protocol<PROTOCOL_NT1?1:260; /* NT uses 260, OS/2 uses 2. Both accept 1. */
  char *p;
  pstring mask;
  file_info finfo;
  int i;
  char *dirlist = NULL;
  int dirlist_len = 0;
  int total_received = 0;
  BOOL First = True;
  char *resp_data=NULL;
  char *resp_param=NULL;
  int resp_data_len = 0;
  int resp_param_len=0;

  int ff_resume_key = 0;
  int ff_searchcount=0;
  int ff_eos=0;
  int ff_lastname=0;
  int ff_dir_handle=0;
  int loop_count = 0;

  uint16 setup;
  pstring param;

  strcpy(mask,Mask);

  while (ff_eos == 0)
    {
      loop_count++;
      if (loop_count > 200)
	{
	  DEBUG(0,("Error: Looping in FIND_NEXT??\n"));
	  break;
	}

      if (First)
	{
	  setup = TRANSACT2_FINDFIRST;
	  SSVAL(param,0,attribute); /* attribute */
	  SSVAL(param,2,max_matches); /* max count */
	  SSVAL(param,4,8+4+2);	/* resume required + close on end + continue */
	  SSVAL(param,6,info_level); 
	  SIVAL(param,8,0);
	  strcpy(param+12,mask);
	}
      else
	{
	  setup = TRANSACT2_FINDNEXT;
	  SSVAL(param,0,ff_dir_handle);
	  SSVAL(param,2,max_matches); /* max count */
	  SSVAL(param,4,info_level); 
	  SIVAL(param,6,ff_resume_key); /* ff_resume_key */
	  SSVAL(param,10,8+4+2);	/* resume required + close on end + continue */
	  strcpy(param+12,mask);

	  DEBUG(5,("hand=0x%X resume=%d ff_lastname=%d mask=%s\n",
		   ff_dir_handle,ff_resume_key,ff_lastname,mask));
	}
      /* ??? original code added 1 pad byte after param */

      cli_send_trans(cli, t_idx, SMBtrans2,NULL,0,FID_UNUSED,0,
			 NULL,param,&setup,
			 0,12+strlen(mask)+1,1,
			 BUFFER_SIZE,10,0);

      if (!cli_receive_trans(cli, t_idx,  SMBtrans2,
			      &resp_data_len,&resp_param_len,
			          &resp_data,&resp_param))
	{
	  DEBUG(3,("FIND%s gave %s\n",First?"FIRST":"NEXT", cli_errstr(cli)));
	  break;
	}

      /* parse out some important return info */
      p = resp_param;
      if (First)
	{
	  ff_dir_handle = SVAL(p,0);
	  ff_searchcount = SVAL(p,2);
	  ff_eos = SVAL(p,4);
	  ff_lastname = SVAL(p,8);
	}
      else
	{
	  ff_searchcount = SVAL(p,0);
	  ff_eos = SVAL(p,2);
	  ff_lastname = SVAL(p,6);
	}

      if (ff_searchcount == 0) 
	break;

      /* point to the data bytes */
      p = resp_data;

      /* we might need the lastname for continuations */
      if (ff_lastname > 0)
	{
	  switch(info_level)
	    {
	    case 260:
	      ff_resume_key =0;
	      StrnCpy(mask,p+ff_lastname,resp_data_len-ff_lastname);
	      /* strcpy(mask,p+ff_lastname+94); */
	      break;
	    case 1:
	      strcpy(mask,p + ff_lastname + 1);
	      ff_resume_key = 0;
	      break;
	    }
	}
      else
	strcpy(mask,"");
  
      /* and add them to the dirlist pool */
      dirlist = Realloc(dirlist,dirlist_len + resp_data_len);

      if (!dirlist)
	{
	  DEBUG(0,("Failed to expand dirlist\n"));
	  break;
	}

      /* put in a length for the last entry, to ensure we can chain entries 
	 into the next packet */
      {
	char *p2;
	for (p2=p,i=0;i<(ff_searchcount-1);i++)
	  p2 += interpret_long_filename(info_level,p2,NULL, info);
	SSVAL(p2,0,resp_data_len - PTR_DIFF(p2,p));
      }

      /* grab the data for later use */
      memcpy(dirlist+dirlist_len,p,resp_data_len);
      dirlist_len += resp_data_len;

      total_received += ff_searchcount;

      if (resp_data) free(resp_data); resp_data = NULL;
      if (resp_param) free(resp_param); resp_param = NULL;

      DEBUG(3,("received %d entries (eos=%d resume=%d)\n",
	       ff_searchcount,ff_eos,ff_resume_key));

      First = False;
    }

  if (!fn)
    for (p=dirlist,i=0;i<total_received;i++)
      {
	p += interpret_long_filename(info_level,p,&finfo, info);
	display_finfo(cli, t_idx,  info, &finfo);
      }

  for (p=dirlist,i=0;i<total_received;i++)
    {
      p += interpret_long_filename(info_level,p,&finfo, info);
      dir_action(cli, t_idx,  info, attribute, recurse_dir, fn, &finfo, True);
    }

  /* free up the dirlist buffer */
  if (dirlist) free(dirlist);
  return(total_received);
}


/****************************************************************************
interpret a short filename structure
The length of the structure is returned
****************************************************************************/
static int interpret_short_filename(char *p,file_info *finfo)
{
  finfo->mode = CVAL(p,21);

  /* this date is converted to GMT by make_unix_date */
  finfo->ctime = make_unix_date(p+22);
  finfo->mtime = finfo->atime = finfo->ctime;
  finfo->size = IVAL(p,26);
  strcpy(finfo->name,p+30);
  
  return(DIR_STRUCT_SIZE);
}

/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
int cli_short_dir(struct cli_state *cli, int t_idx, struct client_info *info,
				char *Mask,int attribute, BOOL recurse_dir,
				void (*fn)(struct cli_state*, int, struct client_info*, file_info*))
{
  char *p;
  int received = 0;
  BOOL first = True;
  char status[21];
  int num_asked = (cli->max_xmit - 100)/DIR_STRUCT_SIZE;
  int num_received = 0;
  int i;
  char *dirlist = NULL;
  pstring mask;
  file_info finfo;

  finfo = def_finfo;

  bzero(status,21);

  strcpy(mask,Mask);
  
  while (1)
    {
		int num_bytes = 0;
		int num_words = 0;
		uint8 cmd = 0;

      bzero(cli->outbuf,smb_size);
      if (first)	
		{
			num_words = 2;
			num_bytes = 5 + strlen(mask);
		}
      else
		{
			num_words = 2;
			num_bytes = 5 + 21;
		}

#if FFIRST
      if (cli->protocol >= PROTOCOL_LANMAN1)
	cmd = SMBffirst;
      else
#endif
	cmd = SMBsearch;

	cli_set_smb_cmd(cli, t_idx,  cmd, num_words, num_bytes, True);

      SSVAL(cli->outbuf,smb_vwv0,num_asked);
      SSVAL(cli->outbuf,smb_vwv1,attribute);
  
      p = smb_buf(cli->outbuf);
      *p++ = 4;
      
      if (first)
	strcpy(p,mask);
      else
	strcpy(p,"");
      p += strlen(p) + 1;
      
      *p++ = 5;
      if (first)
	SSVAL(p,0,0);
      else
	{
	  SSVAL(p,0,21);
	  p += 2;
	  memcpy(p,status,21);
	}

	send_smb(cli->fd,cli->outbuf);
	if (receive_smb(cli->fd, cli->inbuf, cli->timeout))
	{ 
      received = SVAL(cli->inbuf,smb_vwv0);
    }
    else
    {
      received = 0;
    }

      DEBUG(5,("dir received %d\n",received));

      DEBUG(6,("errstr=%s\n",cli_errstr(cli)));

      if (received <= 0) break;

      first = False;

      dirlist = Realloc(dirlist,(num_received + received)*DIR_STRUCT_SIZE);

      if (!dirlist) 
	return 0;

      p = smb_buf(cli->inbuf) + 3;

      memcpy(dirlist+num_received*DIR_STRUCT_SIZE,
	     p,received*DIR_STRUCT_SIZE);

      memcpy(status,p + ((received-1)*DIR_STRUCT_SIZE),21);

      num_received += received;

      if (CVAL(cli->inbuf,smb_rcls) != 0) break;
    }

#if FFIRST
  if (!first && cli->protocol >= PROTOCOL_LANMAN1)
    {
      bzero(cli->outbuf,smb_size);
      CVAL(cli->outbuf,smb_com) = SMBfclose;

      SSVAL(cli->outbuf,smb_tid,cli->con[t_idx].cnum );
      cli_setup_packet(cli);

      p = smb_buf(cli->outbuf);
      *p++ = 4;
      
      strcpy(p,"");
      p += strlen(p) + 1;
      
      *p++ = 5;
      SSVAL(p,0,21);
      p += 2;
      memcpy(p,status,21);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd, cli->inbuf, cli->timeout) ||
	     cli_error(cli,  NULL, NULL))
	{ 
	DEBUG(0,("Error closing search: %s\n", cli_errstr(cli)));      
    }
#endif

  if (!fn)
    for (p=dirlist,i=0;i<num_received;i++)
      {
	p += interpret_short_filename(p,&finfo);
	display_finfo(cli, t_idx,  info, &finfo);
      }

  for (p=dirlist,i=0;i<num_received;i++)
    {
      p += interpret_short_filename(p,&finfo);
      dir_action(cli, t_idx,  info, attribute, recurse_dir, fn, &finfo, False);
    }

  if (dirlist) free(dirlist);
  return(num_received);
}

/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
void cli_dir(struct cli_state *cli, int t_idx, struct client_info *info,
				char *Mask,int attribute, BOOL recurse_dir,
				void (*fn)(struct cli_state*, int, struct client_info*, file_info*))
{
  DEBUG(5,("cli_dir(%s,%x,%s)\n",Mask,attribute,BOOLSTR(recurse_dir)));
  if (cli->protocol >= PROTOCOL_LANMAN2)
    {
      if (cli_long_dir(cli, t_idx,  info, Mask, attribute, recurse_dir, fn) > 0)
	return;
    }

  expand_mask(Mask,False);
  cli_short_dir(cli, t_idx,  info, Mask, attribute, recurse_dir, fn);
  return;
}


/****************************************************************************
  put a single file
  ****************************************************************************/
int cli_put(struct cli_state *cli, int t_idx, struct client_info *info,
				char *rname,char *lname, file_info *finfo,
				int (*read_fn)(struct client_info *, char*, int, int, FILE *))
{
  uint16 fnum;
  FILE *f;
  int nread=0;
  time_t close_time = finfo->mtime;
  char *buf=NULL;
  static int maxwrite=0;

  struct timeval tp_start;
  GetTimeOfDay(&tp_start);

  f = fopen(lname,"r");

  if (!f)
    {
      DEBUG(0,("cli_put: Error opening local file %s\n", lname));
      return False;
    }

  if (finfo->mtime == 0 || finfo->mtime == -1)
    finfo->mtime = finfo->atime = finfo->ctime = time(NULL);

  if (!cli_create(cli, t_idx,  rname, finfo->mode, finfo->mtime, &fnum)) return False;

  if (fnum == 0xffff) return False;

  if (finfo->size < 0)
    finfo->size = file_size(lname);
  
  DEBUG(1,("putting file %s of size %d bytes as %s\n",
		lname,finfo->size,CNV_LANG(rname)));
  
  if (!maxwrite)
    maxwrite = cli->writebraw_supported?MAX(cli->max_xmit,BUFFER_SIZE):(cli->max_xmit-200);

  while (nread < finfo->size)
    {
      int n = maxwrite;
      int ret;

      n = MIN(n,finfo->size - nread);

      /* HACK! this is for *possible* use by writeraw */
      buf = (char *)Realloc(buf,n+4);
  
      fseek(f,nread,SEEK_SET);
      /* buf+4 because that's where the data is */
      if ((n = read_fn(info, buf+4,1,n, f)) < 1)
	{
	  DEBUG(0,("Error reading local file\n"));
	  break;
	}	  

      /* buf+4 is the data.  buf[0..3] *might* get used by writeraw */
      ret = cli_write(cli, t_idx,  fnum, nread, buf+4, n);

      DEBUG(5,("cli_write: offset %ld requested %d.  received %d\n",
			nread, n, ret));

      if (n != ret) {
	if (!maxwrite) {
	  DEBUG(0,("Error writing file\n"));
	  break;
	} else {
	  maxwrite /= 2;
	  continue;
	}
      }

      nread += n;
    }

    if (!cli_close(cli, t_idx,  fnum, close_time))
    {
      DEBUG(0,("%s closing remote file %s\n",smb_errstr(cli->inbuf),CNV_LANG(rname)));
      fclose(f);
      if (buf) free(buf);
      return False;
    }

  
  fclose(f);
  if (buf) free(buf);

  {
    struct timeval tp_end;
    int this_time;

    GetTimeOfDay(&tp_end);
    this_time = 
      (tp_end.tv_sec - tp_start.tv_sec)*1000 +
	(tp_end.tv_usec - tp_start.tv_usec)/1000;
    info->put_total_time_ms += this_time;
    info->put_total_size += finfo->size;

    DEBUG(1,("(%g kb/s) (average %g kb/s)\n",
	     finfo->size          / (1.024*this_time + 1.0e-4),
	     info->put_total_size / (1.024*info->put_total_time_ms)));
  }

  return True;
} 

 
/****************************************************************************
  get a file from rname to lname
  ****************************************************************************/
int cli_get(struct cli_state *cli, int t_idx, struct client_info *info,
				char *rname,char *lname,file_info *finfo1,
				int handle,
				int (*init_fn)(struct client_info *, int, char*, file_info *),
				int (*write_fn)(struct client_info *, int, char*, int),
				int (*end_fn)(struct client_info*, int, char*, int, file_info*))
{  
  uint32 nread=0;
  char *p;
  file_info finfo;
  BOOL close_done = False;
  BOOL ignore_close_error = False;
  char *dataptr=NULL;
  int datalen=0;

  uint16 fnum;
  uint16 fmode;
  time_t mtime;
  uint32 fsize;

	struct timeval tar_tp_start;
	GetTimeOfDay(&tar_tp_start);

  if (finfo1) 
    finfo = *finfo1;
  else
    finfo = def_finfo;

  if (info->lowercase)
    strlower(lname);

  fnum = cli_open(cli, t_idx,  rname, O_RDONLY, DENY_NONE, &fmode, &mtime, &fsize);
			
  if (fnum == 0xffff) return False;

  strcpy(finfo.name,rname);

  if (!finfo1)
    {
      finfo.mode = fmode;
      /* these times arrive as LOCAL time, using the DST offset 
	 corresponding to that time, we convert them to GMT */
      finfo.atime = finfo.ctime = finfo.mtime = mtime;
      finfo.size = fsize;
    }

  /* following a successful cli_create(), call the initialisation function */
  if (init_fn)
  {
	if (!init_fn(info, handle, rname, &finfo)) return 0;
  }

  /* we might have got some data from a chained readX */
  if (SVAL(cli->inbuf,smb_vwv0) == SMBreadX)
    {
      p = (smb_base(cli->inbuf)+SVAL(cli->inbuf,smb_vwv1)) - smb_wct;
      datalen = SVAL(p,smb_vwv5);
      dataptr = smb_base(cli->inbuf) + SVAL(p,smb_vwv6);
    }
  else
    {
      dataptr = NULL;
      datalen = 0;
    }


  DEBUG(2,("getting file %s of size %d bytes as %s ",
	   CNV_LANG(finfo.name),
	   finfo.size,
	   lname));

  while (nread < finfo.size && !close_done)
    {
      int method = -1;
      static BOOL can_chain_close = True;

      p=NULL;
      
      DEBUG(3,("nread=%d max_xmit=%d fsize=%d\n",nread,cli->max_xmit,finfo.size));

      /* 3 possible read types. readbraw if a large block is required.
	 readX + close if not much left and read if neither is supported */

      /* we might have already read some data from a chained readX */
      if (dataptr && datalen>0)
	method=3;

      /* if we can finish now then readX+close */
      if (method<0 && can_chain_close && (cli->protocol >= PROTOCOL_LANMAN1) && 
	  ((finfo.size - nread) < 
	   (cli->max_xmit - (2*smb_size + 13*SIZEOFWORD + 300))))
	method = 0;

      /* if we support readraw then use that */
      if (method<0 && cli->readbraw_supported)
	method = 1;

      /* if we can then use readX */
      if (method<0 && (cli->protocol >= PROTOCOL_LANMAN1))
	method = 2;

      switch (method)
	{
	  /* use readX */
	case 0:
	case 2:
	  if (method == 0)
	    close_done = True;
	    
	  /* use readX + close */
	cli_set_smb_cmd(cli, t_idx,  SMBreadX, 10,0,True);
	  
	  if (close_done)
	    {
	      CVAL(cli->outbuf,smb_vwv0) = SMBclose;
	      SSVAL(cli->outbuf,smb_vwv1,smb_offset(smb_buf(cli->outbuf),cli->outbuf));
	    }
	  else
	    CVAL(cli->outbuf,smb_vwv0) = 0xFF;	      
	  
	  SSVAL(cli->outbuf,smb_vwv2,fnum);
	  SIVAL(cli->outbuf,smb_vwv3,nread);
	  SSVAL(cli->outbuf,smb_vwv5,MIN(cli->max_xmit-200,finfo.size - nread));
	  SSVAL(cli->outbuf,smb_vwv6,0);
	  SIVAL(cli->outbuf,smb_vwv7,0);
	  SSVAL(cli->outbuf,smb_vwv9,MIN(BUFFER_SIZE,finfo.size-nread));
	  
	  if (close_done)
	    {
	      p = smb_buf(cli->outbuf);
	      bzero(p,9);
	      
	      CVAL(p,0) = 3;
	      SSVAL(p,1,fnum);
	      SIVALS(p,3,-1);
	      
	      /* now set the total packet length */
	      smb_setlen(cli->outbuf,smb_len(cli->outbuf)+9);
	    }
	  
      send_smb(cli->fd,cli->outbuf);
      if (!receive_smb(cli->fd, cli->inbuf, cli->timeout)) break;
      if (cli_error(cli,  NULL, NULL)) break;

	  if (close_done &&
	      SVAL(cli->inbuf,smb_vwv0) != SMBclose)
	    {
	      /* NOTE: WfWg sometimes just ignores the chained
		 command! This seems to break the spec? */
	      DEBUG(3,("Rejected chained close?\n"));
	      close_done = False;
	      can_chain_close = False;
	      ignore_close_error = True;
	    }
	  
	  datalen = SVAL(cli->inbuf,smb_vwv5);
	  dataptr = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);
	  break;

	  /* use readbraw */
	case 1:
	  {
	    static int readbraw_size = BUFFER_SIZE;
	  
	cli_set_smb_cmd(cli, t_idx,  SMBreadbraw, 8,0,True);

	    SSVAL(cli->outbuf,smb_vwv0,fnum);
	    SIVAL(cli->outbuf,smb_vwv1,nread);
	    SSVAL(cli->outbuf,smb_vwv3,MIN(finfo.size-nread,readbraw_size));
	    SSVAL(cli->outbuf,smb_vwv4,0);
	    SIVALS(cli->outbuf,smb_vwv5,-1);

      send_smb(cli->fd,cli->outbuf);

	    /* Now read the raw data into the buffer and write it */	  
	    if(read_smb_length(cli->fd,cli->inbuf,0) == -1) {
	      DEBUG(0,("Failed to read length in readbraw\n"));	    
	      exit(1);
	    }
	    
	    /* Even though this is not an smb message, smb_len
	       returns the generic length of an smb message */
	    datalen = smb_len(cli->inbuf);

	    if (datalen == 0)
	      {
		/* we got a readbraw error */
		DEBUG(4,("readbraw error - reducing size\n"));
		readbraw_size = (readbraw_size * 9) / 10;
		
		if (readbraw_size < cli->max_xmit)
		  {
		    DEBUG(0,("disabling readbraw\n"));
		    cli->readbraw_supported = False;
		  }
		
		dataptr=NULL;
		continue;
	      }

	    if(read_data(cli->fd,cli->inbuf,datalen) != datalen) {
	      DEBUG(0,("Failed to read data in readbraw\n"));
	      exit(1);
	    }
	    dataptr = cli->inbuf;
	  }
	  break;

	case 3:
	  /* we've already read some data with a chained readX */
	  break;

	default:
	  /* use plain read */

	cli_set_smb_cmd(cli, t_idx,  SMBread, 5,0,True);

	  SSVAL(cli->outbuf,smb_vwv0,fnum);
	  SSVAL(cli->outbuf,smb_vwv1,MIN(cli->max_xmit-200,finfo.size - nread));
	  SIVAL(cli->outbuf,smb_vwv2,nread);
	  SSVAL(cli->outbuf,smb_vwv4,finfo.size - nread);

  send_smb(cli->fd,cli->outbuf);
  if (!receive_smb(cli->fd, cli->inbuf, cli->timeout)) break;
  if (cli_error(cli,  NULL, NULL)) break;

	  datalen = SVAL(cli->inbuf,smb_vwv0);
	  dataptr = smb_buf(cli->inbuf) + 3;
	  break;
	}
 
      if (write_fn(info, handle,dataptr,datalen) != datalen)
	{
	  DEBUG(0,("Error writing local file\n"));
	  break;
	}
      
      nread += datalen;
      if (datalen == 0) 
	{
	  DEBUG(0,("Error reading file %s. Got %d bytes\n",CNV_LANG(rname),nread));
	  break;
	}

      dataptr=NULL;
      datalen=0;
    }

    if (end_fn)
	{
       end_fn(info, handle, cli->inbuf, nread, &finfo);
    }

  if (!close_done)
    {

      cli_close(cli, t_idx,  fnum, 0);
      
      if (!ignore_close_error && cli_error(cli,  NULL, NULL))
	{
	  DEBUG(0,("Error %s closing remote file\n",cli_errstr(cli)));
	  return 0;
	}
    }

	{
		struct timeval tar_tp_end;
		int this_time;

		GetTimeOfDay(&tar_tp_end);
		this_time = 
		(tar_tp_end.tv_sec - tar_tp_start.tv_sec)*1000 +
		(tar_tp_end.tv_usec - tar_tp_start.tv_usec)/1000;
		info->get_total_time_ms += this_time;
		info->get_total_size    += nread;

		/* Thanks to Carel-Jan Engel (ease@mail.wirehub.nl) for this one */
		DEBUG(1,("(%g kb/s) (average %g kb/s)\n",
			nread                / MAX(0.001, (1.024*this_time)),
			info->get_total_size / MAX(0.001,(1.024*info->get_total_time_ms))));
	}

  return nread;
}

/****************************************************************************
check for existance of a dir
****************************************************************************/
BOOL cli_chkpath(struct cli_state *cli, int t_idx, char *path)
{
	fstring path2;
	char *p;

	strcpy(path2,path);
	trim_string(path2,NULL,"\\");
	if (!*path2) *path2 = '\\';

	cli_set_smb_cmd(cli, t_idx,  SMBchkpth, 0,4 + strlen(path2),True);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	strcpy(p,path2);

#if 0
	{
	/* this little bit of code can be used to extract NT error codes.
	   Just feed a bunch of "cd foo" commands to smbclient then watch
	   in netmon (tridge)
	 */
		static int code=0;
		SIVAL(outbuf, smb_rcls, code | 0xC0000000);
		SSVAL(outbuf, smb_flg2, SVAL(outbuf, smb_flg2) | (1<<14));
		code++;
	}
#endif

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
	{
		return False;
	}

    if (cli_error(cli, NULL, NULL)) return False;

	return True;
}


/****************************************************************************
check the space on a device
****************************************************************************/
BOOL cli_dskattr(struct cli_state *cli, int t_idx,
				uint16 *num_blocks, uint32 *block_size, uint16 *free_blocks)
{
	cli_set_smb_cmd(cli, t_idx,  SMBdskattr, 0,0,True);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
    if (cli_error(cli, NULL, NULL)) return False;

	*num_blocks  = SVAL(cli->inbuf,smb_vwv0);
	*block_size  = SVAL(cli->inbuf,smb_vwv1) * SVAL(cli->inbuf,smb_vwv2);
	*free_blocks = SVAL(cli->inbuf,smb_vwv3);

	return True;
}

/****************************************************************************
make a directory of name "name"
****************************************************************************/
BOOL cli_mkdir(struct cli_state *cli, int t_idx, char *name)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBmkdir, 0,2 + strlen(name),True);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p,name);
  
	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
    if (cli_error(cli, NULL, NULL)) return False;

	return(True);
}


/****************************************************************************
rename some files
****************************************************************************/
BOOL cli_move(struct cli_state *cli, int t_idx, char *src, char *dest)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBmv, 1, 4 + strlen(src) + strlen(dest),True);

	SSVAL(cli->outbuf,smb_vwv0,aHIDDEN | aDIR | aSYSTEM);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p,src);
	p = skip_string(p,1);
	*p++ = 4;      
	strcpy(p,dest);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
    if (cli_error(cli, NULL, NULL)) return False;

	return(True);
}

/****************************************************************************
Get DOS file attributes
***************************************************************************/
BOOL cli_getatr(struct cli_state *cli, int t_idx, char *fname,
				uint8 *fattr, uint16 *ftime, uint16 *fsize)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBgetatr, 0,2 + strlen(fname),True);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	strcpy(p,fname);
	p += (strlen(fname)+1);

	*p++ = 4;
	*p++ = 0; /* zero this, due to byte-alignment issues... */

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL)) return False;

	if (fattr) (*fattr) = CVAL(cli->inbuf,smb_vwv0);
	if (ftime) (*ftime) = SVAL(cli->inbuf,smb_vwv1);
	if (fsize) (*fsize) = SVAL(cli->inbuf,smb_vwv3);

	if (fattr && ftime && fsize)
	{
		DEBUG(5,("SMBgetatr attr:0x%X time:%d  size:%d\n",
				*fattr, *ftime, *fsize));
	}

	return(True);
}


/****************************************************************************
Set DOS file attributes
***************************************************************************/
BOOL cli_setatr(struct cli_state *cli, int t_idx, char *fname,
				uint8 fattr, uint16 write_time)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBsetatr, 8,4 + strlen(fname),True);

	SSVAL(cli->outbuf,smb_vwv0, fattr);
	SSVAL(cli->outbuf,smb_vwv1, write_time); /* zero indicates no change */
	/* all the other 6 words are reserved, so says cifs6.txt... */

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p,fname);
	p += (strlen(fname)+1);

	*p++ = 4;
	*p++ = 0; /* zero this, due to byte-alignment issues... */

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL)) return False;

	return(True);
}


/****************************************************************************
Create a file on a share
***************************************************************************/
BOOL cli_create(struct cli_state *cli, int t_idx,
				char *name, uint16 file_mode, uint16 make_time, uint16 *fnum)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBcreate, 3,2 + strlen(name),True);

	SSVAL(cli->outbuf,smb_vwv0,file_mode);
	put_dos_date3(cli->outbuf,smb_vwv1,make_time);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	strcpy(p, name);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return False;
	if (cli_error(cli,  NULL, NULL)) return False;

	*fnum = SVAL(cli->inbuf,smb_vwv0);
	return True;
}

/****************************************************************************
open a file
****************************************************************************/
uint16 cli_open(struct cli_state *cli, int t_idx, char *fname, int flags, int share_mode,
			uint16 *fmode, time_t *mtime, uint32 *fsize)
{
	char *p;
	unsigned openfn=0;
	unsigned accessmode=0;
	uint16 fnum;

	if (flags & O_CREAT)
		openfn |= (1<<4);

	if (!(flags & O_EXCL))
	{
		if (flags & O_TRUNC)
			openfn |= (1<<1);
		else
			openfn |= (1<<0);
	}

	accessmode = (share_mode<<4);

	if ((flags & O_RDWR) == O_RDWR) {
		accessmode |= 2;
	} else if ((flags & O_WRONLY) == O_WRONLY) {
		accessmode |= 1;
	} 

	cli_set_smb_cmd(cli, t_idx,  SMBopenX, 15,1 + strlen(fname),True);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,1);  /* return additional info */
	SSVAL(cli->outbuf,smb_vwv3,accessmode);
	SSVAL(cli->outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
	SSVAL(cli->outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
	SSVAL(cli->outbuf,smb_vwv8,openfn);
	SSVAL(cli->outbuf,smb_vwv11,0xffff);
	SSVAL(cli->outbuf,smb_vwv12,0xffff);
  
	p = smb_buf(cli->outbuf);
	strcpy(p,fname);
	p = skip_string(p,1);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return 0xffff;
    if (cli_error(cli,  NULL, NULL)) return 0xffff;

	fnum                = SVAL(cli->inbuf,smb_vwv2);

    if (fmode) (*fmode) = SVAL(cli->inbuf,smb_vwv3);
    if (mtime) (*mtime) = make_unix_date3(cli->inbuf+smb_vwv4);
    if (fsize) (*fsize) = IVAL(cli->inbuf,smb_vwv6);

	DEBUG(5,("cli_open: opening fnum:%04x\n", fnum));

	return fnum;
}




/****************************************************************************
  close a file
****************************************************************************/
BOOL cli_close(struct cli_state *cli, int t_idx, uint16 fnum, time_t close_time)
{
	cli_set_smb_cmd(cli, t_idx,  SMBclose, 3,0,True); 

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	put_dos_date3(cli->outbuf,smb_vwv1, close_time);
	SSVAL(cli->outbuf,smb_vwv2,0);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

    if (cli_error(cli, NULL, NULL)) return False;

	return True;
}


/****************************************************************************
  lock a file
****************************************************************************/
BOOL cli_lock(struct cli_state *cli, int t_idx, uint16 fnum, uint32 offset, uint32 len, int timeout)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBlockingX, 8,10,True);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	CVAL(cli->outbuf,smb_vwv3) = 0;
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

    if (cli_error(cli, NULL, NULL)) return False;

	return True;
}

/****************************************************************************
  unlock a file
****************************************************************************/
BOOL cli_unlock(struct cli_state *cli, int t_idx, uint16 fnum, uint32 offset, uint32 len, int timeout)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBlockingX, 8,10,True);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	CVAL(cli->outbuf,smb_vwv3) = 0;
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

    if (cli_error(cli, NULL, NULL)) return False;

	return True;
}


/****************************************************************************
  read from a file
****************************************************************************/
int cli_readx(struct cli_state *cli, int t_idx, uint16 fnum, char *buf, uint32 offset, uint16 size)
{
	char *p;

	cli_set_smb_cmd(cli, t_idx,  SMBreadX, 10,0,True);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SIVAL(cli->outbuf,smb_vwv3,offset);
	SSVAL(cli->outbuf,smb_vwv5,size);
	SSVAL(cli->outbuf,smb_vwv6,size);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return -1;
	}

    if (cli_error(cli, NULL, NULL)) return -1;

	size = SVAL(cli->inbuf, smb_vwv5);
	p = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);

	memcpy(buf, p, size);

	return size;
}


/*******************************************************************
  write to a file using writebraw
  ********************************************************************/
int cli_writeraw(struct cli_state *cli, int t_idx, uint16 fnum,int pos,char *buf,int n)
{
	DEBUG(5,("cli_write_raw: [%04x] %d %d\n", fnum, pos, n));

	cli_set_smb_cmd(cli, t_idx,  SMBwritebraw, cli->protocol>PROTOCOL_COREPLUS?12:10,0,True);

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	SSVAL(cli->outbuf,smb_vwv1,n);
	SIVAL(cli->outbuf,smb_vwv3,pos);
	SSVAL(cli->outbuf,smb_vwv7,1);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return -1;
    if (cli_error(cli, NULL, NULL)) return -1;

	/* direct write */
	_smb_setlen(buf-4,n);		/* HACK! XXXX */
	if (write_socket(cli->fd,buf-4,n+4) != n+4) return(0);

	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return -1;

	return(SVAL(cli->inbuf,smb_vwv0));
}
      


/*******************************************************************
  write to a file
  ********************************************************************/
int cli_write(struct cli_state *cli, int t_idx, uint16 fnum,int pos,char *buf,int n)
{
	int len;

	if (cli->writebraw_supported && n > (cli->max_xmit-200)) 
	{
		return(cli_writeraw(cli, t_idx,  fnum, pos, buf, n));
	}

	cli_set_smb_cmd(cli, t_idx,  SMBwrite, 5,n + 3,True);

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	SSVAL(cli->outbuf,smb_vwv1,n);
	SIVAL(cli->outbuf,smb_vwv2,pos);
	SSVAL(cli->outbuf,smb_vwv4,0);
	CVAL(smb_buf(cli->outbuf),0) = 1;
	SSVAL(smb_buf(cli->outbuf),1,n);

	memcpy(smb_buf(cli->outbuf)+3,buf,n);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return -1;
    if (cli_error(cli, NULL, NULL)) return -1;

	len = SVAL(cli->inbuf,smb_vwv0);

	DEBUG(5,("cli_write: [%04x] offset:%ld req:%d ret:%d\n",
				fnum, pos, n, len));

	return len;
}
      


/****************************************************************************
  write to a file
****************************************************************************/
int cli_write_x(struct cli_state *cli, int t_idx, uint16 fnum, char *buf, uint32 offset, uint16 size)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	cli_set_smb_cmd(cli, t_idx,  SMBwriteX, 12,size,True);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SIVAL(cli->outbuf,smb_vwv3,offset);

	SSVAL(cli->outbuf,smb_vwv10,size);
	SSVAL(cli->outbuf,smb_vwv11,smb_buf(cli->outbuf) - smb_base(cli->outbuf));

	p = smb_base(cli->outbuf) + SVAL(cli->outbuf,smb_vwv11);
	memcpy(p, buf, size);

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout)) return -1;
    if (cli_error(cli, NULL, NULL)) return -1;

	return SVAL(cli->inbuf, smb_vwv2);
}

/****************************************************************************
send a negprot command
****************************************************************************/
BOOL cli_negprot(struct cli_state *cli)
{
	char *p;
	int numprots;
	int plength;

	bzero(cli->outbuf,smb_size);

	DEBUG(3,("cli_negprot\n"));

	if (cli->num_tcons != 0)
	{
		DEBUG(2,("cli_negprot: connections appear to be already open\n"));
		return False;
	}

	/* setup the protocol strings */
	for (plength=0,numprots=0;
	     prots[numprots].name && prots[numprots].prot<=cli->protocol;
	     numprots++)
		plength += strlen(prots[numprots].name)+2;
    
	set_message(cli->outbuf,0,plength,True);

	p = smb_buf(cli->outbuf);
	for (numprots=0;
	     prots[numprots].name && prots[numprots].prot<=cli->protocol;
	     numprots++) {
		*p++ = 2;
		strcpy(p,prots[numprots].name);
		p += strlen(p) + 1;
	}

	CVAL(cli->outbuf,smb_com) = SMBnegprot;
	cli_setup_packet(cli);

	CVAL(smb_buf(cli->outbuf),0) = 2;

	send_smb(cli->fd,cli->outbuf);
	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

	show_msg(cli->inbuf);

    if (cli_error(cli, NULL, NULL)) return False;
	if ((int)SVAL(cli->inbuf,smb_vwv0) >= numprots) return(False);

	cli->protocol = prots[SVAL(cli->inbuf,smb_vwv0)].prot;


	if (cli->protocol < PROTOCOL_NT1) {    
		cli->sec_mode = SVAL(cli->inbuf,smb_vwv1);
		cli->max_xmit = SVAL(cli->inbuf,smb_vwv2);
		cli->sesskey = IVAL(cli->inbuf,smb_vwv6);
		cli->serverzone = SVALS(cli->inbuf,smb_vwv10)*60;
		/* this time is converted to GMT by make_unix_date */
		cli->servertime = make_unix_date(cli->inbuf+smb_vwv8);
		if (cli->protocol >= PROTOCOL_COREPLUS) {
			cli->readbraw_supported = ((SVAL(cli->inbuf,smb_vwv5) & 0x1) != 0);
			cli->writebraw_supported = ((SVAL(cli->inbuf,smb_vwv5) & 0x2) != 0);
		}
		memcpy(cli->cryptkey,smb_buf(cli->inbuf),8);
	} else {
		/* NT protocol */
		cli->sec_mode = CVAL(cli->inbuf,smb_vwv1);
		cli->max_xmit = IVAL(cli->inbuf,smb_vwv3+1);
		cli->sesskey = IVAL(cli->inbuf,smb_vwv7+1);
		cli->serverzone = SVALS(cli->inbuf,smb_vwv15+1)*60;
		/* this time arrives in real GMT */
		cli->servertime = interpret_long_date(cli->inbuf+smb_vwv11+1);
		memcpy(cli->cryptkey,smb_buf(cli->inbuf),8);
		if (IVAL(cli->inbuf,smb_vwv9+1) & 1)
			cli->readbraw_supported = 
				cli->writebraw_supported = True;      
	}

	DEBUG(5,("cli_negprot: secmode:%x\n", cli->sec_mode));

	return True;
}

#define TRUNCATE_NETBIOS_NAME 1

/****************************************************************************
  send a session request.  see rfc1002.txt 4.3 and 4.3.2
****************************************************************************/
BOOL cli_session_request(struct cli_state *cli,
			char *called_host_name        , int called_name_type,
			char  calling_netbios_name[16], int calling_name_type)
{
	char *p;
	int len = 4;
	/* send a session request (RFC 1002) */

	strncpy(cli->called_netbios_name , called_host_name    , sizeof(cli->called_netbios_name ));
	strncpy(cli->calling_netbios_name, calling_netbios_name, sizeof(cli->calling_netbios_name));
  
	/* sorry, don't trust strncpy to null-terminate the string... */
	cli->called_netbios_name [sizeof(cli->called_netbios_name )-1] = 0;
	cli->calling_netbios_name[sizeof(cli->calling_netbios_name)-1] = 0;

#ifdef TRUNCATE_NETBIOS_NAME
	/* ok.  this is because of a stupid microsoft-ism.  if the called host
	   name contains a '.', microsoft clients expect you to truncate the
	   netbios name up to and including the '.'
	 */
	p = strchr(cli->called_netbios_name, '.');
	if (p) *p = 0;
#endif /* TRUNCATE_NETBIOS_NAME */

	/* put in the destination name */
	p = cli->outbuf+len;
	name_mangle(cli->called_netbios_name, p, called_name_type);
	len += name_len(p);

	/* and my name */
	p = cli->outbuf+len;
	name_mangle(cli->calling_netbios_name, p, calling_name_type);
	len += name_len(p);

	/* setup the packet length */
	_smb_setlen(cli->outbuf,len);
	CVAL(cli->outbuf,0) = 0x81;

	send_smb(cli->fd,cli->outbuf);
	DEBUG(5,("Sent session request\n"));

	if (!receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

	if (CVAL(cli->inbuf,0) != 0x82) {
		cli->error = CVAL(cli->inbuf,0);
		return False;
	}
	return(True);
}


/****************************************************************************
open the client sockets
****************************************************************************/
BOOL cli_connect(struct cli_state *cli, char *host, struct in_addr *ip)
{
	struct in_addr dest_ip;

	fstrcpy(cli->full_dest_host_name, host);
	
	if (!ip || zero_ip(*ip))
	{
		/* no ip specified - look up the name */
		struct hostent *hp;

		if ((hp = Get_Hostbyname(host)) == 0) {
			return False;
		}

		putip((char *)&dest_ip,(char *)hp->h_addr);
	} else {
		/* use the given ip address */
		dest_ip = *ip;
	}

	/* open the socket */
	cli->fd = open_socket_out(SOCK_STREAM, &dest_ip, 139, cli->timeout);

	return (cli->fd != -1);
}


/****************************************************************************
initialise a client structure
****************************************************************************/
BOOL cli_initialise(struct cli_state *cli)
{
	int i;
	if (cli->initialised) cli_shutdown(cli);

	memset(cli, 0, sizeof(*cli));
	cli->fd = -1;

	for (i = 0; i < MAX_CLIENT_CONNECTIONS; i++)
	{
		cli->con[i].cnum = -1;
	}
	cli->num_tcons = 0;

	cli->pid = getpid();
	cli->mid = 1;
	cli->uid = getuid();
	cli->protocol = PROTOCOL_NT1;
	cli->timeout = 20000;
	cli->bufsize = 0x10000;
	cli->max_xmit = cli->bufsize - 4;
	cli->outbuf = (char *)malloc(cli->bufsize);
	cli->inbuf = (char *)malloc(cli->bufsize);
	if (!cli->outbuf || !cli->inbuf) return False;
	cli->initialised = 1;
	return True;
}

/****************************************************************************
shutdown a client structure
****************************************************************************/
void cli_shutdown(struct cli_state *cli)
{
	if (cli->outbuf) free(cli->outbuf);
	if (cli->inbuf) free(cli->inbuf);
	if (cli->fd != -1) close(cli->fd);
	memset(cli, 0, sizeof(*cli));
}

/****************************************************************************
  return a description of the error
****************************************************************************/
char *cli_errstr(struct cli_state *cli)
{
	return smb_errstr(cli->inbuf);
}

/****************************************************************************
  return error codes for the last packet
****************************************************************************/
BOOL cli_error(struct cli_state *cli, uint8 *eclass, uint32 *num)
{
	int  flgs2 = SVAL(cli->inbuf,smb_flg2);

	if (eclass) *eclass = 0;
	if (num   ) *num = 0;

	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES)
	{
		/* 32 bit error codes detected */
		uint32 nt_err = IVAL(cli->inbuf,smb_rcls);
		if (num) *num = nt_err;
		return (nt_err != 0);
	}
	else
	{
		/* dos 16 bit error codes detected */
		char rcls  = CVAL(cli->inbuf,smb_rcls);
		if (rcls != 0)
		{
			if (eclass) *eclass = rcls;
			if (num   ) *num    = SVAL(cli->inbuf,smb_err);
			return True;
		}
	}
	return False;
}

/****************************************************************************
set socket options on a open connection
****************************************************************************/
void cli_sockopt(struct cli_state *cli, char *options)
{
	set_socket_options(cli->fd, options);
}

/****************************************************************************
set the MID to use for smb messages. Return the old MID.
****************************************************************************/
int cli_setmid(struct cli_state *cli, int mid)
{
	int ret = cli->mid;
	cli->mid = mid;
	return ret;
}

/****************************************************************************
set the PID to use for smb messages. Return the old pid.
****************************************************************************/
int cli_setpid(struct cli_state *cli, int pid)
{
	int ret = cli->pid;
	cli->pid = pid;
	return ret;
}


/****************************************************************************
establishes a connection right up to doing tconX, reading in a password.
****************************************************************************/
BOOL cli_establish_connection(struct cli_state *cli, int *t_idx,
				char *dest_host, uint8 name_type, struct in_addr *dest_ip,
				char *my_hostname,
				char *passwd_report,
				char *username, char *user_pass, char *workgroup,
				char *service, char *service_type,
				BOOL do_shutdown, BOOL do_tcon, BOOL encrypted)
{
	fstring passwd;
	int pass_len = 0;

	if (passwd_report != NULL && (user_pass == NULL || user_pass[0] == 0))
	{
		/* grab a password */
		user_pass = (char*)getpass(passwd_report);
	}

	if (user_pass != NULL && user_pass[0] != 0)
	{
		fstrcpy(passwd, user_pass);
		pass_len = strlen(passwd);
	}
	else
	{
		passwd[0] = 0;
		pass_len = 1;
	}

	/* establish connection */

	if (!cli_initialise(cli))
	{
		DEBUG(1,("failed to initialise client connection\n"));
		return False;
	}

	if (!cli_connect(cli, dest_host, dest_ip))
	{
		DEBUG(1,("failed to connect to %s (%s)\n", dest_host, inet_ntoa(*dest_ip)));
		return False;
	}

	if (!cli_session_request(cli, dest_host, name_type, my_hostname, 0x0))
	{
		DEBUG(1,("failed session request\n"));
		if (do_shutdown) cli_shutdown(cli);
		return False;
	}

	if (!cli_negprot(cli))
	{
		DEBUG(1,("failed negprot\n"));
		if (do_shutdown) cli_shutdown(cli);
		return False;
	}

	/* attempt encrypted session; attempt clear-text session */
	if (encrypted && user_pass)
	{
		uchar lm_owf_passwd[16];
		uchar nt_owf_passwd[16];
		uchar lm_sess_pwd[24];
		uchar nt_sess_pwd[24];

		nt_lm_owf_gen(passwd, nt_owf_passwd, lm_owf_passwd);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("client cryptkey: "));
		dump_data(100, cli->cryptkey, sizeof(cli->cryptkey));
#endif

		SMBOWFencrypt(nt_owf_passwd, cli->cryptkey, nt_sess_pwd);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("nt_owf_passwd: "));
		dump_data(100, nt_owf_passwd, sizeof(lm_owf_passwd));
		DEBUG(100,("nt_sess_pwd: "));
		dump_data(100, nt_sess_pwd, sizeof(nt_sess_pwd));
#endif

		SMBOWFencrypt(lm_owf_passwd, cli->cryptkey, lm_sess_pwd);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("lm_owf_passwd: "));
		dump_data(100, lm_owf_passwd, sizeof(lm_owf_passwd));
		DEBUG(100,("lm_sess_pwd: "));
		dump_data(100, lm_sess_pwd, sizeof(lm_sess_pwd));
#endif
		/* attempt encrypted session */
		if (!cli_session_setup(cli, username,
	                       lm_owf_passwd, sizeof(lm_owf_passwd),
	                       nt_owf_passwd, sizeof(nt_owf_passwd),
	                       workgroup))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown) cli_shutdown(cli);
			return False;
		}
		if (do_tcon)
		{
			if (!cli_send_tconX(cli, t_idx,  service, service_type,
			                    nt_owf_passwd, sizeof(nt_owf_passwd)))
			{
				DEBUG(1,("failed tcon_X\n"));
				if (do_shutdown) cli_shutdown(cli);
				return False;
			}
		}
	}
	else
	{
		/* attempt clear-text session */
		if (!cli_session_setup(cli, username,
	                       passwd, pass_len,
	                       "", 0,
	                       workgroup))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown) cli_shutdown(cli);
			return False;
		}
		if (do_tcon)
		{
			if (!cli_send_tconX(cli, t_idx,  service, service_type,
			                    passwd, pass_len))
			{
				DEBUG(1,("failed tcon_X\n"));
				if (do_shutdown) cli_shutdown(cli);
				return False;
			}
		}
	}

	if (do_shutdown) cli_shutdown(cli);

	return True;
}


