/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1998
   
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
#include "trans2.h"


extern int DEBUGLEVEL;

/*****************************************************
 RAP error codes - a small start but will be extended.
*******************************************************/

struct
{
  int err;
  char *message;
} rap_errmap[] =
{
  {5,    "User has insufficient privilege" },
  {86,   "The specified password is invalid" },
  {2226, "Operation only permitted on a Primary Domain Controller"  },
  {2242, "The password of this user has expired." },
  {2243, "The password of this user cannot change." },
  {2244, "This password cannot be used now (password history conflict)." },
  {2245, "The password is shorter than required." },
  {2246, "The password of this user is too recent to change."},
  {0, NULL}
};  

/****************************************************************************
  return a description of an SMB error
****************************************************************************/
static char *cli_smb_errstr(struct cli_state *cli)
{
	return smb_errstr(cli->inbuf);
}

/******************************************************
 Return an error message - either an SMB error or a RAP
 error.
*******************************************************/
    
char *cli_errstr(struct cli_state *cli)
{   
  static fstring error_message;
  int errclass;
  int errnum;
  int i;      
      
  /*  
   * Errors are of three kinds - smb errors,
   * dealt with by cli_smb_errstr, NT errors,
   * whose code is in cli.nt_error, and rap
   * errors, whose error code is in cli.rap_error.
   */ 

  cli_error(cli, &errclass, &errnum);
  if(errclass != 0)
    return cli_smb_errstr(cli);

  /*
   * Was it an NT error ?
   */

  if(cli->nt_error) {
    char *nt_msg = get_nt_error_msg(cli->nt_error);

    if(nt_msg == NULL)
      slprintf(error_message, sizeof(fstring) - 1, "NT code %d", cli->nt_error);
    else
      fstrcpy(error_message, nt_msg);

    return error_message;
  }

  /*
   * Must have been a rap error.
   */

  slprintf(error_message, sizeof(error_message) - 1, "code %d", cli->rap_error);
    
  for(i = 0; rap_errmap[i].message != NULL; i++) {
    if (rap_errmap[i].err == cli->rap_error) {
      fstrcpy( error_message, rap_errmap[i].message);
      break;
    }
  } 
  
  return error_message;
}

/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
static void cli_setup_packet(struct cli_state *cli)
{
        cli->rap_error = 0;
        cli->nt_error = 0;
	SSVAL(cli->outbuf,smb_pid,cli->pid);
	SSVAL(cli->outbuf,smb_uid,cli->uid);
	SSVAL(cli->outbuf,smb_mid,cli->mid);
	if (cli->protocol > PROTOCOL_CORE) {
		SCVAL(cli->outbuf,smb_flg,0x8);
		SSVAL(cli->outbuf,smb_flg2,0x1);
	}
}


/****************************************************************************
  send a SMB trans or trans2 request
  ****************************************************************************/
static BOOL cli_send_trans(struct cli_state *cli, int trans, 
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

	bzero(cli->outbuf,smb_size);
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
	send_smb(cli->fd,cli->outbuf);

	if (this_ldata < ldata || this_lparam < lparam) {
		/* receive interim response */
		if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout) || 
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
static BOOL cli_receive_trans(struct cli_state *cli,int trans,
                              char **param, int *param_len,
                              char **data, int *data_len)
{
	int total_data=0;
	int total_param=0;
	int this_data,this_param;
	
	*data_len = *param_len = 0;
	
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

	show_msg(cli->inbuf);
	
	/* sanity check */
	if (CVAL(cli->inbuf,smb_com) != trans) {
		DEBUG(0,("Expected %s response, got command 0x%02x\n",
			 trans==SMBtrans?"SMBtrans":"SMBtrans2", 
			 CVAL(cli->inbuf,smb_com)));
		return(False);
	}
	if (CVAL(cli->inbuf,smb_rcls) != 0)
		return(False);

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
		
		if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
			return False;

		show_msg(cli->inbuf);
		
		/* sanity check */
		if (CVAL(cli->inbuf,smb_com) != trans) {
			DEBUG(0,("Expected %s response, got command 0x%02x\n",
				 trans==SMBtrans?"SMBtrans":"SMBtrans2", 
				 CVAL(cli->inbuf,smb_com)));
			return(False);
		}
		if (CVAL(cli->inbuf,smb_rcls) != 0)
			return(False);
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
  if(pipe_name_len == 0)
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
	p += 21; p++; p += 15; p++; 
	pstrcpy(p, workstation); 
	strupper(p);
	p += 16;
	SSVAL(p, 0, BUFFER_SIZE);
	p += 2;
	SSVAL(p, 0, BUFFER_SIZE);
	p += 2;
	
	if (cli_api(cli, 
                    param, PTR_DIFF(p,param),1024,  /* param, length, max */
                    NULL, 0, BUFFER_SIZE,           /* data, length, max */
                    &rparam, &rprcnt,               /* return params, return size */
                    &rdata, &rdrcnt                 /* return data, return size */
                   )) {
		cli->rap_error = SVAL(rparam,0);
		p = rdata;
		
		if (cli->rap_error == 0) {
			DEBUG(4,("NetWkstaUserLogon success\n"));
			cli->privilages = SVAL(p, 24);
			fstrcpy(cli->eff_name,p+2);
		} else {
			DEBUG(1,("NetwkstaUserLogon gave error %d\n", cli->rap_error));
		}
	}
	
	if (rparam) free(rparam);
	if (rdata) free(rdata);
	return (cli->rap_error == 0);
}

#if UNUSED_CODE
/****************************************************************************
call a NetShareEnum - try and browse available connections on a host
****************************************************************************/
BOOL cli_RNetShareEnum(struct cli_state *cli, void (*fn)(char *, uint32, char *))
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
  SSVAL(p,2,BUFFER_SIZE);
  p += 4;

  if (cli_api(cli, 
              param, PTR_DIFF(p,param), 1024,  /* Param, length, maxlen */
              NULL, 0, BUFFER_SIZE,            /* data, length, maxlen */
              &rparam, &rprcnt,                /* return params, length */
              &rdata, &rdrcnt))                /* return data, length */
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);
      int i;
      
      if (res == 0)
	{
	  count=SVAL(rparam,4);
	  p = rdata;

	  for (i=0;i<count;i++,p+=20)
	    {
	      char *sname = p;
	      int type = SVAL(p,14);
	      int comment_offset = IVAL(p,16) & 0xFFFF;
	      char *cmnt = comment_offset?(rdata+comment_offset-converter):"";
	      fn(sname, type, cmnt);
	    }
	}
    }
  
  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return(count>0);
}
#endif

/****************************************************************************
call a NetServerEnum for the specified workgroup and servertype mask.
This function then calls the specified callback function for each name returned.

The callback function takes 3 arguments: the machine name, the server type and
the comment.
****************************************************************************/
BOOL cli_NetServerEnum(struct cli_state *cli, char *workgroup, uint32 stype,
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
	pstrcpy(p,"WrLehDz");
	p = skip_string(p,1);
  
	pstrcpy(p,"B16BBDz");
  
	p = skip_string(p,1);
	SSVAL(p,0,uLevel);
	SSVAL(p,2,BUFFER_SIZE);
	p += 4;
	SIVAL(p,0,stype);
	p += 4;
	
	pstrcpy(p, workgroup);
	p = skip_string(p,1);
	
	if (cli_api(cli, 
                    param, PTR_DIFF(p,param), 8,        /* params, length, max */
                    NULL, 0, BUFFER_SIZE,               /* data, length, max */
                    &rparam, &rprcnt,                   /* return params, return size */
                    &rdata, &rdrcnt                     /* return data, return size */
                   )) {
		int res = SVAL(rparam,0);
		int converter=SVAL(rparam,2);
		int i;
			
		if (res == 0) {
			count=SVAL(rparam,4);
			p = rdata;
					
			for (i = 0;i < count;i++, p += 26) {
				char *sname = p;
				int comment_offset = (IVAL(p,22) & 0xFFFF)-converter;
				char *cmnt = comment_offset?(rdata+comment_offset):"";
				if (comment_offset < 0 || comment_offset > rdrcnt) continue;

				stype = IVAL(p,18) & ~SV_TYPE_LOCAL_LIST_ONLY;

				fn(sname, stype, cmnt);
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
      {PROTOCOL_NT1,"NT LM 0.12"},
      {PROTOCOL_NT1,"NT LANMAN 1.0"},
      {-1,NULL}
    };


/****************************************************************************
send a session setup
****************************************************************************/
BOOL cli_session_setup(struct cli_state *cli, 
		       char *user, 
		       char *pass, int passlen,
		       char *ntpass, int ntpasslen,
		       char *workgroup)
{
	char *p;
	fstring pword;

	if (cli->protocol < PROTOCOL_LANMAN1)
		return True;

	if (passlen > sizeof(pword)-1) {
		return False;
	}

        if(((passlen == 0) || (passlen == 1)) && (pass[0] == '\0')) {
          /* Null session connect. */
          pword[0] = '\0';
        } else {
          if ((cli->sec_mode & 2) && passlen != 24) {
            passlen = 24;
            SMBencrypt((uchar *)pass,(uchar *)cli->cryptkey,(uchar *)pword);
          } else {
            memcpy(pword, pass, passlen);
          }
        }

	/* if in share level security then don't send a password now */
	if (!(cli->sec_mode & 1)) {fstrcpy(pword, "");passlen=1;} 

	/* send a session setup command */
	bzero(cli->outbuf,smb_size);

	if (cli->protocol < PROTOCOL_NT1) {
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
		pstrcpy(p,user);
		strupper(p);
	} else {
		set_message(cli->outbuf,13,0,True);
		CVAL(cli->outbuf,smb_com) = SMBsesssetupX;
		cli_setup_packet(cli);
		
		CVAL(cli->outbuf,smb_vwv0) = 0xFF;
		SSVAL(cli->outbuf,smb_vwv2,BUFFER_SIZE);
		SSVAL(cli->outbuf,smb_vwv3,2);
		SSVAL(cli->outbuf,smb_vwv4,cli->pid);
		SIVAL(cli->outbuf,smb_vwv5,cli->sesskey);
		SSVAL(cli->outbuf,smb_vwv7,passlen);
		SSVAL(cli->outbuf,smb_vwv8,ntpasslen);
		p = smb_buf(cli->outbuf);
		memcpy(p,pword,passlen); 
		p += SVAL(cli->outbuf,smb_vwv7);
		memcpy(p,ntpass,ntpasslen); 
		p += SVAL(cli->outbuf,smb_vwv8);
		pstrcpy(p,user);
		strupper(p);
		p = skip_string(p,1);
		pstrcpy(p,workgroup);
		strupper(p);
		p = skip_string(p,1);
		pstrcpy(p,"Unix");p = skip_string(p,1);
		pstrcpy(p,"Samba");p = skip_string(p,1);
		set_message(cli->outbuf,13,PTR_DIFF(p,smb_buf(cli->outbuf)),False);
	}

      send_smb(cli->fd,cli->outbuf);
      if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
	      return False;

      show_msg(cli->inbuf);

      if (CVAL(cli->inbuf,smb_rcls) != 0) {
	      return False;
      }

      /* use the returned uid from now on */
      cli->uid = SVAL(cli->inbuf,smb_uid);

      return True;
}

/****************************************************************************
 Send a uloggoff.
*****************************************************************************/

BOOL cli_ulogoff(struct cli_state *cli)
{
        bzero(cli->outbuf,smb_size);
        set_message(cli->outbuf,2,0,True);
        CVAL(cli->outbuf,smb_com) = SMBulogoffX;
        cli_setup_packet(cli);
	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,0);  /* no additional info */

        send_smb(cli->fd,cli->outbuf);
        if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
                return False;

        return CVAL(cli->inbuf,smb_rcls) == 0;
}

/****************************************************************************
send a tconX
****************************************************************************/
BOOL cli_send_tconX(struct cli_state *cli, 
		    char *share, char *dev, char *pass, int passlen)
{
	fstring fullshare, pword;
	char *p;
	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	if (cli->sec_mode & 1) {
		passlen = 1;
		pass = "";
	}

	if ((cli->sec_mode & 2) && *pass && passlen != 24) {
		passlen = 24;
		SMBencrypt((uchar *)pass,(uchar *)cli->cryptkey,(uchar *)pword);
	} else {
		memcpy(pword, pass, passlen);
	}

	slprintf(fullshare, sizeof(fullshare)-1,
		 "\\\\%s\\%s", cli->desthost, share);

	set_message(cli->outbuf,4,
		    2 + strlen(fullshare) + passlen + strlen(dev),True);
	CVAL(cli->outbuf,smb_com) = SMBtconX;
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv3,passlen);

	p = smb_buf(cli->outbuf);
	memcpy(p,pword,passlen);
	p += passlen;
	fstrcpy(p,fullshare);
	p = skip_string(p,1);
	pstrcpy(p,dev);

	SCVAL(cli->inbuf,smb_rcls, 1);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	cli->cnum = SVAL(cli->inbuf,smb_tid);
	return True;
}


/****************************************************************************
send a tree disconnect
****************************************************************************/
BOOL cli_tdis(struct cli_state *cli)
{
	bzero(cli->outbuf,smb_size);
	set_message(cli->outbuf,0,0,True);
	CVAL(cli->outbuf,smb_com) = SMBtdis;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	
	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;
	
	return CVAL(cli->inbuf,smb_rcls) == 0;
}

#if UNUSED_CODE
/****************************************************************************
rename a file
****************************************************************************/
BOOL cli_mv(struct cli_state *cli, char *fname_src, char *fname_dst)
{
        char *p;

        bzero(cli->outbuf,smb_size);
        bzero(cli->inbuf,smb_size);

        set_message(cli->outbuf,1, 4 + strlen(fname_src) + strlen(fname_dst), True);

        CVAL(cli->outbuf,smb_com) = SMBmv;
        SSVAL(cli->outbuf,smb_tid,cli->cnum);
        cli_setup_packet(cli);

        SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN);

        p = smb_buf(cli->outbuf);
        *p++ = 4;
        pstrcpy(p,fname_src);
        p = skip_string(p,1);
        *p++ = 4;
        pstrcpy(p,fname_dst);

        send_smb(cli->fd,cli->outbuf);
        if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
                return False;
        }

        if (CVAL(cli->inbuf,smb_rcls) != 0) {
                return False;
        }

        return True;
}
#endif

/****************************************************************************
delete a file
****************************************************************************/
BOOL cli_unlink(struct cli_state *cli, char *fname)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,1, 2 + strlen(fname),True);

	CVAL(cli->outbuf,smb_com) = SMBunlink;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,aSYSTEM | aHIDDEN);
  
	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	pstrcpy(p,fname);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}


/****************************************************************************
create a directory
****************************************************************************/
BOOL cli_mkdir(struct cli_state *cli, char *dname)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,0, 2 + strlen(dname),True);

	CVAL(cli->outbuf,smb_com) = SMBmkdir;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	pstrcpy(p,dname);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
remove a directory
****************************************************************************/
BOOL cli_rmdir(struct cli_state *cli, char *dname)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,0, 2 + strlen(dname),True);

	CVAL(cli->outbuf,smb_com) = SMBrmdir;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p++ = 4;      
	pstrcpy(p,dname);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}



/****************************************************************************
open a file
****************************************************************************/
int cli_open(struct cli_state *cli, char *fname, int flags, int share_mode)
{
	char *p;
	unsigned openfn=0;
	unsigned accessmode=0;

	if (flags & O_CREAT)
		openfn |= (1<<4);
	if (!(flags & O_EXCL)) {
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

#if defined(O_SYNC)
	if ((flags & O_SYNC) == O_SYNC) {
		accessmode |= (1<<14);
	}
#endif /* O_SYNC */

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

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
  
	p = smb_buf(cli->outbuf);
	pstrcpy(p,fname);
	p = skip_string(p,1);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
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
	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,3,0,True);

	CVAL(cli->outbuf,smb_com) = SMBclose;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,fnum);
	SIVALS(cli->outbuf,smb_vwv1,-1);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
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
BOOL cli_lock(struct cli_state *cli, int fnum, uint32 offset, uint32 len, int timeout)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,8,10,True);

	CVAL(cli->outbuf,smb_com) = SMBlockingX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

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
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}

/****************************************************************************
  unlock a file
****************************************************************************/
BOOL cli_unlock(struct cli_state *cli, int fnum, uint32 offset, uint32 len, int timeout)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,8,10,True);

	CVAL(cli->outbuf,smb_com) = SMBlockingX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

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
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	return True;
}


/****************************************************************************
  read from a file
****************************************************************************/
int cli_read(struct cli_state *cli, int fnum, char *buf, uint32 offset, uint16 size)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,10,0,True);

	CVAL(cli->outbuf,smb_com) = SMBreadX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SIVAL(cli->outbuf,smb_vwv3,offset);
	SSVAL(cli->outbuf,smb_vwv5,size);
	SSVAL(cli->outbuf,smb_vwv6,size);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return -1;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return -1;
	}

	size = SVAL(cli->inbuf, smb_vwv5);
	p = smb_base(cli->inbuf) + SVAL(cli->inbuf,smb_vwv6);

	memcpy(buf, p, size);

	return size;
}


/****************************************************************************
  write to a file
****************************************************************************/
int cli_write(struct cli_state *cli, int fnum, char *buf, uint32 offset, uint16 size)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,12,size,True);

	CVAL(cli->outbuf,smb_com) = SMBwriteX;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	CVAL(cli->outbuf,smb_vwv0) = 0xFF;
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SIVAL(cli->outbuf,smb_vwv3,offset);

	SSVAL(cli->outbuf,smb_vwv10,size);
	SSVAL(cli->outbuf,smb_vwv11,smb_buf(cli->outbuf) - smb_base(cli->outbuf));

	p = smb_base(cli->outbuf) + SVAL(cli->outbuf,smb_vwv11);
	memcpy(p, buf, size);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
		return -1;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return -1;
	}

	return SVAL(cli->inbuf, smb_vwv2);
}


/****************************************************************************
do a SMBgetatr call
****************************************************************************/
BOOL cli_getatr(struct cli_state *cli, char *fname, 
		int *attr, uint32 *size, time_t *t)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,0,strlen(fname)+2,True);

	CVAL(cli->outbuf,smb_com) = SMBgetatr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	p = smb_buf(cli->outbuf);
	*p = 4;
	pstrcpy(p+1, fname);

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
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
BOOL cli_setatr(struct cli_state *cli, char *fname, int attr, time_t t)
{
	char *p;

	bzero(cli->outbuf,smb_size);
	bzero(cli->inbuf,smb_size);

	set_message(cli->outbuf,8,strlen(fname)+4,True);

	CVAL(cli->outbuf,smb_com) = SMBsetatr;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0, attr);
	put_dos_date3(cli->outbuf,smb_vwv1, t);

	p = smb_buf(cli->outbuf);
	*p = 4;
	pstrcpy(p+1, fname);
	p = skip_string(p,1);
	*p = 4;

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout)) {
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
BOOL cli_qpathinfo(struct cli_state *cli, char *fname, 
		   time_t *c_time, time_t *a_time, time_t *m_time, uint32 *size)
{
	int data_len = 0;
	int param_len = 0;
	uint16 setup = TRANSACT2_QPATHINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;

	param_len = strlen(fname) + 7;

	memset(param, 0, param_len);
	SSVAL(param, 0, SMB_INFO_STANDARD);
	pstrcpy(&param[6], fname);

	if (!cli_send_trans(cli, SMBtrans2, 
                            NULL, 0,                      /* Name, length */
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
		*c_time = make_unix_date2(rdata+0);
	}
	if (a_time) {
		*a_time = make_unix_date2(rdata+4);
	}
	if (m_time) {
		*m_time = make_unix_date2(rdata+8);
	}
	if (size) {
		*size = IVAL(rdata, 12);
	}

	if (rdata) free(rdata);
	if (rparam) free(rparam);
	return True;
}

/****************************************************************************
send a qpathinfo call with the SMB_QUERY_FILE_ALL_INFO info level
****************************************************************************/
BOOL cli_qpathinfo2(struct cli_state *cli, char *fname, 
		    time_t *c_time, time_t *a_time, time_t *m_time, 
		    time_t *w_time, uint32 *size)
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
	if (size) {
		*size = IVAL(rdata, 40);
	}

	if (rdata) free(rdata);
	if (rparam) free(rparam);
	return True;
}


/****************************************************************************
send a qfileinfo call
****************************************************************************/
BOOL cli_qfileinfo(struct cli_state *cli, int fnum, 
		   time_t *c_time, time_t *a_time, time_t *m_time, uint32 *size)
{
	int data_len = 0;
	int param_len = 0;
	uint16 setup = TRANSACT2_QFILEINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;

	param_len = 4;

	memset(param, 0, param_len);
	SSVAL(param, 0, fnum);
	SSVAL(param, 2, SMB_INFO_STANDARD);

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

	if (!rdata || data_len < 22) {
		return False;
	}

	if (c_time) {
		*c_time = make_unix_date2(rdata+0);
	}
	if (a_time) {
		*a_time = make_unix_date2(rdata+4);
	}
	if (m_time) {
		*m_time = make_unix_date2(rdata+8);
	}
	if (size) {
		*size = IVAL(rdata, 12);
	}

	if (rdata) free(rdata);
	if (rparam) free(rparam);
	return True;
}

/****************************************************************************
Send a SamOEMChangePassword command
****************************************************************************/

BOOL cli_oem_change_password(struct cli_state *cli, char *user, char *new_password,
                             char *old_password)
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
  int new_pw_len = strlen(new_password);
  char *rparam = NULL;
  char *rdata = NULL;
  int rprcnt, rdrcnt;

  if(strlen(user) >= sizeof(fstring)-1) {
    DEBUG(0,("cli_oem_change_password: user name %s is too long.\n", user));
    return False;
  }

  if(new_pw_len > 512) {
    DEBUG(0,("cli_oem_change_password: new password for user %s is too long.\n", user));
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
   * Now setup the data area.
   * We need to generate a random fill
   * for this area to make it harder to
   * decrypt. JRA.
   */
  generate_random_buffer((unsigned char *)data, sizeof(data), False);
  fstrcpy( &data[512 - new_pw_len], new_password);
  SIVAL(data, 512, new_pw_len);

  /*
   * Get the Lanman hash of the old password, we
   * use this as the key to SamOEMHash().
   */
  memset(upper_case_old_pw, '\0', sizeof(upper_case_old_pw));
  fstrcpy(upper_case_old_pw, old_password);
  strupper(upper_case_old_pw);
  E_P16((uchar *)upper_case_old_pw, old_pw_hash);

  SamOEMhash( (unsigned char *)data, (unsigned char *)old_pw_hash, True);

  /* 
   * Now place the old password hash in the data.
   */
  memset(upper_case_new_pw, '\0', sizeof(upper_case_new_pw));
  fstrcpy(upper_case_new_pw, new_password);
  strupper(upper_case_new_pw);

  E_P16((uchar *)upper_case_new_pw, new_pw_hash);

  E_old_pw_hash( new_pw_hash, old_pw_hash, (uchar *)&data[516]);

  data_len = 532;
    
  if(cli_send_trans(cli,SMBtrans,
                    PIPE_LANMAN,strlen(PIPE_LANMAN),      /* name, length */
                    0,0,                                  /* fid, flags */
                    NULL,0,0,                             /* setup, length, max */
                    param,param_len,2,                    /* param, length, max */
                    data,data_len,0                       /* data, length, max */
                   ) == False) {
    DEBUG(0,("cli_oem_change_password: Failed to send password change for user %s\n",
              user ));
    return False;
  }

  if(cli_receive_trans(cli,SMBtrans,
                       &rparam, &rprcnt,
                       &rdata, &rdrcnt)) {
    if(rparam)
      cli->rap_error = SVAL(rparam,0);
  }

  if (rparam)
    free(rparam);
  if (rdata)
    free(rdata);

  return (cli->rap_error == 0);
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
		pstrcpy(p,prots[numprots].name);
		p += strlen(p) + 1;
	}

	CVAL(cli->outbuf,smb_com) = SMBnegprot;
	cli_setup_packet(cli);

	CVAL(smb_buf(cli->outbuf),0) = 2;

	send_smb(cli->fd,cli->outbuf);
	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

	show_msg(cli->inbuf);

	if (CVAL(cli->inbuf,smb_rcls) != 0 || 
	    ((int)SVAL(cli->inbuf,smb_vwv0) >= numprots)) {
		return(False);
	}

	cli->protocol = prots[SVAL(cli->inbuf,smb_vwv0)].prot;


	if (cli->protocol >= PROTOCOL_NT1) {    
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
	} else if (cli->protocol >= PROTOCOL_LANMAN1) {
		cli->sec_mode = SVAL(cli->inbuf,smb_vwv1);
		cli->max_xmit = SVAL(cli->inbuf,smb_vwv2);
		cli->sesskey = IVAL(cli->inbuf,smb_vwv6);
		cli->serverzone = SVALS(cli->inbuf,smb_vwv10)*60;
		/* this time is converted to GMT by make_unix_date */
		cli->servertime = make_unix_date(cli->inbuf+smb_vwv8);
		cli->readbraw_supported = ((SVAL(cli->inbuf,smb_vwv5) & 0x1) != 0);
		cli->writebraw_supported = ((SVAL(cli->inbuf,smb_vwv5) & 0x2) != 0);
		memcpy(cli->cryptkey,smb_buf(cli->inbuf),8);
	} else {
		/* the old core protocol */
		cli->sec_mode = 0;
		cli->serverzone = TimeDiff(time(NULL));
	}

	return True;
}


/****************************************************************************
  send a session request.  see rfc1002.txt 4.3 and 4.3.2
****************************************************************************/
BOOL cli_session_request(struct cli_state *cli,
			struct nmb_name *calling, struct nmb_name *called)
{
	char *p;
	int len = 4;
	/* send a session request (RFC 1002) */

	memcpy(&(cli->calling), calling, sizeof(*calling));
	memcpy(&(cli->called ), called , sizeof(*called ));
  
	/* put in the destination name */
	p = cli->outbuf+len;
	name_mangle(cli->called .name, p, cli->called .name_type);
	len += name_len(p);

	/* and my name */
	p = cli->outbuf+len;
	name_mangle(cli->calling.name, p, cli->calling.name_type);
	len += name_len(p);

	/* setup the packet length */
	_smb_setlen(cli->outbuf,len);
	CVAL(cli->outbuf,0) = 0x81;

#ifdef WITH_SSL
retry:
#endif /* WITH_SSL */

	send_smb(cli->fd,cli->outbuf);
	DEBUG(5,("Sent session request\n"));

	if (!client_receive_smb(cli->fd,cli->inbuf,cli->timeout))
		return False;

#ifdef WITH_SSL
    if(CVAL(cli->inbuf,0) == 0x83 && CVAL(cli->inbuf,4) == 0x8e){ /* use ssl */
        if(!sslutil_fd_is_ssl(cli->fd)){
            if(sslutil_connect(cli->fd) == 0)
                goto retry;
        }
    }
#endif /* WITH_SSL */

	if (CVAL(cli->inbuf,0) != 0x82) {
                /* This is the wrong place to put the error... JRA. */
		cli->rap_error = CVAL(cli->inbuf,0);
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
	extern struct in_addr ipzero;

	fstrcpy(cli->desthost, host);
	
	if (!ip || ip_equal(*ip, ipzero)) {
                if(!resolve_name( cli->desthost, &dest_ip)) {
                        return False;
                }
	} else {
		dest_ip = *ip;
	}


	cli->fd = open_socket_out(SOCK_STREAM, &dest_ip, 139, cli->timeout);
	if (cli->fd == -1)
		return False;

	return True;
}


/****************************************************************************
initialise a client structure
****************************************************************************/
BOOL cli_initialise(struct cli_state *cli)
{
	if (cli->initialised) cli_shutdown(cli);

	memset(cli, 0, sizeof(*cli));
	cli->fd = -1;
	cli->cnum = -1;
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
#ifdef WITH_SSL
    if (cli->fd != -1) sslutil_disconnect(cli->fd);
#endif /* WITH_SSL */
	if (cli->fd != -1) close(cli->fd);
	memset(cli, 0, sizeof(*cli));
}

/****************************************************************************
  return error codes for the last packet
****************************************************************************/
void cli_error(struct cli_state *cli, int *eclass, int *num)
{
	*eclass = CVAL(cli->inbuf,smb_rcls);
	*num = SVAL(cli->inbuf,smb_err);
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
int cli_setpid(struct cli_state *cli, int pid)
{
	int ret = cli->pid;
	cli->pid = pid;
	return ret;
}

/****************************************************************************
establishes a connection right up to doing tconX, reading in a password.
****************************************************************************/
BOOL cli_reestablish_connection(struct cli_state *cli)
{
	struct nmb_name calling;
	struct nmb_name called;
	fstring dest_host;
	struct in_addr dest_ip;
	fstring share;
	fstring dev;
	BOOL do_tcon = False;

	if (!cli->initialised || cli->fd == -1)
	{
		DEBUG(3,("cli_reestablish_connection: not connected\n"));
		return False;
	}

	/* copy the parameters necessary to re-establish the connection */

	if (cli->cnum != 0)
	{
		fstrcpy(share, cli->share);
		fstrcpy(dev  , cli->dev);
		do_tcon = True;
	}

	memcpy(&called , &(cli->called ), sizeof(called ));
	memcpy(&calling, &(cli->calling), sizeof(calling));
	fstrcpy(dest_host, cli->full_dest_host_name);
	dest_ip = cli->dest_ip;

	DEBUG(5,("cli_reestablish_connection: %s connecting to %s (ip %s) - %s [%s]\n",
		          namestr(&calling), namestr(&called), inet_ntoa(dest_ip),
	              cli->user_name, cli->domain));

	return cli_establish_connection(cli,
	                                dest_host, &dest_ip,
	                                &calling, &called,
	                                share, dev, False, do_tcon);
}

/****************************************************************************
establishes a connection right up to doing tconX, reading in a password.
****************************************************************************/
BOOL cli_establish_connection(struct cli_state *cli, 
				char *dest_host, struct in_addr *dest_ip,
				struct nmb_name *calling, struct nmb_name *called,
				char *service, char *service_type,
				BOOL do_shutdown, BOOL do_tcon)
{
	DEBUG(5,("cli_establish_connection: %s connecting to %s (%s) - %s [%s]\n",
		          namestr(calling), namestr(called), inet_ntoa(*dest_ip),
	              cli->user_name, cli->domain));

	/* establish connection */

	if ((!cli->initialised))
	{
		return False;
	}

	if (cli->fd == -1)
	{
		if (!cli_connect(cli, dest_host, dest_ip))
		{
			DEBUG(1,("cli_establish_connection: failed to connect to %s (%s)\n",
					  namestr(calling), inet_ntoa(*dest_ip)));
			return False;
		}
	}

	if (!cli_session_request(cli, calling, called))
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

	if (cli->pwd.cleartext || cli->pwd.null_pwd)
	{
		/* attempt clear-text session */

		fstring passwd;

		pwd_get_cleartext(&(cli->pwd), passwd);

		/* attempt clear-text session */
		if (!cli_session_setup(cli, cli->user_name,
	                       passwd, strlen(passwd),
	                       NULL, 0,
	                       cli->domain))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown) cli_shutdown(cli);
			return False;
		}
		if (do_tcon)
		{
			if (!cli_send_tconX(cli, service, service_type,
			                    (char*)passwd, strlen(passwd)))
			{
				DEBUG(1,("failed tcon_X\n"));
				if (do_shutdown) cli_shutdown(cli);
				return False;
			}
		}
	}
	else
	{
		/* attempt encrypted session */
		char nt_sess_pwd[24];
		char lm_sess_pwd[24];

		/* creates (storing a copy of) and then obtains a 24 byte password OWF */
		pwd_make_lm_nt_owf(&(cli->pwd), cli->cryptkey);
		pwd_get_lm_nt_owf(&(cli->pwd), lm_sess_pwd, nt_sess_pwd);

		/* attempt encrypted session */
		if (!cli_session_setup(cli, cli->user_name,
	                       (char*)lm_sess_pwd, sizeof(lm_sess_pwd),
	                       (char*)nt_sess_pwd, sizeof(nt_sess_pwd),
	                       cli->domain))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown) cli_shutdown(cli);
			return False;
		}

		if (do_tcon)
		{
			if (!cli_send_tconX(cli, service, service_type,
			                    (char*)nt_sess_pwd, sizeof(nt_sess_pwd)))
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
