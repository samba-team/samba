/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client RAP calls
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


/****************************************************************************
Call a remote api on an arbitrary pipe.  takes param, data and setup buffers.
****************************************************************************/
BOOL cli_api_pipe(struct cli_state *cli, const char *pipe_name, 
                  uint16 *setup, uint32 setup_count, uint32 max_setup_count,
                  char *params, uint32 param_count, uint32 max_param_count,
                  char *data, uint32 data_count, uint32 max_data_count,
                  char **rparam, uint32 *rparam_count,
                  char **rdata, uint32 *rdata_count)
{
  cli_send_trans(cli, SMBtrans, 
                 pipe_name, 
                 0,0,                         /* fid, flags */
                 setup, setup_count, max_setup_count,
                 params, param_count, max_param_count,
                 data, data_count, max_data_count);

  return (cli_receive_trans(cli, SMBtrans, 
                            rparam, (unsigned int *)rparam_count,
                            rdata, (unsigned int *)rdata_count));
}

/****************************************************************************
call a remote api
****************************************************************************/
BOOL cli_api(struct cli_state *cli,
	     char *param, int prcnt, int mprcnt,
	     char *data, int drcnt, int mdrcnt,
	     char **rparam, unsigned int *rprcnt,
	     char **rdata, unsigned int *rdrcnt)
{
  cli_send_trans(cli,SMBtrans,
                 PIPE_LANMAN,             /* Name */
                 0,0,                     /* fid, flags */
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
		cli->rap_error = rparam? SVAL(rparam,0) : -1;
		p = rdata;
		
		if (cli->rap_error == 0) {
			DEBUG(4,("NetWkstaUserLogon success\n"));
			cli->privileges = SVAL(p, 24);
			fstrcpy(cli->eff_name,p+2);
		} else {
			DEBUG(1,("NetwkstaUserLogon gave error %d\n", cli->rap_error));
		}
	}
	
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);
	return (cli->rap_error == 0);
}

/****************************************************************************
call a NetShareEnum - try and browse available connections on a host
****************************************************************************/
int cli_RNetShareEnum(struct cli_state *cli, void (*fn)(const char *, uint32, const char *, void *), void *state)
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
			int res = rparam? SVAL(rparam,0) : -1;
			
			if (res == 0 || res == ERRmoredata) {
				int converter=SVAL(rparam,2);
				int i;
				
				count=SVAL(rparam,4);
				p = rdata;
				
				for (i=0;i<count;i++,p+=20) {
					char *sname = p;
					int type = SVAL(p,14);
					int comment_offset = IVAL(p,16) & 0xFFFF;
					const char *cmnt = comment_offset?(rdata+comment_offset-converter):"";
					pstring s1, s2;

					pstrcpy(s1, dos_to_unix_static(sname));
					pstrcpy(s2, dos_to_unix_static(cmnt));

					fn(s1, type, s2, state);
				}
			} else {
				DEBUG(4,("NetShareEnum res=%d\n", res));
			}      
		} else {
			DEBUG(4,("NetShareEnum failed\n"));
		}
  
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);
	
	return count;
}


/****************************************************************************
call a NetServerEnum for the specified workgroup and servertype mask.  This
function then calls the specified callback function for each name returned.

The callback function takes 4 arguments: the machine name, the server type,
the comment and a state pointer.
****************************************************************************/
BOOL cli_NetServerEnum(struct cli_state *cli, char *workgroup, uint32 stype,
		       void (*fn)(const char *, uint32, const char *, void *),
		       void *state)
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

	p += clistr_push(cli, p, workgroup, -1,
		STR_TERMINATE | STR_CONVERT | STR_ASCII);

	if (cli_api(cli, 
                    param, PTR_DIFF(p,param), 8,        /* params, length, max */
                    NULL, 0, CLI_BUFFER_SIZE,               /* data, length, max */
                    &rparam, &rprcnt,                   /* return params, return size */
                    &rdata, &rdrcnt                     /* return data, return size */
                   )) {
		int res = rparam? SVAL(rparam,0) : -1;
			
		if (res == 0 || res == ERRmoredata) {
			int i;
			int converter=SVAL(rparam,2);

			count=SVAL(rparam,4);
			p = rdata;
					
			for (i = 0;i < count;i++, p += 26) {
				char *sname = p;
				int comment_offset = (IVAL(p,22) & 0xFFFF)-converter;
				const char *cmnt = comment_offset?(rdata+comment_offset):"";
				pstring s1, s2;

				if (comment_offset < 0 || comment_offset > rdrcnt) continue;

				stype = IVAL(p,18) & ~SV_TYPE_LOCAL_LIST_ONLY;

				pstrcpy(s1, dos_to_unix_static(sname));
				pstrcpy(s2, dos_to_unix_static(cmnt));
				fn(s1, stype, s2, state);
			}
		}
	}
  
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);
	
	return(count > 0);
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
  unsigned int data_len;
  unsigned int param_len = 0;
  char *rparam = NULL;
  char *rdata = NULL;
  int rprcnt, rdrcnt;
  pstring dos_new_password;

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
  clistr_push(cli, upper_case_old_pw, old_password, -1,STR_CONVERT|STR_TERMINATE|STR_UPPER|STR_ASCII);
  E_P16((uchar *)upper_case_old_pw, old_pw_hash);

  clistr_push(cli, dos_new_password, new_password, -1, STR_CONVERT|STR_TERMINATE|STR_ASCII);

  if (!make_oem_passwd_hash( data, dos_new_password, old_pw_hash, False))
    return False;

  /* 
   * Now place the old password hash in the data.
   */
  memset(upper_case_new_pw, '\0', sizeof(upper_case_new_pw));
  clistr_push(cli, upper_case_new_pw, new_password, -1, STR_CONVERT|STR_TERMINATE|STR_UPPER|STR_ASCII);

  E_P16((uchar *)upper_case_new_pw, new_pw_hash);

  E_old_pw_hash( new_pw_hash, old_pw_hash, (uchar *)&data[516]);

  data_len = 532;
    
  if (cli_send_trans(cli,SMBtrans,
                    PIPE_LANMAN,                          /* name */
                    0,0,                                  /* fid, flags */
                    NULL,0,0,                             /* setup, length, max */
                    param,param_len,2,                    /* param, length, max */
                    data,data_len,0                       /* data, length, max */
                   ) == False) {
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

  SAFE_FREE(rparam);
  SAFE_FREE(rdata);

  return (cli->rap_error == 0);
}


/****************************************************************************
send a qpathinfo call
****************************************************************************/
BOOL cli_qpathinfo(struct cli_state *cli, const char *fname, 
		   time_t *c_time, time_t *a_time, time_t *m_time, 
		   size_t *size, uint16 *mode)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_QPATHINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;
	int count=8;
	BOOL ret;
	time_t (*date_fn)(void *);
	char *p;

	p = param;
	memset(p, 0, 6);
	SSVAL(p, 0, SMB_INFO_STANDARD);
	p += 6;
	p += clistr_push(cli, p, fname, sizeof(pstring)-6, STR_TERMINATE|STR_CONVERT );

	param_len = PTR_DIFF(p, param);

	do {
		ret = (cli_send_trans(cli, SMBtrans2, 
				      NULL,           /* Name */
				      -1, 0,          /* fid, flags */
				      &setup, 1, 0,   /* setup, length, max */
				      param, param_len, 10, /* param, length, max */
				      NULL, data_len, cli->max_xmit /* data, length, max */
				      ) &&
		       cli_receive_trans(cli, SMBtrans2, 
					 &rparam, &param_len,
					 &rdata, &data_len));
		if (!ret && cli_is_dos_error(cli)) {
			/* we need to work around a Win95 bug - sometimes
			   it gives ERRSRV/ERRerror temprarily */
			uint8 eclass;
			uint32 ecode;
			cli_dos_error(cli, &eclass, &ecode);
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

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);
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
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_QPATHINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;
	char *p;

	p = param;
	memset(p, 0, 6);
	SSVAL(p, 0, SMB_QUERY_FILE_ALL_INFO);
	p += 6;
	p += clistr_push(cli, p, fname, sizeof(pstring)-6, STR_TERMINATE|STR_CONVERT );

	param_len = PTR_DIFF(p, param);

	if (!cli_send_trans(cli, SMBtrans2, 
                            NULL,                         /* name */
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
		*size = IVAL(rdata, 48);
	}
	if (ino) {
		*ino = IVAL(rdata, 64);
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);
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
	unsigned int data_len = 0;
	unsigned int param_len = 0;
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
                            NULL,                           /* name */
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
		*size = IVAL(rdata, 48);
	}
	if (ino) {
		*ino = IVAL(rdata, 64);
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);
	return True;
}

/****************************************************************************
send a qfileinfo call
****************************************************************************/
BOOL cli_qfileinfo_test(struct cli_state *cli, int fnum, int level, char *outdata)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_QFILEINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;

	/* if its a win95 server then fail this - win95 totally screws it
	   up */
	if (cli->win95) return False;

	param_len = 4;

	memset(param, 0, param_len);
	SSVAL(param, 0, fnum);
	SSVAL(param, 2, level);

	if (!cli_send_trans(cli, SMBtrans2, 
                            NULL,                           /* name */
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

	memcpy(outdata, rdata, data_len);

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);
	return True;
}

/****************************************************************************
 Send a qpathinfo SMB_QUERY_FILE_ALT_NAME_INFO call.
****************************************************************************/

NTSTATUS cli_qpathinfo_alt_name(struct cli_state *cli, const char *fname, fstring alt_name)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16 setup = TRANSACT2_QPATHINFO;
	pstring param;
	char *rparam=NULL, *rdata=NULL;
	int count=8;
	char *p;
	BOOL ret;
	int len;

	p = param;
	memset(p, 0, 6);
	SSVAL(p, 0, SMB_QUERY_FILE_ALT_NAME_INFO);
	p += 6;
	p += clistr_push(cli, p, fname, sizeof(pstring)-6, STR_TERMINATE|STR_CONVERT);

	param_len = PTR_DIFF(p, param);

	do {
		ret = (cli_send_trans(cli, SMBtrans2, 
				      NULL,           /* Name */
				      -1, 0,          /* fid, flags */
				      &setup, 1, 0,   /* setup, length, max */
				      param, param_len, 10, /* param, length, max */
				      NULL, data_len, cli->max_xmit /* data, length, max */
				      ) &&
		       cli_receive_trans(cli, SMBtrans2, 
					 &rparam, &param_len,
					 &rdata, &data_len));
		if (!ret && cli_is_dos_error(cli)) {
			/* we need to work around a Win95 bug - sometimes
			   it gives ERRSRV/ERRerror temprarily */
			uint8 eclass;
			uint32 ecode;
			cli_dos_error(cli, &eclass, &ecode);
			if (eclass != ERRSRV || ecode != ERRerror) break;
			msleep(100);
		}
	} while (count-- && ret==False);

	if (!ret || !rdata || data_len < 4) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	len = IVAL(rdata, 0);

	if (len > data_len - 4) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	clistr_pull(cli, alt_name, rdata+4, sizeof(fstring), len, 0);

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return NT_STATUS_OK;
}
