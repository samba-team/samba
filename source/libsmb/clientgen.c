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
	/* there might have been an error on the socket */
	if (cli->fd == -1) return False;

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

	/* if the server is not responding, then note that now */
	if (!ret) {
		close(cli->fd);
		cli->fd = -1;
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

	/* there might have been an error on the socket */
	if (cli->fd == -1) return False;

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
			close(cli->fd);
			cli->fd = -1;
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

