/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client message handling routines
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
start a message sequence
****************************************************************************/
BOOL cli_message_start(struct cli_state *cli, char *host, char *username, 
			      int *grp)
{
	char *p;

	/* send a SMBsendstrt command */
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,0,True);
	CVAL(cli->outbuf,smb_com) = SMBsendstrt;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	
	p = smb_buf(cli->outbuf);
	*p++ = 4;
	pstrcpy(p,username);
	unix_to_dos(p,True);
	p = skip_string(p,1);
	*p++ = 4;
	pstrcpy(p,host);
	unix_to_dos(p,True);
	p = skip_string(p,1);
	
	set_message(cli->outbuf,0,PTR_DIFF(p,smb_buf(cli->outbuf)),False);
	
	cli_send_smb(cli);	
	
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_error(cli, NULL, NULL, NULL)) return False;

	*grp = SVAL(cli->inbuf,smb_vwv0);

	return True;
}


/****************************************************************************
send a message 
****************************************************************************/
BOOL cli_message_text(struct cli_state *cli, char *msg, int len, int grp)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,1,len+3,True);
	CVAL(cli->outbuf,smb_com) = SMBsendtxt;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,grp);
	
	p = smb_buf(cli->outbuf);
	*p = 1;
	SSVAL(p,1,len);
	memcpy(p+3,msg,len);
	cli_send_smb(cli);

	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_error(cli, NULL, NULL, NULL)) return False;

	return True;
}      

/****************************************************************************
end a message 
****************************************************************************/
BOOL cli_message_end(struct cli_state *cli, int grp)
{
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,1,0,True);
	CVAL(cli->outbuf,smb_com) = SMBsendend;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);

	SSVAL(cli->outbuf,smb_vwv0,grp);

	cli_setup_packet(cli);
	
	cli_send_smb(cli);

	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_error(cli, NULL, NULL, NULL)) return False;

	return True;
}      

