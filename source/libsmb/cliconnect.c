/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client connect/disconnect routines
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

extern pstring user_socket_options;


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
****************************************************************************/
BOOL cli_session_setup_x(struct cli_state *cli, 
				char *user, 
				char *pass, int passlen,
				char *ntpass, int ntpasslen,
				char *user_domain)
{
	uint8 eclass;
	uint32 ecode;
	char *p;
	BOOL esec = IS_BITS_SET_ALL(cli->capabilities, CAP_EXTENDED_SECURITY);

	DEBUG(100,("cli_session_setup.  extended security: %s\n",
	            BOOLSTR(esec)));

#ifdef DEBUG_PASSWORD
	DEBUG(100,("cli_session_setup.  pass, ntpass\n"));
	dump_data(100, pass, passlen);
	dump_data(100, ntpass, ntpasslen);
#endif

	if (cli->protocol < PROTOCOL_LANMAN1)
	{
		return True;
	}

	/* send a session setup command */
	memset(cli->outbuf,'\0',smb_size);

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
		memcpy(p,pass,passlen);
		p += passlen;
		pstrcpy(p,user);
		unix_to_dos(p,True);
		strupper(p);
	}
	else if (esec)
	{
		set_message(cli->outbuf,12,0,True);
		CVAL(cli->outbuf,smb_com) = SMBsesssetupX;
		cli_setup_packet(cli);
		
		CVAL(cli->outbuf,smb_vwv0) = 0xFF;
		SSVAL(cli->outbuf,smb_vwv2,CLI_BUFFER_SIZE);
		SSVAL(cli->outbuf,smb_vwv3,2);
		SSVAL(cli->outbuf,smb_vwv4,cli->pid);
		SIVAL(cli->outbuf,smb_vwv5,cli->sesskey);
		SSVAL(cli->outbuf,smb_vwv7,passlen);
		SIVAL(cli->outbuf,smb_vwv10, CAP_EXTENDED_SECURITY|CAP_STATUS32|CAP_UNICODE);
		p = smb_buf(cli->outbuf);
		memcpy(p,pass,passlen); 
		p += passlen;

		pstrcpy(p, "Unix"); p = skip_string(p, 1);
		pstrcpy(p, "Samba"); p = skip_string(p, 1);
		pstrcpy(p, ""); p = skip_string(p, 1);
		p++;
		
		set_message(cli->outbuf,12,PTR_DIFF(p,smb_buf(cli->outbuf)),False);
	}
	else 
	{
		set_message(cli->outbuf,13,0,True);
		CVAL(cli->outbuf,smb_com) = SMBsesssetupX;
		cli_setup_packet(cli);
		
		CVAL(cli->outbuf,smb_vwv0) = 0xFF;
		SSVAL(cli->outbuf,smb_vwv2,CLI_BUFFER_SIZE);
		SSVAL(cli->outbuf,smb_vwv3,2);
		SSVAL(cli->outbuf,smb_vwv4,cli->pid);
		SIVAL(cli->outbuf,smb_vwv5,cli->sesskey);
		SSVAL(cli->outbuf,smb_vwv7,passlen);
		SSVAL(cli->outbuf,smb_vwv8,ntpasslen);
		SIVAL(cli->outbuf,smb_vwv11, 0);
		p = smb_buf(cli->outbuf);
		memcpy(p,pass,passlen); 
		p += SVAL(cli->outbuf,smb_vwv7);
		memcpy(p,ntpass,ntpasslen); 
		p += SVAL(cli->outbuf,smb_vwv8);
		strupper(user);
		pstrcpy(p, user); p = skip_string(p, 1);
		strupper(user_domain);
		pstrcpy(p, user_domain); p = skip_string(p, 1);
		pstrcpy(p, "Unix"); p = skip_string(p, 1);
		p++;
		pstrcpy(p, "Samba"); p = skip_string(p, 1);
		
		set_message(cli->outbuf,13,PTR_DIFF(p,smb_buf(cli->outbuf)),False);
	}

	cli_send_smb(cli);
	if (!cli_receive_smb(cli))
	{
		DEBUG(10,("cli_session_setup_x: receive smb failed\n"));
	      return False;
	}

	if (cli_error(cli, &eclass, &ecode))
	{
		uint16 flgs2 = SVAL(cli->inbuf,smb_flg2);
		if (IS_BITS_CLR_ALL(flgs2, FLAGS2_32_BIT_ERROR_CODES))
		{
			if (ecode != ERRmoredata || !esec)
			{
				return False;
			}
		}
		else if (ecode != 0xC0000016) /* STATUS_MORE_PROCESSING_REQD */
		{
			return False;
		}
	}

	/* use the returned vuid from now on */
	cli->vuid = SVAL(cli->inbuf,smb_uid);

	if (cli->protocol >= PROTOCOL_NT1)
	{
		if (esec)
		{
		}
		else
		{
			/*
			 * Save off some of the connected server
			 * info.
			 */
			char *server_domain;
			char *server_os;
			char *server_type;

			server_os = smb_buf(cli->inbuf);
			server_type = skip_string(server_os,1);
			server_domain = skip_string(server_type,1);

			fstrcpy(cli->server_os, server_os);
		dos_to_unix(cli->server_os, True);
			fstrcpy(cli->server_type, server_type);
		dos_to_unix(cli->server_type, True);
			fstrcpy(cli->server_domain, server_domain);
		dos_to_unix(cli->server_domain, True);
		}
      }

      return True;
}

static BOOL cli_calc_session_pwds(struct cli_state *cli,
				char *my_hostname,
				char *pword, char *ntpword,
				char *pass, int *passlen,
				char *ntpass, int *ntpasslen,
				char *sess_key,
				BOOL ntlmv2)
{
	BOOL ntpass_ok = ntpass != NULL && ntpasslen != NULL;

	if (pass == NULL || passlen == NULL)
	{
		DEBUG(0,("cli_calc_session_pwds: pass and passlen are NULL\n"));
		return False;
	}
	if ((ntpass != NULL || ntpasslen != NULL) &&
	    (ntpass == NULL || ntpasslen == NULL))
	{
		DEBUG(0,("cli_calc_session_pwds: ntpasswd pointers invalid\n"));
		return False;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100,("cli_calc_session_pwds.  pass, ntpass\n"));
	dump_data(100, pass, *passlen);
	if (ntpass_ok)
	{
		dump_data(100, ntpass, *ntpasslen);
	}
#endif
	if (!IS_BITS_SET_ALL(cli->sec_mode, 1))
	{
		/* if in share level security then don't send a password now */
		pword[0] = '\0';
		*passlen=1;
		if (ntpass_ok)
		{
			ntpword[0] = '\0';
			*ntpasslen=1;
		}
		return True;
	} 
	else if ((*passlen == 0 || *passlen == 1) && (pass[0] == '\0'))
	{
		/* Null session connect. */
		pword  [0] = '\0';
		if (ntpass_ok)
		{
			ntpword[0] = '\0';
			*ntpasslen=0;
		}

		return True;
	}

	if (!ntpass_ok)
	{
		return False;
	}

	if (*passlen == 24 && *ntpasslen >= 24)
	{
		if (IS_BITS_SET_ALL(cli->sec_mode, 2))
		{
			/* encrypted password, implicit from 24-byte lengths */
			memcpy(pword  , pass  , *passlen);
			memcpy(ntpword, ntpass, *ntpasslen);
		}
		else
		{
			DEBUG(0,("cli_calc_session_pwds: encrypted passwords not supported by server\n"));
			return False;
		}
	}
	else if (*ntpasslen == 0 || !IS_BITS_SET_ALL(cli->sec_mode, 2))
	{
		/* plain-text password: server doesn't support encrypted. */
		fstrcpy(pword, pass);
		fstrcpy(ntpword, "");
		*ntpasslen = 0;
	}
	else if (ntpasslen != NULL)
	{
		if (cli->use_ntlmv2 != False)
		{
			DEBUG(10,("cli_establish_connection: NTLMv2\n"));
			pwd_make_lm_nt_owf2(&(cli->usr.pwd), cli->cryptkey,
			           cli->usr.user_name, my_hostname,
			           cli->usr.domain, sess_key);
		}
		else
		{
			DEBUG(10,("cli_establish_connection: NTLMv1\n"));
			pwd_make_lm_nt_owf(&(cli->usr.pwd), cli->cryptkey,
			                  sess_key);
		}

		pwd_get_lm_nt_owf(&(cli->usr.pwd), pass, ntpass,
		                  ntpasslen);

		*passlen = 24; 
	}
	return True;
}

/****************************************************************************
send a session setup 
****************************************************************************/
BOOL cli_session_setup(struct cli_state *cli, 
				char *user,
				char *pass, int passlen,
				char *ntpass, int ntpasslen,
				char *user_domain)
{
	fstring pword, ntpword;
	extern pstring global_myname;

	if (passlen > sizeof(pword)-1 || ntpasslen > sizeof(ntpword)-1)
	{
		return False;
	}

	fstrcpy(cli->usr.user_name, user);

	return cli_calc_session_pwds(cli, global_myname, pword, ntpword,
				pass, &passlen,
				ntpass, &ntpasslen, cli->nt.usr_sess_key,
	                        cli->use_ntlmv2) &&
	       cli_session_setup_x(cli, user, pass, passlen, ntpass, ntpasslen,
				user_domain);
}

/****************************************************************************
 Send a uloggoff.
*****************************************************************************/

BOOL cli_ulogoff(struct cli_state *cli)
{
        memset(cli->outbuf,'\0',smb_size);
        set_message(cli->outbuf,2,0,True);
        CVAL(cli->outbuf,smb_com) = SMBulogoffX;
        cli_setup_packet(cli);
	SSVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,0);  /* no additional info */

        cli_send_smb(cli);
        if (!cli_receive_smb(cli))
                return False;

        return CVAL(cli->inbuf,smb_rcls) == 0;
}

/****************************************************************************
send a tconX
****************************************************************************/
BOOL cli_send_tconX(struct cli_state *cli, 
		    char *share, char *dev, char *pass, int passlen)
{
	fstring fullshare, pword, dos_pword;
	char *p;
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	fstrcpy(cli->share, share);

	/* in user level security don't send a password now */
	if (cli->sec_mode & 1) {
		passlen = 1;
		pass = "";
	}

	if ((cli->sec_mode & 2) && *pass && passlen != 24) {
		/*
		 * Non-encrypted passwords - convert to DOS codepage before encryption.
		 */
		passlen = 24;
		fstrcpy(dos_pword,pass);
		unix_to_dos(dos_pword,True);
		SMBencrypt((uchar *)dos_pword,(uchar *)cli->cryptkey,(uchar *)pword);
	} else if(!(cli->sec_mode & 2)) {
			/*
			 * Non-encrypted passwords - convert to DOS codepage before using.
			 */
			fstrcpy(pword,pass);
			unix_to_dos(pword,True);
	} else {
		memcpy(pword, pass, passlen);
	}

	slprintf(fullshare, sizeof(fullshare)-1,
		 "\\\\%s\\%s", cli->desthost, share);
	unix_to_dos(fullshare, True);
	strupper(fullshare);

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
	p = skip_string(p, 1);
	pstrcpy(p,dev);
	unix_to_dos(p,True);

	SCVAL(cli->inbuf,smb_rcls, 1);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli))
		return False;

	if (CVAL(cli->inbuf,smb_rcls) != 0) {
		return False;
	}

	fstrcpy(cli->dev, "A:");

	if (cli->protocol >= PROTOCOL_NT1) {
		fstrcpy(cli->dev, smb_buf(cli->inbuf));
	}

	if (strcasecmp(share,"IPC$")==0) {
		fstrcpy(cli->dev, "IPC");
	}

	/* only grab the device if we have a recent protocol level */
	if (cli->protocol >= PROTOCOL_NT1 &&
	    smb_buflen(cli->inbuf) == 3) {
		/* almost certainly win95 - enable bug fixes */
		cli->win95 = True;
	}

	cli->cnum = SVAL(cli->inbuf,smb_tid);
	return True;
}

/****************************************************************************
send a tree disconnect
****************************************************************************/
BOOL cli_tdis(struct cli_state *cli)
{
	memset(cli->outbuf,'\0',smb_size);
	set_message(cli->outbuf,0,0,True);
	CVAL(cli->outbuf,smb_com) = SMBtdis;
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);
	
	cli_send_smb(cli);
	if (!cli_receive_smb(cli))
		return False;
	
	return CVAL(cli->inbuf,smb_rcls) == 0;
}


/****************************************************************************
send a negprot command
****************************************************************************/
BOOL cli_negprot(struct cli_state *cli)
{
	char *p;
	int numprots;
	int plength;

	memset(cli->outbuf,'\0',smb_size);

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
		unix_to_dos(p,True);
		p += strlen(p) + 1;
	}

	CVAL(cli->outbuf,smb_com) = SMBnegprot;
	cli_setup_packet(cli);

	CVAL(smb_buf(cli->outbuf),0) = 2;

	cli_send_smb(cli);
	if (!cli_receive_smb(cli))
	{
		return False;
	}

	if (CVAL(cli->inbuf,smb_rcls) != 0 || 
	    ((int)SVAL(cli->inbuf,smb_vwv0) >= numprots)) {
		return(False);
	}

	cli->protocol = prots[SVAL(cli->inbuf,smb_vwv0)].prot;


	if (cli->protocol >= PROTOCOL_NT1)
	{    
		char *buf = smb_buf(cli->inbuf);
		int bcc = SVAL(cli->inbuf,smb_vwv+2*(CVAL(cli->inbuf,smb_wct)));
		/* NT protocol */
		cli->sec_mode = CVAL(cli->inbuf,smb_vwv1);
		cli->max_mux = SVAL(cli->inbuf, smb_vwv1+1);
		cli->max_xmit = IVAL(cli->inbuf,smb_vwv3+1);
		cli->sesskey = IVAL(cli->inbuf,smb_vwv7+1);
		cli->serverzone = SVALS(cli->inbuf,smb_vwv15+1);
		cli->serverzone *= 60;
		/* this time arrives in real GMT */
		cli->servertime = interpret_long_date(cli->inbuf+smb_vwv11+1);

		cli->capabilities = IVAL(cli->inbuf,smb_vwv9+1);
		if (IS_BITS_SET_ALL(cli->capabilities, CAP_RAW_MODE))
		{
			cli->readbraw_supported = True;
			cli->writebraw_supported = True;      
		}

		if (IS_BITS_SET_ALL(cli->capabilities, CAP_EXTENDED_SECURITY))
		{
			/* oops, some kerberos-related nonsense. */
			/* expect to have to use NTLMSSP-over-SMB */
			DEBUG(10,("unknown kerberos-related (?) blob\n"));
			memset(cli->cryptkey, 0, 8);
			cli->server_domain[0] = 0;
		}
		else
		{
			memcpy(cli->cryptkey, buf,8);
			if (bcc > 8)
			{
				unibuf_to_ascii(cli->server_domain,  buf+8,
						sizeof(cli->server_domain));
			}
			else
			{
				cli->server_domain[0] = 0;
			}
			DEBUG(5,("server's domain: %s bcc: %d\n",
				cli->server_domain, bcc));
		}
	}
	else if (cli->protocol >= PROTOCOL_LANMAN1)
	{
		cli->sec_mode = SVAL(cli->inbuf,smb_vwv1);
		cli->max_xmit = SVAL(cli->inbuf,smb_vwv2);
		cli->sesskey = IVAL(cli->inbuf,smb_vwv6);
		cli->serverzone = SVALS(cli->inbuf,smb_vwv10);
		cli->serverzone *= 60;
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

	cli->max_xmit = MIN(cli->max_xmit, CLI_BUFFER_SIZE);

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
  
	if (cli->port == 445)
	{
		return True;
	}

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

	cli_send_smb(cli);
	DEBUG(5,("Sent session request\n"));

	if (!cli_receive_smb(cli))
		return False;

	if (CVAL(cli->inbuf,0) == 0x84) {
		/* C. Hoch  9/14/95 Start */
		/* For information, here is the response structure.
		 * We do the byte-twiddling to for portability.
		struct RetargetResponse{
		unsigned char type;
		unsigned char flags;
		int16 length;
		int32 ip_addr;
		int16 port;
		};
		*/
		int port = (CVAL(cli->inbuf,8)<<8)+CVAL(cli->inbuf,9);
		/* SESSION RETARGET */
		putip((char *)&cli->dest_ip,cli->inbuf+4);

		cli->fd = open_socket_out(SOCK_STREAM, &cli->dest_ip, port, LONG_CONNECT_TIMEOUT);
		if (cli->fd == -1)
			return False;

		DEBUG(3,("Retargeted\n"));

		set_socket_options(cli->fd,user_socket_options);

		/* Try again */
		{
			static int depth;
			BOOL ret;
			if (depth > 4) {
				DEBUG(0,("Retarget recursion - failing\n"));
				return False;
			}
			depth++;
			ret = cli_session_request(cli, calling, called);
			depth--;
			return ret;
		}
	} /* C. Hoch 9/14/95 End */

#ifdef WITH_SSL
    if (CVAL(cli->inbuf,0) == 0x83 && CVAL(cli->inbuf,4) == 0x8e){ /* use ssl */
        if (!sslutil_fd_is_ssl(cli->fd)){
            if (sslutil_connect(cli->fd) == 0)
                goto retry;
        }
    }
#endif /* WITH_SSL */

	if (CVAL(cli->inbuf,0) != 0x82) {
                /* This is the wrong place to put the error... JRA. */
		cli->rap_error = CVAL(cli->inbuf,4);
		return False;
	}
	return(True);
}


/****************************************************************************
open the client sockets
****************************************************************************/
BOOL cli_connect(struct cli_state *cli, const char *host, struct in_addr *ip)
{
	extern struct in_addr ipzero;
	int port = cli->port;

	fstrcpy(cli->desthost, host);
	
	if (!ip || ip_equal(*ip, ipzero)) {
                if (!resolve_name( cli->desthost, &cli->dest_ip, 0x20)) {
                        return False;
                }
		if (ip) *ip = cli->dest_ip;
	} else {
		cli->dest_ip = *ip;
	}


	if (port == 0) port = SMB_PORT2;

	cli->fd = open_socket_out(SOCK_STREAM, &cli->dest_ip, 
				  port, cli->timeout);
	if (cli->fd == -1)
	{
		if (cli->port != 0)
		{
			return False;
		}
		port = SMB_PORT;

		cli->fd = open_socket_out(SOCK_STREAM, &cli->dest_ip, 
					  port, cli->timeout);
		if (cli->fd == -1) return False;
	}

	cli->port = port;

	return True;
}


/****************************************************************************
re-establishes a connection
****************************************************************************/
BOOL cli_reestablish_connection(struct cli_state *cli)
{
	struct nmb_name calling;
	struct nmb_name called;
	fstring dest_host;
	fstring share;
	fstring dev;
	BOOL do_tcon = False;
	int oldfd = cli->fd;

	if (!cli->initialised || cli->fd == -1)
	{
		DEBUG(3,("cli_reestablish_connection: not connected\n"));
		return False;
	}

	/* copy the parameters necessary to re-establish the connection */

	if (cli->cnum != 0)
	{
		do_tcon = True;
	}

	if (do_tcon)
	{
		fstrcpy(share, cli->share);
		fstrcpy(dev  , cli->dev);
	}

	memcpy(&called , &(cli->called ), sizeof(called ));
	memcpy(&calling, &(cli->calling), sizeof(calling));
	fstrcpy(dest_host, cli->desthost);

	DEBUG(5,("cli_reestablish_connection: %s connecting to %s (ip %s) - %s [%s]\n",
		 nmb_namestr(&calling), nmb_namestr(&called), 
		 inet_ntoa(cli->dest_ip),
		 cli->usr.user_name, cli->usr.domain));

	cli->fd = -1;

	if (cli_establish_connection(cli,
				     dest_host, &cli->dest_ip,
				     &calling, &called,
				     share, dev, False, do_tcon))
	{
		if (cli->fd != oldfd)
		{
			if (dup2(cli->fd, oldfd) == oldfd)
			{
				cli_close_socket(cli);
			}
		}
		return True;
	}
	return False;
}

/****************************************************************************
establishes a connection right up to doing tconX, reading in a password.
****************************************************************************/
BOOL cli_establish_connection(struct cli_state *cli, 
				const char *dest_host, struct in_addr *dest_ip,
				struct nmb_name *calling, struct nmb_name *called,
				char *service, char *service_type,
				BOOL do_shutdown, BOOL do_tcon)
{
	fstring callingstr;
	fstring calledstr;

	nmb_safe_namestr(calling, callingstr, sizeof(callingstr));
	nmb_safe_namestr(called , calledstr , sizeof(calledstr ));

	DEBUG(5,("cli_establish_connection: %s connecting to %s (%s) - %s [%s] with NTLM%s, nopw: %s\n",
		          callingstr, calledstr, inet_ntoa(*dest_ip),
	              cli->usr.user_name, cli->usr.domain,
			cli->use_ntlmv2 ? "v2" : "v1",
			BOOLSTR(pwd_is_nullpwd(&cli->usr.pwd))));

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
					  dest_host, inet_ntoa(*dest_ip)));
			return False;
		}
	}

	if (!cli_session_request(cli, calling, called))
	{
		DEBUG(1,("failed session request\n"));
		if (do_shutdown)
		{
			cli_shutdown(cli);
		}
		return False;
	}

	if (!cli_negprot(cli))
	{
		DEBUG(1,("failed negprot\n"));
		if (do_shutdown)
		{
			cli_shutdown(cli);
		}
		return False;
	}

#if 0
	if (cli->usr.domain[0] == 0)
	{
		safe_strcpy(cli->usr.domain, cli->server_domain,
		            sizeof(cli->usr.domain));
	}
#endif

	if (IS_BITS_SET_ALL(cli->capabilities, CAP_EXTENDED_SECURITY))
	{
		/* common to both session setups */
		uint32 ntlmssp_flgs;
		char pwd_buf[128];
		int buf_len;
		char *p;
		char *e = pwd_buf + sizeof(pwd_buf);

		uchar lm_owf[24];
		uchar nt_owf[128];
		size_t nt_owf_len;

		/* 1st session setup */
		uchar pwd_data[34] =
		{
			0x60, 0x40, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
			0x05, 0x02, 0xa0, 0x36, 0x30, 0x34, 0xa0, 0x0e,
			0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
			0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x22,
			0x04, 0x20
		};
		/* 2nd session setup */
#if 0
		uchar pwd_data_2[8] =
		{
			0xa1, 0x51, 0x30, 0x4f, 0xa2, 0x4d, 0x04, 0x4b
		};
#endif
		prs_struct auth_resp;
		int resp_len;
		char *p_gssapi;
		char *p_oem;
		char *p_gssapi_end;
		uint16 gssapi_len;

		memset(pwd_buf, 0, sizeof(pwd_buf));
		memcpy(pwd_buf, pwd_data, sizeof(pwd_data));
		p = pwd_buf + sizeof(pwd_data);

		safe_strcpy(p, "NTLMSSP", PTR_DIFF(e, p) - 1);
		p = skip_string(p, 1);
		CVAL(p, 0) = 0x1;
		p += 4;
		ntlmssp_flgs = 
				NTLMSSP_NEGOTIATE_UNICODE |
				NTLMSSP_NEGOTIATE_OEM |
				NTLMSSP_NEGOTIATE_SIGN |
				NTLMSSP_NEGOTIATE_SEAL |
				NTLMSSP_NEGOTIATE_LM_KEY |
				NTLMSSP_NEGOTIATE_NTLM |
				NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
				NTLMSSP_NEGOTIATE_00001000 |
				NTLMSSP_NEGOTIATE_00002000;
		SIVAL(p, 0, ntlmssp_flgs);
		p += 4;
		p += 16; /* skip some NULL space */
		CVAL(p, 0) = 0; p++; /* alignment */

		buf_len = PTR_DIFF(p, pwd_buf);

		/* first session negotiation stage */
		if (!cli_session_setup_x(cli, cli->usr.user_name,
			       pwd_buf, buf_len,
			       NULL, 0,
			       cli->usr.domain))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown)
			{
				cli_shutdown(cli);
			}
			return False;
		}

		DEBUG(1,("1st session setup ok\n"));

		if (*cli->server_domain || *cli->server_os || *cli->server_type)
		{
			DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",
			     cli->server_domain,
		             cli->server_os,
		             cli->server_type));
		}
	
		p = smb_buf(cli->inbuf) + 0x2f;
		ntlmssp_flgs = IVAL(p, 0); /* 0x80808a05; */
		p += 4;
		memcpy(cli->cryptkey, p, 8);
#ifdef DEBUG_PASSWORD
		DEBUG(100,("cli_session_setup_x: ntlmssp %8x\n",
			    ntlmssp_flgs));
			   
		DEBUG(100,("cli_session_setup_x: crypt key\n"));
		dump_data(100, cli->cryptkey, 8);
#endif
		prs_init(&auth_resp, 0x0, 4, False);
		auth_resp.bigendian = False;

		if (cli->use_ntlmv2 != False)
		{
			DEBUG(10,("cli_establish_connection: NTLMv2\n"));
			pwd_make_lm_nt_owf2(&(cli->usr.pwd), cli->cryptkey,
			           cli->usr.user_name, calling->name,
			           cli->usr.domain,
			           cli->nt.usr_sess_key);
		}
		else
		{
			DEBUG(10,("cli_establish_connection: NTLMv1\n"));
			pwd_make_lm_nt_owf(&(cli->usr.pwd), cli->cryptkey,
			           cli->nt.usr_sess_key);
		}

		pwd_get_lm_nt_owf(&cli->usr.pwd, lm_owf, nt_owf, &nt_owf_len);

		create_ntlmssp_resp(lm_owf, nt_owf, nt_owf_len, cli->usr.domain,
				     cli->usr.user_name, cli->calling.name,
				     ntlmssp_flgs,
				     &auth_resp);
		prs_link(NULL, &auth_resp, NULL);

		memset(pwd_buf, 0, sizeof(pwd_buf));
		p = pwd_buf;

		CVAL(p, 0) = 0xa1; p++;
		CVAL(p, 0) = 0x82; p++;
		p_gssapi = p; p+= 2;
		CVAL(p, 0) = 0x30; p++;
		CVAL(p, 0) = 0x82; p++;
		p += 2;
		
		CVAL(p, 0) = 0xa2; p++;
		CVAL(p, 0) = 0x82; p++;
		p_oem = p; p+= 2;
		CVAL(p, 0) = 0x04; p++;
		CVAL(p, 0) = 0x82; p++;
		p += 2;

		p_gssapi_end = p;
		
		safe_strcpy(p, "NTLMSSP", PTR_DIFF(e, p) - 1);
		p = skip_string(p, 1);
		CVAL(p, 0) = 0x3;
		p += 4;

		resp_len = prs_buf_len(&auth_resp);
		prs_buf_copy(p, &auth_resp, 0, resp_len);
		prs_free_data(&auth_resp);

		p += resp_len;

		buf_len = PTR_DIFF(p, pwd_buf);
		gssapi_len = PTR_DIFF(p, p_gssapi_end) + 12;

		*p_gssapi++ = (gssapi_len >> 8) & 0xff;
		*p_gssapi++ = gssapi_len & 0xff;

		p_gssapi += 2;
		gssapi_len -= 4;

		*p_gssapi++ = (gssapi_len >> 8) & 0xff;
		*p_gssapi++ = gssapi_len & 0xff;

		gssapi_len -= 4;

		*p_oem++ = (gssapi_len >> 8) & 0xff;
		*p_oem++ = gssapi_len & 0xff;

		p_oem += 2;
		gssapi_len -= 4;

		*p_oem++ = (gssapi_len >> 8) & 0xff;
		*p_oem++ = gssapi_len & 0xff;

		/* second session negotiation stage */
		if (!cli_session_setup_x(cli, cli->usr.user_name,
			       pwd_buf, buf_len,
			       NULL, 0,
			       cli->usr.domain))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown)
			{
				cli_shutdown(cli);
			}
			return False;
		}

		DEBUG(1,("2nd session setup ok\n"));

		if (do_tcon)
		{
			if (!cli_send_tconX(cli, service, service_type,
			                    NULL, 0))
			                    
			{
				DEBUG(1,("failed tcon_X\n"));
				if (do_shutdown)
				{
					cli_shutdown(cli);
				}
				return False;
			}
		}
	}
	else if (cli->usr.pwd.cleartext || cli->usr.pwd.null_pwd)
	{
		fstring passwd, ntpasswd;
		int pass_len = 0, ntpass_len = 0;

		if (cli->usr.pwd.null_pwd)
		{
			/* attempt null session */
			passwd[0] = ntpasswd[0] = 0;
			pass_len = ntpass_len = 1;
		}
		else
		{
			/* attempt clear-text session */
			pwd_get_cleartext(&(cli->usr.pwd), passwd);
			pass_len = strlen(passwd);
		}

		/* attempt clear-text session */
		if (!cli_session_setup(cli, 
		               cli->usr.user_name,
	                       passwd, pass_len,
	                       ntpasswd, ntpass_len,
	                       cli->usr.domain))
		{
			DEBUG(1,("failed session setup\n"));
			if (do_shutdown)
			{
				cli_shutdown(cli);
			}
			return False;
		}
		if (do_tcon)
		{
			if (!cli_send_tconX(cli, service, service_type,
			                    (char*)passwd, strlen(passwd)))
			{
				DEBUG(1,("failed tcon_X\n"));
				if (do_shutdown)
				{
					cli_shutdown(cli);
				}
				return False;
			}
		}
	}
	else
	{
		/* attempt encrypted session */
		unsigned char lm_sess_pwd[24];
		unsigned char nt_sess_pwd[128];
		size_t nt_sess_pwd_len;

		if (cli->use_ntlmv2 != False)
		{
			DEBUG(10,("cli_establish_connection: NTLMv2\n"));
			pwd_make_lm_nt_owf2(&(cli->usr.pwd), cli->cryptkey,
			           cli->usr.user_name, calling->name,
			           cli->usr.domain,
			           cli->nt.usr_sess_key);
		}
		else
		{
			DEBUG(10,("cli_establish_connection: NTLMv1\n"));
			pwd_make_lm_nt_owf(&(cli->usr.pwd), cli->cryptkey,
			                   cli->nt.usr_sess_key);
		}

		pwd_get_lm_nt_owf(&(cli->usr.pwd), lm_sess_pwd, nt_sess_pwd,
		                  &nt_sess_pwd_len);

		/* attempt encrypted session */
		if (!cli_session_setup_x(cli, cli->usr.user_name,
			               (char*)lm_sess_pwd, sizeof(lm_sess_pwd),
			               (char*)nt_sess_pwd, nt_sess_pwd_len,
			               cli->usr.domain))
		{
			DEBUG(1,("failed session setup\n"));

			if (cli->use_ntlmv2 == Auto)
			{
				DEBUG(10,("NTLMv2 failed.  Using NTLMv1\n"));
				cli->use_ntlmv2 = False;
				if (do_tcon)
				{
					fstrcpy(cli->share, service);
					fstrcpy(cli->dev, service_type);
				}
				fstrcpy(cli->desthost, dest_host);
				cli_close_socket(cli);
				return cli_establish_connection(cli, 
					dest_host, dest_ip,
					calling, called,
					service, service_type,
					do_shutdown, do_tcon);
			}
			
			if (do_shutdown)
			{
				cli_shutdown(cli);
			}
			return False;
		}

		DEBUG(1,("session setup ok\n"));

		if (*cli->server_domain || *cli->server_os || *cli->server_type)
		{
			DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",
			     cli->server_domain,
		             cli->server_os,
		             cli->server_type));
		}
	
		if (do_tcon)
		{
			if (!cli_send_tconX(cli, service, service_type,
			                    (char*)nt_sess_pwd, sizeof(nt_sess_pwd)))
			{
				DEBUG(1,("failed tcon_X\n"));
				if (do_shutdown)
				{
					cli_shutdown(cli);
				}
				return False;
			}
		}
	}

	if (do_shutdown)
	{
		cli_shutdown(cli);
	}

	return True;
}

