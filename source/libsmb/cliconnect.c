/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client connect/disconnect routines
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
 Send a session setup. The username is in UNIX character format and must be
 converted to DOS codepage format before sending. If the password is in
 plaintext, the same should be done.
****************************************************************************/

BOOL cli_session_setup(struct cli_state *cli, 
		       char *user, 
		       char *pass, int passlen,
		       char *ntpass, int ntpasslen,
		       char *workgroup)
{
	char *p;
	fstring pword, ntpword;

	if (cli->protocol < PROTOCOL_LANMAN1)
		return True;

	if (passlen > sizeof(pword)-1 || ntpasslen > sizeof(ntpword)-1) {
		return False;
	}

	if (((passlen == 0) || (passlen == 1)) && (pass[0] == '\0')) {
		/* Null session connect. */
		pword[0] = '\0';
		ntpword[0] = '\0';
	} else {
		if ((cli->sec_mode & 2) && passlen != 24) {
			/*
			 * Encrypted mode needed, and non encrypted password supplied.
			 */
			passlen = 24;
			ntpasslen = 24;
			fstrcpy(pword, pass);
			unix_to_dos(pword,True);
			fstrcpy(ntpword, ntpass);;
			unix_to_dos(ntpword,True);
			SMBencrypt((uchar *)pword,(uchar *)cli->cryptkey,(uchar *)pword);
			SMBNTencrypt((uchar *)ntpword,(uchar *)cli->cryptkey,(uchar *)ntpword);
		} else if ((cli->sec_mode & 2) && passlen == 24) {
			/*
			 * Encrypted mode needed, and encrypted password supplied.
			 */
			memcpy(pword, pass, passlen);
			if(ntpasslen == 24) {
				memcpy(ntpword, ntpass, ntpasslen);
			} else {
				fstrcpy(ntpword, "");
				ntpasslen = 0;
			}
		} else {
			/*
			 * Plaintext mode needed, assume plaintext supplied.
			 */
			fstrcpy(pword, pass);
			unix_to_dos(pword,True);
			fstrcpy(ntpword, "");
			ntpasslen = 0;
		}
	}

	/* if in share level security then don't send a password now */
	if (!(cli->sec_mode & 1)) {
		fstrcpy(pword, "");
		passlen=1;
		fstrcpy(ntpword, "");
		ntpasslen=1;
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
		memcpy(p,pword,passlen);
		p += passlen;
		pstrcpy(p,user);
		unix_to_dos(p,True);
		strupper(p);
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
		SSVAL(cli->outbuf,smb_vwv11,0);
		p = smb_buf(cli->outbuf);
		memcpy(p,pword,passlen); 
		p += SVAL(cli->outbuf,smb_vwv7);
		memcpy(p,ntpword,ntpasslen); 
		p += SVAL(cli->outbuf,smb_vwv8);
		pstrcpy(p,user);
		unix_to_dos(p,True);
		strupper(p);
		p = skip_string(p,1);
		pstrcpy(p,workgroup);
		strupper(p);
		p = skip_string(p,1);
		pstrcpy(p,"Unix");p = skip_string(p,1);
		pstrcpy(p,"Samba");p = skip_string(p,1);
		set_message(cli->outbuf,13,PTR_DIFF(p,smb_buf(cli->outbuf)),False);
	}

      cli_send_smb(cli);
      if (!cli_receive_smb(cli))
	      return False;

      show_msg(cli->inbuf);

      if (CVAL(cli->inbuf,smb_rcls) != 0) {
	      return False;
      }

      /* use the returned vuid from now on */
      cli->vuid = SVAL(cli->inbuf,smb_uid);

      if (cli->protocol >= PROTOCOL_NT1) {
        /*
         * Save off some of the connected server
         * info.
         */
        char *server_domain,*server_os,*server_type;
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

      fstrcpy(cli->user_name, user);
      dos_to_unix(cli->user_name, True);

      return True;
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
	} else {
		if(!(cli->sec_mode & 2)) {
			/*
			 * Non-encrypted passwords - convert to DOS codepage before using.
			 */
			fstrcpy(pword,pass);
			unix_to_dos(pword,True);
		} else {
			memcpy(pword, pass, passlen);
		}
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
	p = skip_string(p,1);
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
		cli->max_mux = SVAL(cli->inbuf, smb_vwv1+1);
		cli->max_xmit = IVAL(cli->inbuf,smb_vwv3+1);
		cli->sesskey = IVAL(cli->inbuf,smb_vwv7+1);
		cli->serverzone = SVALS(cli->inbuf,smb_vwv15+1);
		cli->serverzone *= 60;
		/* this time arrives in real GMT */
		cli->servertime = interpret_long_date(cli->inbuf+smb_vwv11+1);
		memcpy(cli->cryptkey,smb_buf(cli->inbuf),8);
		cli->capabilities = IVAL(cli->inbuf,smb_vwv9+1);
		if (cli->capabilities & 1) {
			cli->readbraw_supported = True;
			cli->writebraw_supported = True;      
		}
	} else if (cli->protocol >= PROTOCOL_LANMAN1) {
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
	extern pstring user_socket_options;

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
	extern pstring user_socket_options;

	fstrcpy(cli->desthost, host);
	
	if (!ip || ip_equal(*ip, ipzero)) {
                if (!resolve_name( cli->desthost, &cli->dest_ip, 0x20)) {
                        return False;
                }
		if (ip) *ip = cli->dest_ip;
	} else {
		cli->dest_ip = *ip;
	}

        if (cli->port == 0) cli->port = 139;  /* Set to default */

	cli->fd = open_socket_out(SOCK_STREAM, &cli->dest_ip, 
				  cli->port, cli->timeout);
	if (cli->fd == -1)
		return False;

	set_socket_options(cli->fd,user_socket_options);

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
		fstrcpy(share, cli->share);
		fstrcpy(dev  , cli->dev);
		do_tcon = True;
	}

	memcpy(&called , &(cli->called ), sizeof(called ));
	memcpy(&calling, &(cli->calling), sizeof(calling));
	fstrcpy(dest_host, cli->full_dest_host_name);

	DEBUG(5,("cli_reestablish_connection: %s connecting to %s (ip %s) - %s [%s]\n",
		 nmb_namestr(&calling), nmb_namestr(&called), 
		 inet_ntoa(cli->dest_ip),
		 cli->user_name, cli->domain));

	cli->fd = -1;

	if (cli_establish_connection(cli,
				     dest_host, &cli->dest_ip,
				     &calling, &called,
				     share, dev, False, do_tcon)) {
		if (cli->fd != oldfd) {
			if (dup2(cli->fd, oldfd) == oldfd) {
				close(cli->fd);
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
				char *dest_host, struct in_addr *dest_ip,
				struct nmb_name *calling, struct nmb_name *called,
				char *service, char *service_type,
				BOOL do_shutdown, BOOL do_tcon)
{
	DEBUG(5,("cli_establish_connection: %s connecting to %s (%s) - %s [%s]\n",
		          nmb_namestr(calling), nmb_namestr(called), inet_ntoa(*dest_ip),
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
					  nmb_namestr(calling), inet_ntoa(*dest_ip)));
			return False;
		}
	}

	if (!cli_session_request(cli, calling, called))
	{
		DEBUG(1,("failed session request\n"));
		if (do_shutdown)
          cli_shutdown(cli);
		return False;
	}

	if (!cli_negprot(cli))
	{
		DEBUG(1,("failed negprot\n"));
		if (do_shutdown)
          		cli_shutdown(cli);
		return False;
	}

	if (cli->pwd.cleartext || cli->pwd.null_pwd)
	{
		fstring passwd;
		int pass_len;

		if (cli->pwd.null_pwd)
		{
			/* attempt null session */
			passwd[0] = 0;
			pass_len = 1;
		}
		else
		{
			/* attempt clear-text session */
			pwd_get_cleartext(&(cli->pwd), passwd);
			pass_len = strlen(passwd);
		}

		/* attempt clear-text session */
		if (!cli_session_setup(cli, cli->user_name,
	                       passwd, pass_len,
	                       NULL, 0,
	                       cli->domain))
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
		unsigned char nt_sess_pwd[24];
		unsigned char lm_sess_pwd[24];

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
			if (do_shutdown)
		              cli_shutdown(cli);
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
                  cli_shutdown(cli);
				return False;
			}
		}
	}

	if (do_shutdown)
      cli_shutdown(cli);

	return True;
}


/****************************************************************************
 Attempt a NetBIOS session request, falling back to *SMBSERVER if needed.
****************************************************************************/

BOOL attempt_netbios_session_request(struct cli_state *cli, char *srchost, char *desthost,
                                     struct in_addr *pdest_ip)
{
  struct nmb_name calling, called;

  make_nmb_name(&calling, srchost, 0x0);

  /*
   * If the called name is an IP address
   * then use *SMBSERVER immediately.
   */

  if(is_ipaddress(desthost))
    make_nmb_name(&called, "*SMBSERVER", 0x20);
  else
    make_nmb_name(&called, desthost, 0x20);

  if (!cli_session_request(cli, &calling, &called)) {
    struct nmb_name smbservername;

    make_nmb_name(&smbservername , "*SMBSERVER", 0x20);

    /*
     * If the name wasn't *SMBSERVER then
     * try with *SMBSERVER if the first name fails.
     */

    if (nmb_name_equal(&called, &smbservername)) {

        /*
         * The name used was *SMBSERVER, don't bother with another name.
         */

        DEBUG(0,("attempt_netbios_session_request: %s rejected the session for name *SMBSERVER \
with error %s.\n", desthost, cli_errstr(cli) ));
	    cli_shutdown(cli);
		return False;
	}

    cli_shutdown(cli);

    if (!cli_initialise(cli) ||
        !cli_connect(cli, desthost, pdest_ip) ||
        !cli_session_request(cli, &calling, &smbservername)) {
          DEBUG(0,("attempt_netbios_session_request: %s rejected the session for \
name *SMBSERVER with error %s\n", desthost, cli_errstr(cli) ));
          cli_shutdown(cli);
          return False;
    }
  }

  return True;
}
