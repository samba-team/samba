/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
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
   
   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

*/

#include "includes.h"

extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern pstring myname;


/****************************************************************************
   process a domain logon packet

   **************************************************************************/
void process_logon_packet(struct packet_struct *p,char *buf,int len)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	pstring my_name;
	fstring reply_name;
	BOOL add_slashes = False;
	pstring outbuf;
	int code,reply_code;
	char   unknown_byte = 0;
	uint16 request_count = 0;
	uint16 token = 0;

	uint32 ntversion;
	uint16 lmnttoken;
	uint16 lm20token;
	uint32 allowableaccount; /* Control bits, i.e. 0x80 == workstation trust a/c */
	uint32 domainsidsize;
	uint16 requestcount;
	char *domainsid;
	char *uniuser; /* Unicode user name */
	pstring ascuser;
	char *mailslot;
	char *unicomp; /* Unicode computer name */
	struct smb_passwd *smb_pass; /* To check if machine account exists */

	if (!lp_domain_logons())
	{
		DEBUG(3,("No domain logons\n"));
		return;
	}

	strcpy(my_name, myname);
	strupper(my_name);

	code = SVAL(buf,0);
	DEBUG(1,("namelogon: %x\n", code));

	switch (code)
	{
		case 0:    
		{
			char *q = buf + 2;
			char *machine = q;
			char *user = skip_string(machine,1);

			mailslot = skip_string(user,1);
			q = skip_string(mailslot,1);
			unknown_byte = CVAL(q,0);
			request_count = SVAL(q,1);
			token = SVAL(q,3);

			reply_code = 0x6;
			strcpy(reply_name,my_name); 
			add_slashes = True;

			DEBUG(3,("Domain login request from %s(%s) user=%s token=%x\n",
			          machine,inet_ntoa(p->ip),user,token));

			q = outbuf;
			SSVAL(q, 0, 6); q += 2;

			strcpy(reply_name, "\\\\");
			strcat(reply_name, my_name);
			strcpy(q, reply_name); q = skip_string(q, 1); /* PDC name */

			SSVAL(q, 0, token); q += 2;

			dump_data(4, outbuf, PTR_DIFF(q, outbuf));

			send_mailslot_reply(True, mailslot, ClientDGRAM,
			                    outbuf,PTR_DIFF(q,outbuf),
			                    my_name,&dgram->source_name.name[0],0x20,0,
			                    p->ip, *iface_ip(p->ip));  
			break;
		}

		case QUERYFORPDC:
		{
			char *q = buf + 2;
			char *machine = q;
			mailslot = skip_string(machine,1);
			unicomp = skip_string(mailslot,1);

			q = align2(q, buf);

			q = skip_unicode_string(unicomp,1);

			ntversion = IVAL(q, 0); q += 4;
			lmnttoken = SVAL(q, 0); q += 2;
			lm20token = SVAL(q, 0); q += 2;

			/* construct reply */

			q = outbuf;
			SSVAL(q, 0, QUERYFORPDC_R); q += 2;

			strcpy(reply_name,my_name);
			strcpy(q, reply_name); q = skip_string(q, 1); /* PDC name */

			q = align2(q, buf);

			PutUniCode(q, my_name); q = skip_unicode_string(q, 1); /* PDC name */
			PutUniCode(q, lp_workgroup()); q = skip_unicode_string(q, 1); /* Domain name. */

			SIVAL(q, 0, ntversion); q += 4;
			SSVAL(q, 0, lmnttoken); q += 2;
			SSVAL(q, 0, lm20token); q += 2;

			DEBUG(3,("GETDC request from %s(%s), reporting %s domain %s 0x%x ntversion=%x lm_nt token=%x lm_20 token=%x\n",
			          machine,inet_ntoa(p->ip), reply_name, lp_workgroup(),
			          QUERYFORPDC_R, (uint32)ntversion, (uint32)lmnttoken,
			          (uint32)lm20token));

			dump_data(4, outbuf, PTR_DIFF(q, outbuf));

			send_mailslot_reply(True, mailslot,ClientDGRAM,
			                    outbuf,PTR_DIFF(q,outbuf),
			                    my_name,&dgram->source_name.name[0],0x20,0,
			                    p->ip, *iface_ip(p->ip));  
			return;
		}

		case SAMLOGON:
		{
			char *q = buf + 2;

			requestcount = SVAL(q, 0); q += 2;
			unicomp = q;
			uniuser = skip_unicode_string(unicomp,1);
			mailslot = skip_unicode_string(uniuser,1);
			q = skip_string(mailslot,1);
			allowableaccount = IVAL(q, 0); q += 4;
			domainsidsize = IVAL(q, 0); q += 4;
			domainsid = q;
			q += domainsidsize + 3;
			ntversion = IVAL(q, 0); q += 4;
			lmnttoken = SVAL(q, 0); q += 2;
			lm20token = SVAL(q, 0); q += 2;
			DEBUG(3,("SAMLOGON sidsize %d ntv %d\n", domainsidsize, ntversion));

			/*
			  If MACHINE$ is in our password database then respond, else ignore.
			  Let's ignore the SID.
			*/
			strcpy(ascuser,unistr(uniuser));
			DEBUG(3,("SAMLOGON user %s\n", ascuser));
			strcpy(reply_name,"\\\\"); /* Here it wants \\LOGONSERVER */
			strcpy(reply_name+2,my_name); /* PAXX: Assuming we are logon svr */
			smb_pass = get_smbpwnam(ascuser);

			if(!smb_pass)
			{
				DEBUG(3,("SAMLOGON request from %s(%s) for %s, not in password file\n",
				          unistr(unicomp),inet_ntoa(p->ip), ascuser));
				return;
			}
			else
			{
				DEBUG(3,("SAMLOGON request from %s(%s) for %s, returning logon svr %s domain %s code %x token=%x\n",
				          unistr(unicomp),inet_ntoa(p->ip), ascuser, reply_name, lp_workgroup(),
				          SAMLOGON_R ,lmnttoken));
			}

			/* construct reply */

			q = outbuf;
			SSVAL(q, 0, SAMLOGON_R); q += 2;

			PutUniCode(q, reply_name); q = skip_unicode_string(q, 1);
			unistrcpy(q, uniuser); q = skip_unicode_string(q, 1); /* User name (workstation trust account) */
			PutUniCode(q, lp_workgroup()); q = skip_unicode_string(q, 1); /* Domain name. */

			SIVAL(q, 0, ntversion); q += 4;
			SSVAL(q, 0, lmnttoken); q += 2;
			SSVAL(q, 0, lm20token); q += 2;

			dump_data(4, outbuf, PTR_DIFF(q, outbuf));

			send_mailslot_reply(True, mailslot,ClientDGRAM,
			                    outbuf,PTR_DIFF(q,outbuf),
			                    my_name,&dgram->source_name.name[0],0x20,0,
			                    p->ip, *iface_ip(p->ip));  
			break;
		}

		default:
		{
		DEBUG(3,("Unknown domain request %d\n",code));
		return;
		}
	}

}
