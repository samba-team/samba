/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Luke Kenneth Casson Leighton 1994-1998
   Copyright (C) Jeremy Allison 1994-1998
   
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

*/

#include "includes.h"

extern int DEBUGLEVEL;

extern pstring myname;
extern fstring myworkgroup;

/****************************************************************************
Process a domain logon packet
**************************************************************************/

void process_logon_packet(struct packet_struct *p,char *buf,int len, 
                          char *mailslot)
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
  uint32 allowableaccount; /* Control bits, i.e. 0x80 == workstation trust a/c. */
  uint32 domainsidsize;
  uint16 requestcount;
  char *domainsid;
  char *getdc;
  char *uniuser; /* Unicode user name. */
  pstring ascuser;
  char *unicomp; /* Unicode computer name. */
  struct smb_passwd *smb_pass; /* To check if machine account exists */

  if (!lp_domain_logons())
  {
    DEBUG(3,("process_logon_packet: Logon packet received from IP %s and domain \
logons are not enabled.\n", inet_ntoa(p->ip) ));
    return;
  }

  pstrcpy(my_name, myname);
  strupper(my_name);

  code = SVAL(buf,0);
  DEBUG(1,("process_logon_packet: Logon from %s: code = %x\n", inet_ntoa(p->ip), code));

  switch (code)
  {
    case 0:    
    {
      char *q = buf + 2;
      char *machine = q;
      char *user = skip_string(machine,1);

      getdc = skip_string(user,1);
      q = skip_string(getdc,1);
      unknown_byte = CVAL(q,0);
      request_count = SVAL(q,1);
      token = SVAL(q,3);

      reply_code = 0x6;
      fstrcpy(reply_name,my_name); 
      add_slashes = True;

      DEBUG(3,("process_logon_packet: Domain login request from %s at IP %s user=%s token=%x\n",
             machine,inet_ntoa(p->ip),user,token));

      q = outbuf;
      SSVAL(q, 0, 6); q += 2;

      fstrcpy(reply_name, "\\\\");
      fstrcat(reply_name, my_name);
      fstrcpy(q, reply_name); q = skip_string(q, 1); /* PDC name */

      SSVAL(q, 0, token); q += 2;

      dump_data(4, outbuf, PTR_DIFF(q, outbuf));

      send_mailslot(True, getdc, 
                    outbuf,PTR_DIFF(q,outbuf),
                    dgram->dest_name.name,
                    dgram->dest_name.name_type,
                    dgram->source_name.name,
                    dgram->source_name.name_type,
                    p->ip, *iface_ip(p->ip));  
      break;
    }

    case QUERYFORPDC:
    {
      char *q = buf + 2;
      char *machine = q;

      getdc = skip_string(machine,1);
      unicomp = skip_string(getdc,1);

      q = align2(unicomp, buf);

      q = skip_unicode_string(q, 1);

      ntversion = IVAL(q, 0); q += 4;
      lmnttoken = SVAL(q, 0); q += 2;
      lm20token = SVAL(q, 0); q += 2;

      /* Construct reply. */

      q = outbuf;
      SSVAL(q, 0, QUERYFORPDC_R); q += 2;

      fstrcpy(reply_name,my_name);
      fstrcpy(q, reply_name); q = skip_string(q, 1); /* PDC name */

      if (strcmp(mailslot, NT_LOGON_MAILSLOT)==0) {
        q = align2(q, buf);

        PutUniCode(q, my_name); /* PDC name */
        q = skip_unicode_string(q, 1); 
        PutUniCode(q, myworkgroup); /* Domain name*/
        q = skip_unicode_string(q, 1); 

        SIVAL(q, 0, ntversion); q += 4;
        SSVAL(q, 0, lmnttoken); q += 2;
        SSVAL(q, 0, lm20token); q += 2;
      }

      DEBUG(3,("process_logon_packet: GETDC request from %s at IP %s, \
reporting %s domain %s 0x%x ntversion=%x lm_nt token=%x lm_20 token=%x\n",
            machine,inet_ntoa(p->ip), reply_name, lp_workgroup(),
            QUERYFORPDC_R, (uint32)ntversion, (uint32)lmnttoken,
            (uint32)lm20token ));

      dump_data(4, outbuf, PTR_DIFF(q, outbuf));

      send_mailslot(True, getdc,
                  outbuf,PTR_DIFF(q,outbuf),
                  dgram->dest_name.name,
                  dgram->dest_name.name_type,
                  dgram->source_name.name,
                  dgram->source_name.name_type,
                  p->ip, *iface_ip(p->ip));  
      return;
    }

    case SAMLOGON:
    {
      char *q = buf + 2;

      requestcount = SVAL(q, 0); q += 2;
      unicomp = q;
      uniuser = skip_unicode_string(unicomp,1);
      getdc = skip_unicode_string(uniuser,1);
      q = skip_string(getdc,1);
      allowableaccount = IVAL(q, 0); q += 4;
      domainsidsize = IVAL(q, 0); q += 4;
      domainsid = q;
      q += domainsidsize + 3;
      ntversion = IVAL(q, 0); q += 4;
      lmnttoken = SVAL(q, 0); q += 2;
      lm20token = SVAL(q, 0); q += 2;

      DEBUG(3,("process_logon_packet: SAMLOGON sidsize %d ntv %d\n", domainsidsize, ntversion));

      /*
       * If MACHINE$ is in our password database then respond, else ignore.
       * Let's ignore the SID.
       */

      pstrcpy(ascuser, unistr(uniuser));
      DEBUG(3,("process_logon_packet: SAMLOGON user %s\n", ascuser));

      fstrcpy(reply_name,"\\\\"); /* Here it wants \\LOGONSERVER. */
      fstrcpy(reply_name+2,my_name); 

      smb_pass = get_smbpwd_entry(ascuser, 0);

      if(!smb_pass)
      {
        DEBUG(3,("process_logon_packet: SAMLOGON request from %s(%s) for %s, not in password file\n",
           unistr(unicomp),inet_ntoa(p->ip), ascuser));
        return;
      }
      else
      {
        DEBUG(3,("process_logon_packet: SAMLOGON request from %s(%s) for %s, returning logon svr %s domain %s code %x token=%x\n",
           unistr(unicomp),inet_ntoa(p->ip), ascuser, reply_name, myworkgroup,
           SAMLOGON_R ,lmnttoken));
      }

      /* Construct reply. */

      q = outbuf;
      SSVAL(q, 0, SAMLOGON_R); q += 2;

      PutUniCode(q, reply_name); q = skip_unicode_string(q, 1);
      unistrcpy(q, uniuser); q = skip_unicode_string(q, 1); /* User name (workstation trust account) */
      PutUniCode(q, lp_workgroup()); q = skip_unicode_string(q, 1); /* Domain name. */

      SIVAL(q, 0, ntversion); q += 4;
      SSVAL(q, 0, lmnttoken); q += 2;
      SSVAL(q, 0, lm20token); q += 2;

      dump_data(4, outbuf, PTR_DIFF(q, outbuf));

      send_mailslot(True, getdc,
                   outbuf,PTR_DIFF(q,outbuf),
                   dgram->dest_name.name,
                   dgram->dest_name.name_type,
                   dgram->source_name.name,
                   dgram->source_name.name_type,
                   p->ip, *iface_ip(p->ip));  
      break;
    }

    default:
    {
      DEBUG(3,("process_logon_packet: Unknown domain request %d\n",code));
      return;
    }
  }
}
