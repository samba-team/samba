/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1995
   
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
#include "loadparm.h"
#include "localnet.h"

#define TEST_CODE /* want to debug unknown browse packets */

extern int DEBUGLEVEL;
extern pstring scope;
extern BOOL CanRecurse;

extern struct in_addr myip;
extern struct in_addr bcast_ip;
extern struct in_addr Netmask;

extern pstring myname;

extern int ClientNMB;
extern int ClientDGRAM;

extern int workgroup_count; /* total number of workgroups we know about */

/* this is our browse cache database */
extern struct browse_cache_record *browserlist;

/* this is our domain/workgroup/server database */
extern struct domain_record *domainlist;

/* machine comment for host announcements */
extern  pstring ServerComment;

extern int  updatecount;

/* what server type are we currently */
#define DFLT_SERVER_TYPE (SV_TYPE_WORKSTATION | SV_TYPE_SERVER | \
		SV_TYPE_TIME_SOURCE | SV_TYPE_SERVER_UNIX |\
		SV_TYPE_PRINTQ_SERVER | SV_TYPE_POTENTIAL_BROWSER)

/* backup request types: which servers are to be included */
#define MASTER_TYPE (SV_TYPE_MASTER_BROWSER)
#define DOMCTL_TYPE (SV_TYPE_DOMAIN_CTRL   )

extern time_t StartupTime;

#define AM_MASTER(work) (work->ServerType & SV_TYPE_MASTER_BROWSER)
#define AM_BACKUP(work) (work->ServerType & SV_TYPE_BACKUP_BROWSER)

#define MSBROWSE "\001\002__MSBROWSE__\002"
#define BROWSE_MAILSLOT "\\MAILSLOT\\BROWSE"

#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())


/****************************************************************************
tell a server to become a backup browser
state - 0x01 become backup instead of master
      - 0x02 remove all entries in browse list and become non-master
      - 0x04 stop master browser service altogether. NT ignores this 
**************************************************************************/
void reset_server(char *name, int state, struct in_addr ip)
{
	char outbuf[20];
	char *p;

	bzero(outbuf,sizeof(outbuf));
	p = outbuf;

	CVAL(p,0) = 14;    /* request reset browser state */
	CVAL(p,2) = state; /* type of request */
	p += 2;

	send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
	               myname,name,0x20,0x1d,ip,myip);
}

/****************************************************************************
tell a server to become a backup browser
**************************************************************************/
void tell_become_backup(void)
{
	struct domain_record *d;
	for (d = domainlist; d; d = d->next)
	{
		struct work_record *work;
		for (work = d->workgrouplist; work; work = work->next)
		{
			struct server_record *s;
			int num_servers = 0;
			int num_backups = 0;

			for (s = work->serverlist; s; s = s->next)
			{
				if (s->serv.type & SV_TYPE_DOMAIN_ENUM) continue;

				num_servers++;

				if (strequal(myname, s->serv.name)) continue;

				if (s->serv.type & SV_TYPE_BACKUP_BROWSER)
				{
					num_backups++;
					continue;
				}

				if (s->serv.type & SV_TYPE_MASTER_BROWSER) continue;

				if (!(s->serv.type & SV_TYPE_POTENTIAL_BROWSER)) continue;

				DEBUG(3,("num servers: %d num backups: %d\n", 
				     num_servers, num_backups));

				/* make first server a backup server. thereafter make every
				   tenth server a backup server */
				if (num_backups != 0 && (num_servers+9) / num_backups > 10)
				{
					continue;
				}

				DEBUG(3,("workgroup %s subnet %s: make backup: %s %8x \n", 
				         work->work_group, inet_ntoa(d->bcast_ip),
						 s->serv.name, s->serv.type));
                                                               
				/* type 11 request from MYNAME(20) to WG(1e) for SERVER */
				do_announce_request(s->serv.name, work->work_group,
				                    11, 0x20, 0x1e, d->bcast_ip);
			}
		}
	}
}

/****************************************************************************
find a server responsible for a workgroup, and sync browse lists
**************************************************************************/
static BOOL sync_browse_entry(struct browse_cache_record *b)
{                     
	struct domain_record *d;
	struct work_record *work;
/*
	if (!strequal(serv_name, b->name))
	{
		DEBUG(0, ("browser's netbios name (%s) does not match %s (%s)",
				b->name, inet_ntoa(b->ip), serv_name));
	}
*/
	if (!(d = find_domain(b->ip))) return False;
	if (!(work = find_workgroupstruct(d, b->group, False))) return False;

	sync_browse_lists(work,b->name,0x20,b->ip);
	b->synced = True;
	
	return True;
}


/****************************************************************************
search through browser list for an entry to sync with
**************************************************************************/
void do_browser_lists(void)
{
	struct browse_cache_record *b;
	static time_t last = 0;
	time_t t = time(NULL);

	if (t-last < 4) return; /* don't do too many of these at once! */

	last = t;

	/* pick any entry in the list, preferably one whose time is up */
	for (b = browserlist; b && b->next; b = b->next)
	{
		if (b->sync_time < t && b->synced == False) break;
	}

	if (!b || b->synced || sync_browse_entry(b))
	{
		/* leave entries (even ones already sync'd) for up to a minute.
		   this stops them getting re-sync'd too often */
		expire_browse_cache(t - 60);
	}
}


/****************************************************************************
find a server responsible for a workgroup, and sync browse lists
control ends up back here via response_name_query.
**************************************************************************/
void sync_server(enum cmd_type cmd, char *serv_name, char *work_name, int name_type,
		 struct in_addr ip)
{                     
	add_browser_entry(serv_name, name_type, work_name, 0, ip);

	if (cmd == MASTER_SERVER_CHECK)
	{
		/* announce ourselves as a master browser to serv_name */
		do_announce_request(myname, serv_name, 13, 0x20, 0, ip);
	}
}


/****************************************************************************
update workgroup database from a name registration
**************************************************************************/
void update_from_reg(char *name, int type, struct in_addr ip)
{                     
  /* default server type: minimum guess at requirement XXXX */

  DEBUG(4,("update from registration: host %s ip %s type %0x\n",
	    name, inet_ntoa(ip), type));

  /* workgroup types, but not a chat type */
  if (type >= 0x1b && type <= 0x1e)
    {
      struct work_record *work;
      struct domain_record *d;
      
      if (!(d    = find_domain(ip))) return;
      if (!(work = find_workgroupstruct(d, name, False))) return;
      
      /* request the server to announce if on our subnet */
      if (ip_equal(bcast_ip, d->bcast_ip)) announce_request(work, ip);
      
      /* domain master type or master browser type */
      if (type == 0x1b || type == 0x1d)
	{
	  struct hostent *hp = gethostbyaddr((char*)&ip, sizeof(ip), AF_INET);
	  if (hp) {
	    /* gethostbyaddr name may not match netbios name but who cares */
	    add_browser_entry(hp->h_name, type, work->work_group, 120, ip);
	  }
	}
    }
}


/****************************************************************************
  add the default workgroup into my domain
  **************************************************************************/
void add_my_domains(void)
{
	/* add or find domain on our local subnet, in the default workgroup */

	if (*lp_workgroup() != '*')
	{
		add_domain_entry(bcast_ip,Netmask,lp_workgroup(), True);
	}
}


/****************************************************************************
  send a backup list response.
  **************************************************************************/
static void send_backup_list(char *work_name, struct nmb_name *src_name,
			     int info_count, int token, int info,
			     int name_type, struct in_addr ip)
{                     
	struct domain_record *d;
	char outbuf[1024];
	char *p, *countptr, *nameptr;
	int count = 0;
	int i, j;
	char *theirname = src_name->name;

	DEBUG(3,("Backup list of %s to %s: %s(%x) %s(%x)\n", 
	          work_name, inet_ntoa(ip),
	          myname,0x20,theirname,0x0));	   
                                                               
	if (name_type == 0x1d)
	{
		DEBUG(4,("master browsers: "));
	}
	else if (name_type == 0x1b)
	{
		DEBUG(4,("domain controllers: "));
	}
	else
	{
		DEBUG(0,("backup request for unknown type %0x\n", name_type));
		return;
	}
	
	bzero(outbuf,sizeof(outbuf));
	p = outbuf;

	CVAL(p,0) = 10;    /* backup list response */
	p++;

	countptr = p; /* count pointer */
	
	SSVAL(p,1,token); /* sender's workgroup index representation */
	SSVAL(p,3,info); /* XXXX clueless: info, usually zero */
	p += 5;

	nameptr = p;

	for (d = domainlist; d; d = d->next)
	{
		struct work_record *work;

		for (work = d->workgrouplist; work; work = work->next)
		{
			struct server_record *s;
		
			if (!strequal(work->work_group, work_name)) continue;

			for (s = work->serverlist; s; s = s->next)
			{ 
				BOOL found = False;
				char *n;

				if (s->serv.type & SV_TYPE_DOMAIN_ENUM) continue;

				for (n = nameptr; n < p; n = skip_string(n, 1))
				{
					if (strequal(n, s->serv.name)) found = True;
				}

				if (found) continue; /* exclude names already added */

				/* workgroup request: include all backup browsers in the list */
				/* domain request: include all domain members in the list */

				if ((name_type == 0x1d && (s->serv.type & MASTER_TYPE)) ||
					(name_type == 0x1b && (s->serv.type & DOMCTL_TYPE)))
				{                          
					DEBUG(4, ("%s ", s->serv.name));

					count++;
					strcpy(p,s->serv.name);
					strupper(p);
					p = skip_string(p,1);
				}
			}
		}
	}

	if (count == 0)
	{
		DEBUG(4, ("none\n"));
		return;
	}
	else
	{
		DEBUG(4, (" - count %d\n", count));
	}

	CVAL(countptr,0) = count; /* total number of backup browsers found */

	{
		int len = PTR_DIFF(p, outbuf);

		for (i = 0; i < len; i+= 16)
		{
			DEBUG(4, ("%3x char ", i));

			for (j = 0; j < 16; j++)
			{
				unsigned char x = outbuf[i+j];
				if (x < 32 || x > 127) x = '.';

				if (i+j >= len) break;
				DEBUG(4, ("%c", x));
			}

			DEBUG(4, (" hex ", i));

			for (j = 0; j < 16; j++)
			{
				if (i+j >= len) break;
				DEBUG(4, (" %02x", outbuf[i+j]));
			}

			DEBUG(4, ("\n"));
		}

	}
	send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
	               myname,theirname,0x20,0,ip,myip);
}


/*******************************************************************
  same context: scope. should check name_type as well, and makes sure
  we don't process messages from ourselves
  ******************************************************************/
BOOL same_context(struct dgram_packet *dgram)
{
	if (!strequal(dgram->dest_name  .scope,scope )) return(True);
	if ( strequal(dgram->source_name.name ,myname)) return(True);

	return(False);
}


/*******************************************************************
  am I listening on a name. XXXX check the type of name as well.
  ******************************************************************/
BOOL listening_name(struct work_record *work, struct nmb_name *n)
{
	if (strequal(n->name,myname) ||
	    strequal(n->name,work->work_group) ||
	    strequal(n->name,MSBROWSE))
	{
		return(True);
	}

	return(False);
}


/*******************************************************************
  process a domain announcement frame

  Announce frames come in 3 types. Servers send host announcements
  (command=1) to let the master browswer know they are
  available. Master browsers send local master announcements
  (command=15) to let other masters and backups that they are the
  master. They also send domain announcements (command=12) to register
  the domain

  The comment field of domain announcements contains the master
  browser name. The servertype is used by NetServerEnum to select
  resources. We just have to pass it to smbd (via browser.dat) and let
  the client choose using bit masks.
  ******************************************************************/
static void process_announce(struct packet_struct *p,int command,char *buf)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	struct in_addr ip = dgram->header.source_ip;
	struct domain_record *d = find_domain(ip);

	int update_count = CVAL(buf,0);
	int ttl = IVAL(buf,1)/1000;
	char *name = buf+5;
	int osmajor=CVAL(buf,21);
	int osminor=CVAL(buf,22);
	uint32 servertype = IVAL(buf,23);
	char *comment = buf+31;
	struct work_record *work;
	char *work_name;
	char *serv_name = dgram->source_name.name;

	comment[43] = 0;

	DEBUG(3,("Announce(%d) %s(%x)",command,name,name[15]));
	DEBUG(3,("%s count=%d ttl=%d OS=(%d,%d) type=%08x comment=%s\n",
	   namestr(&dgram->dest_name),update_count,ttl,osmajor,osminor,
	   servertype,comment));

	name[15] = 0;  

	if (dgram->dest_name.name_type == 0 && command == 1)
	{
		DEBUG(2,("Announce to nametype(0) not supported yet\n"));
		return;
	}
	if (command == 12 && ((!strequal(dgram->dest_name.name, MSBROWSE)) ||
	    dgram->dest_name.name_type != 0x1))
	{
		DEBUG(0, ("Announce(%d) from %s should be __MSBROWSE__(1) not %s\n",
					command, inet_ntoa(ip), namestr(&dgram->dest_name)));
		return;
	}

	if (same_context(dgram)) return;

	if (command == 12)
	{
		work_name = name;
	}
	else
	{
		work_name = dgram->dest_name.name;
	}

	if (!(work = find_workgroupstruct(d, work_name, False))) return;

	DEBUG(4, ("workgroup %s on %s\n", work->work_group, serv_name));

	ttl = GET_TTL(ttl);

	/* add them to our browse list */
	add_server_entry(d,work,name,servertype,ttl,comment,True);

	/* make a selection of machines become backup browsers (1 in 10) */
	tell_become_backup();

	/* get their browse list from them and add it to ours. */
	add_browser_entry(serv_name,dgram->dest_name.name_type,
	                  work->work_group,30,ip);
}

/*******************************************************************
  process a master announcement frame
  ******************************************************************/
static void process_master_announce(struct packet_struct *p,char *buf)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	struct in_addr ip = dgram->header.source_ip;
	struct domain_record *d = find_domain(ip);
	struct domain_record *mydomain = find_domain(bcast_ip);
	char *name = buf;
	struct work_record *work;
	name[15] = 0;

	DEBUG(3,("Master Announce from %s (%s)\n",name,inet_ntoa(ip)));

	if (same_context(dgram)) return;

	if (!d || !mydomain) return;

	if (!lp_domain_master()) return;

    for (work = mydomain->workgrouplist; work; work = work->next)
	{
  		if (AM_MASTER(work))
		{
  			/* merge browse lists with them */
			add_browser_entry(name,0x1b, work->work_group,30,ip);
		}
	}
}

/*******************************************************************
  process a receive backup list request
  
  we receive a list of servers, and we attempt to locate them all on
  our local subnet, and sync browse lists with them on the workgroup
  they are said to be in.
  ******************************************************************/
static void process_rcv_backup_list(struct packet_struct *p,char *buf)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	struct in_addr ip = dgram->header.source_ip;
	int count = CVAL(buf,0);
	int Index = IVAL(buf,1); /* caller's index representing workgroup */
	char *buf1;

	DEBUG(3,("Receive Backup ack for %s from %s total=%d index=%d\n",
				namestr(&dgram->dest_name), inet_ntoa(ip),
				count, Index));

	if (same_context(dgram)) return;

	if (count <= 0) return;

	/* go through the list of servers attempting to sync browse lists */
	for (buf1 = buf+5; *buf1 && count; buf1 = skip_string(buf1, 1), --count)
	{
		struct in_addr back_ip;
		struct domain_record *d;

		DEBUG(4, ("Searching for backup browser %s at %s...\n",
				  buf1, inet_ntoa(ip)));

		/* XXXX assume name is a DNS name NOT a netbios name. a more complete
		   approach is to use reply_name_query functionality to find the name */
		back_ip = *interpret_addr2(buf1);

		if (zero_ip(back_ip))
		{
			DEBUG(4,("Failed to find backup browser server using DNS\n"));
			continue;
		}

		DEBUG(4,("Found browser server at %s\n", inet_ntoa(back_ip)));

		if ((d = find_domain(back_ip)))
		{
			struct domain_record *d1;
			for (d1 = domainlist; d1; d1 = d1->next)
			{
				struct work_record *work;
				for (work = d1->workgrouplist; work; work = work->next)
				{
					if (work->token == Index)
					{
						queue_netbios_packet(ClientNMB,NMB_QUERY,SERVER_CHECK,
						                 work->work_group,0x1d,0,
		                                 False,False,back_ip);
						return;
					}
				}
			}
		}
	}
}

/*******************************************************************
  process a send backup list request

  A client send a backup list request to ask for a list of servers on
  the net that maintain server lists for a domain. A server is then
  chosen from this list to send NetServerEnum commands to to list
  available servers.

  Currently samba only sends back one name in the backup list, its
  own. For larger nets we'll have to add backups and send "become
  backup" requests occasionally.
  ******************************************************************/
static void process_send_backup_list(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  struct in_addr ip = dgram->header.source_ip;
  struct domain_record *d; /* = find_domain(ip); */
  struct work_record *work;

  int count = CVAL(buf,0);
  int token = SVAL(buf,1); /* sender's key index for the workgroup? */
  int info  = SVAL(buf,3); /* XXXX don't know: some sort of info */
  int name_type = dgram->dest_name.name_type;

  DEBUG(0,("Send Backup request to %s token=%d info = %x count=%d\n",
	   namestr(&dgram->dest_name), token, info, count));
  
  if (same_context(dgram)) return;
  
  if (count <= 0) return;
  
  if (name_type != 0x1b && name_type != 0x1d)
    {
      DEBUG(0, ("backup request to wrong type %d\n", name_type));
      return;
    }
  
  for (d = domainlist; d; d = d->next)
    {
      for (work = d->workgrouplist; work; work = work->next)
	{
	  if (strequal(work->work_group, dgram->dest_name.name))
	    {
	      DEBUG(3, ("found workgroup %s(%d)\n",
			work->work_group, work->token));
	      send_backup_list(work->work_group,&dgram->source_name,
			       count,token,info,name_type,ip);
	      return;
	    }
	} 
    }
}


/*******************************************************************
  process a reset browser state

  diagnostic packet:
  0x1 - stop being a master browser
  0x2 - discard browse lists, stop being a master browser, try again.
  0x4 - stop being a master browser forever. no way. ain't gonna.
         
  ******************************************************************/
static void process_reset_browser(struct packet_struct *p,char *buf)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	int state = CVAL(buf,0);

	DEBUG(1,("Diagnostic browser reset request to %s state=0x%X\n",
	          namestr(&dgram->dest_name), state));

	/* stop being a master but still deal with being a backup browser */
	if (state & 0x1)
	{
		struct domain_record *d;
		for (d = domainlist; d; d = d->next)
		{
			struct work_record *work;
			for (work = d->workgrouplist; work; work = work->next)
			{
				if (AM_MASTER(work))
				{
					become_nonmaster(d,work);
				}
			}
		}
	}

	/* totally delete all servers and start afresh */
	if (state & 0x2)
	{
		struct domain_record *d;
		for (d = domainlist; d; d = d->next)
		{
			struct work_record *work;
			for (work=d->workgrouplist;work;work=remove_workgroup(d,work));
		}
		add_my_domains();
	}

	/* stop browsing altogether. i don't think this is a good idea! */
	if (state & 0x4)
	{
		DEBUG(1, ("ignoring request to stop being a browser. sorry!\n"));
	}
}


/*******************************************************************
  process a announcement request

  clients send these when they want everyone to send an announcement
  immediately. This can cause quite a storm of packets!
  ******************************************************************/
static void process_announce_request(struct packet_struct *p,char *buf)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	struct work_record *work;
	struct in_addr ip = dgram->header.source_ip;
	struct domain_record *d = find_domain(ip);
	int token = CVAL(buf,0);
	char *name = buf+1;

	name[15] = 0;

	DEBUG(3,("Announce request from %s to %s token=0x%X\n",
	          name,namestr(&dgram->dest_name), token));

	if (strequal(dgram->source_name.name,myname)) return;

	if (!d) return;

	if (!ip_equal(bcast_ip, d->bcast_ip)) return;

	for (work = d->workgrouplist; work; work = work->next)
	{
		if (strequal(dgram->dest_name.name,work->work_group)) 
		{
			work->needannounce = True;
		}
	}
}


/****************************************************************************
   process a domain logon packet
   **************************************************************************/
void process_logon_packet(struct packet_struct *p,char *buf,int len)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	struct in_addr ip = dgram->header.source_ip;
	struct domain_record *d = find_domain(ip);
	char *logname,*q;
	char *reply_name;
	BOOL add_slashes = False;
	pstring outbuf;
	int code,reply_code;
	struct work_record *work;

	if (!d) return;

	if (!(work = find_workgroupstruct(d,dgram->dest_name.name, False))) 
	  return;

   if (!lp_domain_logons()) {
     DEBUG(3,("No domain logons\n"));
     return;
   }
   if (!listening_name(work, &dgram->dest_name))
   {
     DEBUG(4,("Not listening to that domain\n"));
     return;
   }
 
   code = SVAL(buf,0);
   switch (code) {
   case 0:    
     {
       char *machine = buf+2;
       char *user = skip_string(machine,1);
       logname = skip_string(user,1);
       reply_code = 6;
       reply_name = myname;
       add_slashes = True;
       DEBUG(3,("Domain login request from %s(%s) user=%s\n",
 	       machine,inet_ntoa(p->ip),user));
     }
     break;
   case 7:    
     {
       char *machine = buf+2;
       logname = skip_string(machine,1);
       reply_code = 7;
       reply_name = lp_domain_controller();
       if (!*reply_name) {
 	DEBUG(3,("No domain controller configured\n"));
 	return;
       }
       DEBUG(3,("GETDC request from %s(%s)\n",
 	       machine,inet_ntoa(p->ip)));
     }
     break;
   default:
     DEBUG(3,("Unknown domain request %d\n",code));
     return;
   }
 
   bzero(outbuf,sizeof(outbuf));
   q = outbuf;
   SSVAL(q,0,reply_code);
   q += 2;
   if (add_slashes) {
     strcpy(q,"\\\\");
     q += 2;
   }
   StrnCpy(q,reply_name,16);
   strupper(q);
   q = skip_string(q,1);
   SSVAL(q,0,0xFFFF);
   q += 2;
 
   send_mailslot_reply(logname,ClientDGRAM,outbuf,PTR_DIFF(q,outbuf),
 		      myname,&dgram->source_name.name[0],0x20,0,p->ip,myip);  
 }
 

/****************************************************************************
depending on what announce has been made, we are only going to
accept certain types of name announce. XXXX untested code

check listening name type
****************************************************************************/
BOOL listening_type(struct packet_struct *p, int command)
{
	struct dgram_packet *dgram = &p->packet.dgram;
	int type = dgram->dest_name.name_type;

	switch (command)
	{
		case 1: /* host announce */
		{
			if (type != 0x0 || type != 0x20) return (False);
			break;
		}

		case 2: /* announce request */
		{
			return (True);
			break;
		}

		case 8: /* election */
		{
			return (True);
			break;
		}

		case 9: /* get backup list */
		{
			return (True);
			break;
		}

		case 10: /* receive backup list */
		{
			return (True);
			break;
		}

		case 12: /* domain announce */
		{
			if (type != 0x1b || type != 0x1c) return (False);
			break;
		}

		case 13: /* master announcement */
		{
			if (type != 0x1d) return (False);
			break;
		}

		case 15: /* local master announce */
		{
			if (type != 0x1c || type != 0x1d) return (False);
			break;
		}
	}
	return (True); /* we're not dealing with unknown packet types */
}


/****************************************************************************
process a browse frame
****************************************************************************/
void process_browse_packet(struct packet_struct *p,char *buf,int len)
{
	int command = CVAL(buf,0);
	switch (command) 
	{
		case 1: /* host announce */
		case 12: /* domain announce */
		case 15: /* local master announce */
		{
			process_announce(p,command,buf+1);
			break;
		}

		case 2: /* announce request */
		{
			process_announce_request(p,buf+1);
			break;
		}

		case 8: /* election */
		{
			process_election(p,buf+1);
			break;
		}

		case 9: /* get backup list */
		{
			process_send_backup_list(p,buf+1);
			break;
		}

		case 10: /* receive backup list */
		{
#ifdef TEST_CODE
			struct dgram_packet *dgram = &p->packet.dgram;
			int i, j;

			DEBUG(4, ("ignoring browse packet %d from %s %s to %s\n",
			           command, namestr(&dgram->source_name), 
			           inet_ntoa(p->ip), namestr(&dgram->dest_name)));

			for (i = 0; i < len; i+= 16)
			{
				DEBUG(4, ("%3x char ", i));

				for (j = 0; j < 16; j++)
				{
					unsigned char x = buf[i+j];
					if (x < 32 || x > 127) x = '.';

					if (i+j >= len) break;
					DEBUG(4, ("%c", x));
				}

				DEBUG(4, (" hex ", i));

				for (j = 0; j < 16; j++)
				{
					if (i+j >= len) break;
					DEBUG(4, (" %02x", buf[i+j]));
				}

				DEBUG(4, ("\n"));
			}

#endif /* TEST_CODE */
			process_rcv_backup_list(p, buf+1);
			break;
		}

		case 11: /* reset browser state */
		{
			process_reset_browser(p, buf+1);
			break;
		}

		case 13: /* master announcement */
		{
			process_master_announce(p,buf+1);
			break;
		}

#ifdef TEST_CODE
		default:
		{
			struct dgram_packet *dgram = &p->packet.dgram;
			int i, j;

			DEBUG(4, ("ignoring browse packet %d from %s %s to %s\n",
			           command, namestr(&dgram->source_name), 
			           inet_ntoa(p->ip), namestr(&dgram->dest_name)));

			for (i = 0; i < len; i+= 16)
			{
				DEBUG(4, ("%3x char ", i));

				for (j = 0; j < 16; j++)
				{
					unsigned char x = buf[i+j];
					if (x < 32 || x > 127) x = '.';

					if (i+j >= len) break;
					DEBUG(4, ("%c", x));
				}

				DEBUG(4, (" hex ", i));

				for (j = 0; j < 16; j++)
				{
					if (i+j >= len) break;
					DEBUG(4, (" %02x", buf[i+j]));
				}

				DEBUG(4, ("\n"));
			}

		}
#endif /* TEST_CODE */
	}
}


/****************************************************************************
process udp 138 datagrams
****************************************************************************/
void process_dgram(struct packet_struct *p)
{
  char *buf;
  char *buf2;
  int len;
  struct dgram_packet *dgram = &p->packet.dgram;

  if (dgram->header.msg_type != 0x10 &&
      dgram->header.msg_type != 0x11 &&
      dgram->header.msg_type != 0x12) {
    /* don't process error packets etc yet */
    return;
  }

  buf = &dgram->data[0];
  buf -= 4; /* XXXX for the pseudo tcp length - 
	       someday I need to get rid of this */

  if (CVAL(buf,smb_com) != SMBtrans) return;

  len = SVAL(buf,smb_vwv11);
  buf2 = smb_base(buf) + SVAL(buf,smb_vwv12);

  DEBUG(3,("datagram from %s to %s for %s of type %d len=%d\n",
	   namestr(&dgram->source_name),namestr(&dgram->dest_name),
	   smb_buf(buf),CVAL(buf2,0),len));

 
  if (len <= 0) return;

   if (strequal(smb_buf(buf),"\\MAILSLOT\\BROWSE"))
   {
     process_browse_packet(p,buf2,len);
   } else if (strequal(smb_buf(buf),"\\MAILSLOT\\NET\\NETLOGON")) {
     process_logon_packet(p,buf2,len);
   }
}

