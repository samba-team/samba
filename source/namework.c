/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1996
   
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

extern int ClientNMB;
extern int ClientDGRAM;

#define TEST_CODE /* want to debug unknown browse packets */

extern int DEBUGLEVEL;
extern pstring scope;
extern BOOL CanRecurse;

extern pstring myname;

extern int ClientNMB;
extern int ClientDGRAM;

extern struct in_addr ipzero;

extern int workgroup_count; /* total number of workgroups we know about */

/* this is our domain/workgroup/server database */
extern struct subnet_record *subnetlist;

extern int  updatecount;

/* backup request types: which servers are to be included */
#define MASTER_TYPE (SV_TYPE_MASTER_BROWSER)
#define DOMCTL_TYPE (SV_TYPE_DOMAIN_CTRL   )

extern time_t StartupTime;

extern BOOL updatedlists;

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

  CVAL(p,0) = ANN_ResetBrowserState;
  CVAL(p,2) = state; 
  p += 2;

  DEBUG(2,("sending reset to %s %s of state %d\n",
	   name,inet_ntoa(ip),state));

  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,name,0x20,0x1d,ip,*iface_ip(ip));
}


/****************************************************************************
tell a server to become a backup browser
**************************************************************************/
void tell_become_backup(void)
{
  /* XXXX note: this function is currently unsuitable for use, as it
     does not properly check that a server is in a fit state to become
     a backup browser before asking it to be one.
   */

  struct subnet_record *d;
  for (d = subnetlist; d; d = d->next)
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
	      
	      if (s->serv.type & SV_TYPE_BACKUP_BROWSER) {
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
	      
	      DEBUG(2,("sending become backup to %s %s for %s\n",
		       s->serv.name, inet_ntoa(d->bcast_ip),
		       work->work_group));
	      
	      /* type 11 request from MYNAME(20) to WG(1e) for SERVER */
	      do_announce_request(s->serv.name, work->work_group,
				  ANN_BecomeBackup, 0x20, 0x1e, d->bcast_ip);
	    }
	}
    }
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
static void process_announce(struct packet_struct *p,uint16 command,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  struct in_addr ip = dgram->header.source_ip;
  struct subnet_record *d = find_subnet(ip); 
  int update_count = CVAL(buf,0);

  int ttl = IVAL(buf,1)/1000;
  char *name = buf+5;
  int osmajor=CVAL(buf,21);
  int osminor=CVAL(buf,22);
  uint32 servertype = IVAL(buf,23);
  uint32 browse_type= CVAL(buf,27);
  uint32 browse_sig = CVAL(buf,29);
  char *comment = buf+31;

  struct work_record *work;
  char *work_name;
  char *serv_name = dgram->source_name.name;
  BOOL add = False;

  comment[43] = 0;
  
  DEBUG(4,("Announce(%d) %s(%x)",command,name,name[15]));
  DEBUG(4,("%s count=%d ttl=%d OS=(%d,%d) type=%08x sig=%4x %4x comment=%s\n",
	   namestr(&dgram->dest_name),update_count,ttl,osmajor,osminor,
	   servertype,browse_type,browse_sig,comment));
  
  name[15] = 0;  
  
  if (dgram->dest_name.name_type == 0 && command == ANN_HostAnnouncement)
    {
      DEBUG(2,("Announce to nametype(0) not supported yet\n"));
      return;
    }

  if (command == ANN_DomainAnnouncement && 
      ((!strequal(dgram->dest_name.name, MSBROWSE)) ||
       dgram->dest_name.name_type != 0x1))
    {
      DEBUG(0,("Announce(%d) from %s should be __MSBROWSE__(1) not %s\n",
		command, inet_ntoa(ip), namestr(&dgram->dest_name)));
      return;
    }
  
  if (!strequal(dgram->dest_name.scope,scope )) return;
  
  if (command == ANN_DomainAnnouncement) { 
    /* XXXX if we are a master browser for the workgroup work_name,
       then there is a local subnet configuration problem. only
       we should be sending out such domain announcements, because
       as the master browser, that is our job.

       stop being a master browser, and force an election. this will
       sort out the network problem. hopefully.
     */

    work_name = name;
    add = True;
  } else {
    work_name = dgram->dest_name.name;
  }

  /* we need some way of finding out about new workgroups
     that appear to be sending packets to us. The name_type checks make
     sure we don't add host names as workgroups */
  if (command == ANN_HostAnnouncement &&
      (dgram->dest_name.name_type == 0x1d ||
       dgram->dest_name.name_type == 0x1e))
    add = True;
  
  if (!(work = find_workgroupstruct(d, work_name,add)))
    return;
  
  DEBUG(4, ("workgroup %s on %s\n", work->work_group, serv_name));
  
  ttl = GET_TTL(ttl);
  
  /* add them to our browse list, and update the browse.dat file */
  add_server_entry(d,work,name,servertype,ttl,comment,True);
  updatedlists = True;

#if 0
  /* the tell become backup code is broken, no great harm is done by
     disabling it */
  tell_become_backup();
#endif

  /* get the local_only browse list from the local master and add it 
     to ours. */
  if (command == ANN_LocalMasterAnnouncement)
  {
    add_browser_entry(serv_name,dgram->dest_name.name_type,
		      work->work_group,30,ip,True);
  }
}

/*******************************************************************
  process a master announcement frame
  ******************************************************************/
static void process_master_announce(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  struct in_addr ip = dgram->header.source_ip;
  struct subnet_record *d = find_subnet(ip);
  struct subnet_record *mydomain = find_subnet(*iface_bcast(ip));
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
	  add_browser_entry(name,0x1b, work->work_group,30,ip,True);
    }
  }
}

/*******************************************************************
  process a receive backup list request
  
  we receive a list of servers, and we attempt to locate them all on
  our local subnet, and sync browse lists with them on the workgroup
  they are said to be in.

  XXXX NOTE: this function is in overdrive. it should not really do
  half of what it actually does (it should pick _one_ name from the
  list received and sync with it at regular intervals, rather than
  sync with them all only once!)

  ******************************************************************/
static void process_rcv_backup_list(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  struct in_addr ip = dgram->header.source_ip;
  int count = CVAL(buf,0);
  uint32 info = IVAL(buf,1); /* XXXX caller's incremental info */
  char *buf1;
  
  DEBUG(3,("Receive Backup ack for %s from %s total=%d info=%d\n",
	   namestr(&dgram->dest_name), inet_ntoa(ip),
	   count, info));
  
  if (same_context(dgram)) return;
  
  if (count <= 0) return;
  
  /* go through the list of servers attempting to sync browse lists */
  for (buf1 = buf+5; *buf1 && count; buf1 = skip_string(buf1, 1), --count)
  {
    struct in_addr back_ip;
    struct subnet_record *d;
      
    DEBUG(4,("Searching for backup browser %s at %s...\n",
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
      DEBUG(4,("END THIS LOOP: CODE NEEDS UPDATING\n"));
      
      /* XXXX function needs work */
	  continue;

    if ((d = find_subnet(back_ip)))
	{
	  struct subnet_record *d1;
	  for (d1 = subnetlist; d1; d1 = d1->next)
	  {
	      struct work_record *work;
	      for (work = d1->workgrouplist; work; work = work->next)
		{
		  if (work->token == 0 /* token */)
		  {
		      queue_netbios_packet(d1,ClientNMB,NMB_QUERY,NAME_QUERY_SRV_CHK,
					   work->work_group,0x1d,
                       0,0,0,NULL,NULL,
					   False,False,back_ip,back_ip);
		      return;
		  }
		}
	  }
	}
  }
}


/****************************************************************************
  send a backup list response.
  **************************************************************************/
static void send_backup_list(char *work_name, struct nmb_name *src_name,
			     int token, uint32 info,
			     int name_type, struct in_addr ip)
{                     
  char outbuf[1024];
  char *p, *countptr, *nameptr;
  int count = 0;
  char *theirname = src_name->name;
  
  DEBUG(3,("sending backup list of %s to %s: %s(%x) %s(%x)\n", 
	   work_name, inet_ntoa(ip),
	   myname,0x0,theirname,0x0));	   
  
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
  
  CVAL(p,0) = ANN_GetBackupListResp;    /* backup list response */
  
  p++;
  countptr = p;

  SIVAL(p,1,info); /* the sender's unique info */

  p += 5;
  
  nameptr = p;

#if 0

  for (d = subnetlist; d; d = d->next)
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

#endif

	count++;
	strcpy(p,myname);
	strupper(p);
	p = skip_string(p,1);

  if (count == 0)
    {
      DEBUG(4, ("none\n"));
    }
  else
    {
      DEBUG(4, (" - count %d\n", count));
    }
  
  CVAL(countptr, 0) = count;

  {
    int len = PTR_DIFF(p, outbuf);
    debug_browse_data(outbuf, len);
  }
  send_mailslot_reply(BROWSE_MAILSLOT,ClientDGRAM,outbuf,PTR_DIFF(p,outbuf),
		      myname,theirname,0x0,0x0,ip,*iface_ip(ip));
}


/*******************************************************************
  process a send backup list request

  A client sends a backup list request to ask for a list of servers on
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
  struct subnet_record *d;
  struct work_record *work;

  int    token = CVAL(buf,0); /* sender's key index for the workgroup */
  uint32 info  = IVAL(buf,1); /* XXXX don't know: some sort of info */
  int name_type = dgram->dest_name.name_type;

  if (same_context(dgram)) return;
  
  if (name_type != 0x1b && name_type != 0x1d) {
    DEBUG(0,("backup request to wrong type %d from %s\n",
	      name_type,inet_ntoa(ip)));
    return;
  }
  
  for (d = subnetlist; d; d = d->next)
    {
      for (work = d->workgrouplist; work; work = work->next)
	{
	  if (strequal(work->work_group, dgram->dest_name.name))
	    {
	      DEBUG(2,("sending backup list to %s %s id=%x\n",
		       namestr(&dgram->dest_name),inet_ntoa(ip),info));
  
	      send_backup_list(work->work_group,&dgram->source_name,
			       token,info,name_type,ip);
	      return;
	    }
	} 
    }
}


/*******************************************************************
  process a reset browser state

  diagnostic packet:
  0x1 - stop being a master browser and become a backup browser.
  0x2 - discard browse lists, stop being a master browser, try again.
  0x4 - stop being a master browser forever. no way. ain't gonna.
         
  ******************************************************************/
static void process_reset_browser(struct packet_struct *p,char *buf)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  int state = CVAL(buf,0);

  DEBUG(1,("received diagnostic browser reset request to %s state=0x%X\n",
	   namestr(&dgram->dest_name), state));

  /* stop being a master but still deal with being a backup browser */
  if (state & 0x1)
    {
      struct subnet_record *d;
      for (d = subnetlist; d; d = d->next)
	{
	  struct work_record *work;
	  for (work = d->workgrouplist; work; work = work->next)
	    {
	      if (AM_MASTER(work))
		{
		  become_nonmaster(d,work,SV_TYPE_DOMAIN_MASTER|SV_TYPE_MASTER_BROWSER);
		}
	    }
	}
    }
  
  /* XXXX documentation inconsistency: the above description does not
     exactly tally with what is implemented for state & 0x2
   */

  /* totally delete all servers and start afresh */
  if (state & 0x2)
    {
      struct subnet_record *d;
      for (d = subnetlist; d; d = d->next)
	{
	  struct work_record *work;
	  for (work=d->workgrouplist;work;work=remove_workgroup(d,work,True));
	}
      add_my_subnets(lp_workgroup());
    }
  
  /* stop browsing altogether. i don't think this is a good idea! */
  if (state & 0x4)
    {
      DEBUG(1,("ignoring request to stop being a browser. sorry!\n"));
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
  struct subnet_record *d = find_subnet(ip);
  int token = CVAL(buf,0);
  char *name = buf+1;
  
  name[15] = 0;
  
  DEBUG(3,("Announce request from %s to %s token=0x%X\n",
	   name,namestr(&dgram->dest_name), token));
  
  if (strequal(dgram->source_name.name,myname)) return;
  
  /* XXXX BUG or FEATURE?: need to ensure that we are a member of
     this workgroup before announcing, particularly as we only
     respond on local interfaces anyway.

     if (strequal(dgram->dest_name, lp_workgroup()) return; ???
   */

  if (!d) return;
  
  for (work = d->workgrouplist; work; work = work->next)
    {
     /* XXXX BUG: the destination name type should also be checked,
        not just the name. e.g if the name is WORKGROUP(0x1d) then
        we should only respond if we own that name */
    
      if (strequal(dgram->dest_name.name,work->work_group)) 
	{
	  work->needannounce = True;
	}
    }
}



/****************************************************************************
process a browse frame
****************************************************************************/
void process_browse_packet(struct packet_struct *p,char *buf,int len)
{
  int command = CVAL(buf,0);
  switch (command) 
    {
    case ANN_HostAnnouncement:
    case ANN_DomainAnnouncement:
    case ANN_LocalMasterAnnouncement:
      {
        debug_browse_data(buf, len);
	process_announce(p,command,buf+1);
	break;
      }
      
    case ANN_AnnouncementRequest:
      {
	process_announce_request(p,buf+1);
	break;
      }
      
    case ANN_Election:
      {
	process_election(p,buf+1);
	break;
      }
      
    case ANN_GetBackupListReq:
      {
        debug_browse_data(buf, len);
	process_send_backup_list(p,buf+1);
	break;
      }
      
    case ANN_GetBackupListResp:
    {
        debug_browse_data(buf, len);
        process_rcv_backup_list(p, buf+1);
        break;
    }
      
    case ANN_ResetBrowserState:
      {
	process_reset_browser(p, buf+1);
	break;
      }
      
    case ANN_MasterAnnouncement:
      {
	process_master_announce(p,buf+1);
	break;
      }
      
    default:
      {
	struct dgram_packet *dgram = &p->packet.dgram;
	DEBUG(4,("ignoring browse packet %d from %s %s to %s\n",
		 command, namestr(&dgram->source_name), 
		 inet_ntoa(p->ip), namestr(&dgram->dest_name)));
      }
    }
}


