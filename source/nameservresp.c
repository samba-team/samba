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

   Module name: nameservresp.c

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   05 jul 96: lkcl@pires.co.uk
   created module nameservresp containing NetBIOS response functions

*/

#include "includes.h"

extern int ClientNMB;

extern int DEBUGLEVEL;

extern pstring scope;
extern fstring myworkgroup;
extern struct in_addr ipzero;
extern struct in_addr wins_ip;
extern struct in_addr ipzero;


#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())


/****************************************************************************
  response for a reg release received. samba has asked a WINS server if it
  could release a name.
  **************************************************************************/
static void response_name_release(struct nmb_name *ans_name,
			struct subnet_record *d, struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = ans_name->name;
  int   type = ans_name->name_type;
  
  DEBUG(4,("response name release received\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata)
  {
    /* IMPORTANT: see expire_netbios_response_entries() */

    struct in_addr found_ip;
    putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
    /* NOTE: we only release our own names at present */
    if (ismyip(found_ip))
    {
      name_unregister_work(d,name,type);
    }
    else
    {
      DEBUG(2,("name release for different ip! %s %s\n",
                  inet_ntoa(found_ip), namestr(ans_name)));
    }
  }
  else
  {
    DEBUG(2,("name release for %s rejected!\n", namestr(ans_name)));

    /* XXXX PANIC! what to do if it's one of samba's own names? */

    /* XXXX do we honestly care if our name release was rejected? 
       only if samba is issuing the release on behalf of some out-of-sync
       server. if it's one of samba's SELF names, we don't care. */
  }
}


/****************************************************************************
response for a reg request received
**************************************************************************/
static void response_name_reg(struct nmb_name *ans_name,
			struct subnet_record *d, struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  BOOL bcast = nmb->header.nm_flags.bcast;
  char *name = ans_name->name;
  int   type = ans_name->name_type;
  
  DEBUG(4,("response name registration received!\n"));
  
#if 1
  /* This code is neccesitated due to bugs in earlier versions of
     Samba (up to 1.9.16p11). They respond to a broadcast
     name registration of WORKGROUP<1b> when they should
     not. Hence, until these versions are gone, we should
     treat such errors as success for this particular
     case only. jallison@whistle.com.
   */
  if ( ((d != wins_subnet) && (nmb->header.rcode == 6) && strequal(myworkgroup, name) &&
         (type == 0x1b)) ||
       (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata))
#else
  if (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata)
#endif
  {
    /* IMPORTANT: see expire_netbios_response_entries() */

    int nb_flags = nmb->answers->rdata[0];
    int ttl = nmb->answers->ttl;
    struct in_addr found_ip;

    putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
    name_register_work(d,name,type,nb_flags,ttl,found_ip,bcast);
  }
  else
  {
    DEBUG(2,("name registration for %s rejected by ip %s!\n", 
              namestr(ans_name), inet_ntoa(p->ip)));

	/* oh dear. we have problems. possibly unbecome a master browser. */
    name_unregister_work(d,name,type);
  }
}

/****************************************************************************
  response from a name query server check. states of type NAME_QUERY_DOM_SRV_CHK,
  NAME_QUERY_SRV_CHK, and NAME_QUERY_FIND_MST dealt with here.
  ****************************************************************************/
static void response_server_check(struct nmb_name *ans_name, 
        struct response_record *n, struct subnet_record *d, struct packet_struct *p)
{
    struct nmb_packet *nmb = &p->packet.nmb;
    struct in_addr send_ip;
    enum state_type cmd;

    /* This next fix was from Bernhard Laeser <nlaesb@ascom.ch>
       who noticed we were replying directly back to the server
       we sent to - rather than reading the response.
     */

    if (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata)
      putip((char*)&send_ip,&nmb->answers->rdata[2]);
    else
      {
      
        DEBUG(2,("response_server_check: name query for %s failed\n", 
              namestr(ans_name)));
        return;
      }

    /* issue another state: this time to do a name status check */

    cmd = (n->state == NAME_QUERY_DOM_SRV_CHK) ?
	      NAME_STATUS_DOM_SRV_CHK : NAME_STATUS_SRV_CHK;

    /* initiate a name status check on address given in the reply
       record. In addition, the workgroup being checked has been stored
       in the response_record->my_name (see announce_master) we
       also propagate this into the same field. */
    queue_netbios_packet(d,ClientNMB,NMB_STATUS, cmd,
				ans_name->name, ans_name->name_type,
				0,0,0,n->my_name,NULL,
				False,False,send_ip,n->reply_to_ip, 0);
}


/****************************************************************************
  interpret a node status response. this is pretty hacked: we need two bits of
  info. a) the name of the workgroup b) the name of the server. it will also
  add all the names it finds into the namelist.
****************************************************************************/
static BOOL interpret_node_status(struct subnet_record *d,
				char *p, struct nmb_name *name,int t,
			   char *serv_name, struct in_addr ip, BOOL bcast)
{
  int numnames = CVAL(p,0);
  BOOL found = False;

  DEBUG(4,("received %d names\n",numnames));

  p += 1;

  if (serv_name) *serv_name = 0;

  while (numnames--)
    {
      char qname[17];
      int type;
      fstring flags;
      int nb_flags;
      
      BOOL group = False;
      BOOL add   = False;
      
      *flags = 0;
      
      StrnCpy(qname,p,15);
      type = CVAL(p,15);
      nb_flags = p[16];
      trim_string(qname,NULL," ");
      
      p += 18;
      
      if (NAME_GROUP    (nb_flags)) { strcat(flags,"<GROUP> "); group=True;}
      if (NAME_BFLAG    (nb_flags)) { strcat(flags,"B "); }
      if (NAME_PFLAG    (nb_flags)) { strcat(flags,"P "); }
      if (NAME_MFLAG    (nb_flags)) { strcat(flags,"M "); }
      if (NAME_HFLAG    (nb_flags)) { strcat(flags,"H "); }
      if (NAME_DEREG    (nb_flags)) { strcat(flags,"<DEREGISTERING> "); }
      if (NAME_CONFLICT (nb_flags)) { strcat(flags,"<CONFLICT> "); }
      if (NAME_ACTIVE   (nb_flags)) { strcat(flags,"<ACTIVE> "); add=True; }
      if (NAME_PERMANENT(nb_flags)) { strcat(flags,"<PERMANENT> "); add=True;}

      /* we want the server name */
      if (serv_name && !*serv_name && !group && type == 0x20)
	{
	  StrnCpy(serv_name,qname,15);
	  serv_name[15] = 0;
	}
      
      /* looking for a name and type? */
      if (name && !found && (t == type))
	{
	  /* take a guess at some of the name types we're going to ask for.
	     evaluate whether they are group names or no... */
	  if (((t == 0x1b || t == 0x1d || t == 0x20 ) && !group) ||
	      ((t == 0x1c || t == 0x1e              ) &&  group))
	    {
	      found = True;
	      make_nmb_name(name,qname,type,scope);
	    }
	}
      
      DEBUG(4,("\t%s(0x%x)\t%s\n",qname,type,flags));
    }
  DEBUG(4,("num_good_sends=%d num_good_receives=%d\n",
	       IVAL(p,20),IVAL(p,24)));
  return found;
}


/****************************************************************************
  response from a name status check. states of type NAME_STATUS_DOM_SRV_CHK
  and NAME_STATUS_SRV_CHK dealt with here.
  ****************************************************************************/
static void response_name_status_check(struct in_addr ip,
		struct nmb_packet *nmb, BOOL bcast,
		struct response_record *n, struct subnet_record *d)
{
	/* NMB_STATUS arrives: contains workgroup name and server name required.
       amongst other things. */

	struct nmb_name name;
	fstring serv_name;

	if (nmb->answers && 
	    interpret_node_status(d,nmb->answers->rdata,
	                          &name,0x20,serv_name,ip,bcast))
	{
		if (*serv_name)
		{
                        /* response_record->my_name contains the
                           workgroup name to sync with. See 
                           response_server_check() */
			sync_server(n->state,serv_name,
			            n->my_name,name.name_type, d, n->send_ip);
		}
	}
	else
	{
		DEBUG(1,("No 0x20 name type in interpret_node_status()\n"));
	}
}


/****************************************************************************
  response from a name query for secured WINS registration. a state of
  NAME_REGISTER_CHALLENGE is dealt with here.
  ****************************************************************************/
static void response_name_query_register(struct nmb_packet *nmb, 
		struct nmb_name *ans_name, 
		struct response_record *n, struct subnet_record *d)
{
	struct in_addr register_ip;
	BOOL new_owner;

	DEBUG(4, ("Name query at %s ip %s - ",
		  namestr(&n->name), inet_ntoa(n->send_ip)));

	if (!name_equal(&n->name, ans_name))
	{
		/* someone gave us the wrong name as a reply. oops. */
		/* XXXX should say to them 'oi! release that name!' */

		DEBUG(4,("unexpected name received: %s\n", namestr(ans_name)));
		return;
	}

	if (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata)
    {
		/* we had sent out a name query to the current owner
		   of a name because someone else wanted it. now they
		   have responded saying that they still want the name,
		   so the other host can't have it.
		 */

		/* first check all the details are correct */

		int nb_flags = nmb->answers->rdata[0];
		struct in_addr found_ip;

		putip((char*)&found_ip,&nmb->answers->rdata[2]);

		if (nb_flags != n->nb_flags)
		{
			/* someone gave us the wrong nb_flags as a reply. oops. */
			/* XXXX should say to them 'oi! release that name!' */

			DEBUG(4,("expected nb_flags: %d\n", n->nb_flags));
			DEBUG(4,("unexpected nb_flags: %d\n", nb_flags));
			return;
		}

		if (!ip_equal(n->send_ip, found_ip))
		{
			/* someone gave us the wrong ip as a reply. oops. */
			/* XXXX should say to them 'oi! release that name!' */

			DEBUG(4,("expected ip: %s\n", inet_ntoa(n->send_ip)));
			DEBUG(4,("unexpected ip: %s\n", inet_ntoa(found_ip)));
			return;
		}

		DEBUG(4, (" OK: %s\n", inet_ntoa(found_ip)));

		/* fine: now tell the other host they can't have the name */
		register_ip = n->send_ip;
		new_owner = False;
	}
	else
	{
		DEBUG(4, (" NEGATIVE RESPONSE!\n"));

		/* the owner didn't want the name: the other host can have it */
		register_ip = n->reply_to_ip;
		new_owner = True;
	}

	/* register the old or the new owners' ip */
	add_name_respond(d, n->fd, d->myip, n->reply_id,&n->name,n->nb_flags,
					GET_TTL(0), register_ip,
					new_owner, n->reply_to_ip);

	remove_response_record(d,n); /* remove the response record */
}


/****************************************************************************
  response from a name query to sync browse lists or to update our netbios
  entry. states of type NAME_QUERY_SYNC and NAME_QUERY_CONFIRM 
  ****************************************************************************/
static void response_name_query_sync(struct nmb_packet *nmb, 
		struct nmb_name *ans_name, BOOL bcast,
		struct response_record *n, struct subnet_record *d)
{
  DEBUG(4, ("Name query at %s ip %s - ",
	    namestr(&n->name), inet_ntoa(n->send_ip)));

  if (!name_equal(&n->name, ans_name))
    {
      /* someone gave us the wrong name as a reply. oops. */
      DEBUG(4,("unexpected name received: %s\n", namestr(ans_name)));
      return;
    }

  if (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata)
    {
      int nb_flags = nmb->answers->rdata[0];
      struct in_addr found_ip;
      
      putip((char*)&found_ip,&nmb->answers->rdata[2]);
      
      if (!ip_equal(n->send_ip, found_ip))
	{
	  /* someone gave us the wrong ip as a reply. oops. */
	  DEBUG(4,("expected ip: %s\n", inet_ntoa(n->send_ip)));
	  DEBUG(4,("unexpected ip: %s\n", inet_ntoa(found_ip)));
	  return;
	}

      DEBUG(4, (" OK: %s\n", inet_ntoa(found_ip)));
      
      if (n->state == NAME_QUERY_SYNC_LOCAL ||
	  n->state == NAME_QUERY_SYNC_REMOTE)
	{
	  struct work_record *work = NULL;
	  /* We cheat here as we know that the workgroup name has
	     been placed in the my_comment field of the 
	     response_record struct by the code in 
	     start_sync_browse_entry().
	  */
	  if ((work = find_workgroupstruct(d, n->my_comment, False)))
	    {
	      BOOL local_list_only = n->state == NAME_QUERY_SYNC_LOCAL;
	      
	      /* the server is there: sync quick before it (possibly) dies! */
	      sync_browse_lists(d, work, ans_name->name, ans_name->name_type,
				found_ip, local_list_only);
	    }
	}
      else
	{
	  /* update our netbios name list (re-register it if necessary) */
	  add_netbios_entry(d, ans_name->name, ans_name->name_type,
			    nb_flags,GET_TTL(0),REGISTER,
			    found_ip,False,!bcast);
	}
    }
  else
    {
      DEBUG(4, (" NEGATIVE RESPONSE!\n"));
      
      if (n->state == NAME_QUERY_CONFIRM)
	{
	  /* XXXX remove_netbios_entry()? */
	  /* lots of things we ought to do, here. if we get here,
	     then we're in a mess: our name database doesn't match
	     reality. sort it out
             */
	  remove_netbios_name(d,n->name.name, n->name.name_type,
			      REGISTER,n->send_ip);
	}
    }
}

/****************************************************************************
  response from a name query for DOMAIN<1b>
  NAME_QUERY_DOMAIN is dealt with here - we are trying to become a domain
  master browser and WINS replied - check it's our address.
  ****************************************************************************/
static void response_name_query_domain(struct nmb_name *ans_name,
                struct nmb_packet *nmb,
                struct response_record *n, struct subnet_record *d)
{
  DEBUG(4, ("response_name_query_domain: Got %s response from %s for query \
for %s\n", nmb->header.rcode == 0 ? "success" : "failure",
           inet_ntoa(n->send_ip), namestr(ans_name)));

  /* Check the name is correct and ip address returned is our own. If it is then we
     just remove the response record.
   */
  if (name_equal(&n->name, ans_name) && (nmb->header.rcode == 0) && nmb->answers && (nmb->answers->rdata))
  {
    struct in_addr found_ip;

    putip((char*)&found_ip,&nmb->answers->rdata[2]);
    /* Samba 1.9.16p11 servers seem to return the broadcast address for this
       query. */
    if (ismyip(found_ip) || ip_equal(wins_ip, found_ip) || ip_equal(ipzero, found_ip))
    {
      DEBUG(4, ("response_name_query_domain: WINS server returned our ip \
address. Pretending we never received response.\n"));
      n->num_msgs = 0;
      n->repeat_count = 0;
      n->repeat_time = 0;
    }
    else
    {
      DEBUG(0,("response_name_query_domain: WINS server already has a \
domain master browser registered %s at address %s\n", 
           namestr(ans_name), inet_ntoa(found_ip)));
    }
  }
  else
  {
    /* Negative/incorrect response. No domain master
       browser was registered - pretend we didn't get this response.
     */
    n->num_msgs = 0;
    n->repeat_count = 0;
    n->repeat_time = 0;
  }

}

/****************************************************************************
  report the response record type
  ****************************************************************************/
static void debug_rr_type(int rr_type)
{
  switch (rr_type)
    {
    case NMB_STATUS: DEBUG(3,("Name status ")); break;
    case NMB_QUERY : DEBUG(3,("Name query ")); break;
    case NMB_REG   : DEBUG(3,("Name registration ")); break;
    case NMB_REL   : DEBUG(3,("Name release ")); break;
    default        : DEBUG(1,("wrong response packet type received")); break;
    }
}

/****************************************************************************
  report the response record nmbd state
  ****************************************************************************/
void debug_state_type(int state)
{
  /* report the state type to help debugging */
  switch (state)
    {
    case NAME_QUERY_DOM_SRV_CHK  : DEBUG(4,("NAME_QUERY_DOM_SRV_CHK\n")); break;
    case NAME_QUERY_SRV_CHK      : DEBUG(4,("NAME_QUERY_SRV_CHK\n")); break;
    case NAME_QUERY_FIND_MST     : DEBUG(4,("NAME_QUERY_FIND_MST\n")); break;
    case NAME_QUERY_MST_CHK      : DEBUG(4,("NAME_QUERY_MST_CHK\n")); break;
    case NAME_QUERY_CONFIRM      : DEBUG(4,("NAME_QUERY_CONFIRM\n")); break;
    case NAME_QUERY_SYNC_LOCAL   : DEBUG(4,("NAME_QUERY_SYNC_LOCAL\n")); break;
    case NAME_QUERY_SYNC_REMOTE  : DEBUG(4,("NAME_QUERY_SYNC_REMOTE\n")); break;
    case NAME_QUERY_DOMAIN       : DEBUG(4,("NAME_QUERY_DOMAIN\n")); break;
      
    case NAME_REGISTER           : DEBUG(4,("NAME_REGISTER\n")); break;
    case NAME_REGISTER_CHALLENGE : DEBUG(4,("NAME_REGISTER_CHALLENGE\n"));break;
      
    case NAME_RELEASE            : DEBUG(4,("NAME_RELEASE\n")); break;
      
    case NAME_STATUS_DOM_SRV_CHK : DEBUG(4,("NAME_STATUS_DOM_SRV_CHK\n")); break;
    case NAME_STATUS_SRV_CHK     : DEBUG(4,("NAME_STATUS_SRV_CHK\n")); break;
      
    default: break;
    }
}

/****************************************************************************
  report any problems with the fact that a response has been received.

  (responses for certain types of operations are only expected from one host)
  ****************************************************************************/
static BOOL response_problem_check(struct response_record *n,
			struct nmb_packet *nmb, char *ans_name)
{
  switch (nmb->answers->rr_type)
    {
    case NMB_REL:
      {
        if (n->num_msgs > 1)
	  {
            DEBUG(1,("more than one release name response received!\n"));
            return True;
	  }
        break;
      }

    case NMB_REG:
      {
        if (n->num_msgs > 1)
	  {
            DEBUG(1,("more than one register name response received!\n"));
            return True;
	  }
        break;
      }
    
    case NMB_QUERY:
      { 
	if (n->num_msgs > 1)
	  {
	    if (nmb->header.rcode == 0 && nmb->answers && nmb->answers->rdata)
	      {
		int nb_flags = nmb->answers->rdata[0];
		
		if ((!NAME_GROUP(nb_flags)))
		  {
		    /* oh dear. more than one person responded to a 
		       unique name.
		       there is either a network problem, a 
		       configuration problem
		       or a server is mis-behaving */
		    
		    /* XXXX mark the name as in conflict, and then let the
		       person who just responded know that they 
		       must also mark it
		       as in conflict, and therefore must NOT use it.
		       see rfc1001.txt 15.1.3.5 */
		    
		    /* this may cause problems for some 
		       early versions of nmbd */
		    
		    switch (n->state)
		      {
		      case NAME_QUERY_FIND_MST:
			{
			  /* query for ^1^2__MSBROWSE__^2^1 expect
			     lots of responses */
			  return False;
			}
		      case NAME_QUERY_DOM_SRV_CHK:
		      case NAME_QUERY_SRV_CHK:
		      case NAME_QUERY_MST_CHK:
			{
			  if (!strequal(ans_name,n->name.name))
			    {
			      /* one subnet, one master browser 
				 per workgroup */
			      /* XXXX force an election? */
			      
			      DEBUG(3,("more than one master browser replied!\n"));
			      return True;
			    }
			  break;
			}
		      default: break;
		      }
		    DEBUG(3,("Unique Name conflict detected!\n"));
		    return True;
		  }
	      }
	    else
	      {
		/* we have received a negative reply, 
		   having already received
		   at least one response (pos/neg). 
		   something's really wrong! */
		
		DEBUG(3,("wierd name query problem detected!\n"));
		return True;
	      }
	  }
      }
    }
  return False;
}

#if 0
/****************************************************************************
  check that the response received is compatible with the response record
  ****************************************************************************/
static BOOL response_compatible(struct response_record *n,
			struct nmb_packet *nmb)
{
  switch (n->state)
  {
    case NAME_RELEASE:
    {
  		if (nmb->answers->rr_type != 0x20)
		{
			DEBUG(1,("Name release reply has wrong answer rr_type\n"));
			return False;
		}
        break;
    }

    case NAME_REGISTER:
    {
  		if (nmb->answers->rr_type != 0x20)
		{
			DEBUG(1,("Name register reply has wrong answer rr_type\n"));
			return False;
		}
        break;
    }

    case NAME_REGISTER_CHALLENGE: /* this is a query: we then do a register */
    case NAME_QUERY_CONFIRM:
    case NAME_QUERY_SYNC_LOCAL:
    case NAME_QUERY_SYNC_REMOTE:
    case NAME_QUERY_DOM_SRV_CHK:
    case NAME_QUERY_SRV_CHK:
    case NAME_QUERY_FIND_MST:
    case NAME_QUERY_MST_CHK:
    {
		if (nmb->answers->rr_type != 0x20)
		{
			DEBUG(1,("Name query reply has wrong answer rr_type\n"));
			return False;
		}
		break;
    }
      
    case NAME_STATUS_DOM_SRV_CHK:
    case NAME_STATUS_SRV_CHK:
    {
		if (nmb->answers->rr_type != 0x21)
		{
			DEBUG(1,("Name status reply has wrong answer rr_type\n"));
			return False;
		}
		break;
    }
      
    default:
    {
		DEBUG(1,("unknown state type received in response_netbios_packet\n"));
		return False;
    }
  }
  return True;
}
#endif


/****************************************************************************
  process the response packet received
  ****************************************************************************/
static void response_process(struct subnet_record *d, struct packet_struct *p,
			     struct response_record *n, struct nmb_packet *nmb,
			     BOOL bcast, struct nmb_name *ans_name)
{
  switch (n->state)
    {
    case NAME_RELEASE:
      {
        response_name_release(ans_name, d, p);
        break;
      }

    case NAME_REGISTER:
      {
       	response_name_reg(ans_name, d, p);
        break;
      }

    case NAME_REGISTER_CHALLENGE:
      {
        response_name_query_register(nmb, ans_name, n, d);
        break;
      }

    case NAME_QUERY_DOM_SRV_CHK:
    case NAME_QUERY_SRV_CHK:
    case NAME_QUERY_FIND_MST:
      {
	response_server_check(ans_name, n, d, p);
	break;
      }
    
    case NAME_STATUS_DOM_SRV_CHK:
    case NAME_STATUS_SRV_CHK:
      {
	response_name_status_check(p->ip, nmb, bcast, n, d);
	break;
      }
    
    case NAME_QUERY_CONFIRM:
    case NAME_QUERY_SYNC_LOCAL:
    case NAME_QUERY_SYNC_REMOTE:
      {
	response_name_query_sync(nmb, ans_name, bcast, n, d);
	break;
      }
    case NAME_QUERY_MST_CHK:
      {
	/* no action required here. it's when NO responses are received
	   that we need to do something. see expire_name_query_entries() */
	
	DEBUG(4, ("Master browser exists for %s at %s (just checking!)\n",
		  namestr(&n->name), inet_ntoa(n->send_ip)));
	break;
      }
   
    case NAME_QUERY_DOMAIN:
      {
        /* We were asking to be a domain master browser, and someone
           replied. If it was the WINS server and the IP it is
           returning is our own - then remove the record and pretend
           we didn't get a response. Else we do nothing and let 
           dead_netbios_entry deal with it. 
           We can only become domain master browser
           when no broadcast responses are received and WINS
           either contains no entry for the DOMAIN<1b> name or
           contains our IP address.
         */
        response_name_query_domain(ans_name, nmb, n, d);
        break;
      }
    default:
      {
	DEBUG(1,("unknown state type received in response_netbios_packet\n"));
	break;
      }
    }
}


/****************************************************************************
  response from a netbios packet.
  ****************************************************************************/
void response_netbios_packet(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *ans_name = NULL;
  BOOL bcast = nmb->header.nm_flags.bcast;
  struct response_record *n;
  struct subnet_record *d = NULL;

  if (!(n = find_response_record(&d,nmb->header.name_trn_id))) {
    DEBUG(2,("unknown netbios response (received late or from nmblookup?)\n"));
    return;
  }

  if (!d)
    {
      DEBUG(2,("response packet: subnet %s not known\n", inet_ntoa(p->ip)));
      return;
    }

  /* args wrong way round: spotted by ccm@shentel.net */
  if (!same_net(d->bcast_ip, p->ip, d->mask_ip)) /* copes with WINS 'subnet' */
    {
      DEBUG(2,("response from %s. ", inet_ntoa(p->ip)));
      DEBUG(2,("expected on subnet %s. hmm.\n", inet_ntoa(d->bcast_ip)));
    }
  
  if (nmb->answers == NULL) {
	  /* if there is no name is the response then the name is the one
	     we queried on */
	  ans_name = &n->name;
  } else {
	  ans_name = &nmb->answers->rr_name;
	  debug_rr_type(nmb->answers->rr_type);
  }

  DEBUG(3,("response for %s from %s(%d) (bcast=%s)\n",
	   namestr(ans_name), inet_ntoa(p->ip), p->port, BOOLSTR(bcast)));
  
  n->num_msgs++; /* count number of responses received */
  n->repeat_count = 0; /* don't resend: see expire_netbios_packets() */
  
  debug_state_type(n->state);
  
  /* problem checking: multiple responses etc */
  if (nmb->answers && response_problem_check(n, nmb, ans_name->name))
    return;
  
  /* now deal with the current state */
  response_process(d, p, n, nmb, bcast, ans_name);
}
