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
extern struct in_addr ipzero;

#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())


/****************************************************************************
  response for a reg release received. samba has asked a WINS server if it
  could release a name.
  **************************************************************************/
static void response_name_release(struct subnet_record *d,
								struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = nmb->question.question_name.name;
  int   type = nmb->question.question_name.name_type;
  
  DEBUG(4,("response name release received\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers->rdata)
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
                  inet_ntoa(found_ip),
                  namestr(&nmb->question.question_name)));
    }
  }
  else
  {
    DEBUG(2,("name release for %s rejected!\n",
	       namestr(&nmb->question.question_name)));

    /* XXXX PANIC! what to do if it's one of samba's own names? */

    /* XXXX do we honestly care if our name release was rejected? 
       only if samba is issuing the release on behalf of some out-of-sync
       server. if it's one of samba's SELF names, we don't care. */
  }
}


/****************************************************************************
response for a reg request received
**************************************************************************/
static void response_name_reg(struct subnet_record *d, struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *name = nmb->question.question_name.name;
  int   type = nmb->question.question_name.name_type;
  BOOL bcast = nmb->header.nm_flags.bcast;
  
  DEBUG(4,("response name registration received!\n"));
  
  if (nmb->header.rcode == 0 && nmb->answers->rdata)
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
    DEBUG(1,("name registration for %s rejected!\n",
	       namestr(&nmb->question.question_name)));

	/* oh dear. we have problems. possibly unbecome a master browser. */
    name_unregister_work(d,name,type);
  }
}


/****************************************************************************
  response from a name query announce host
  NAME_QUERY_ANNOUNCE_HOST is dealt with here
  ****************************************************************************/
static void response_announce_host(struct nmb_name *ans_name, 
		struct nmb_packet *nmb, 
		struct response_record *n, struct subnet_record *d)
{
	DEBUG(4, ("Name query at %s ip %s - ",
		  namestr(&n->name), inet_ntoa(n->send_ip)));

	if (!name_equal(&n->name, ans_name))
	{
		/* someone gave us the wrong name as a reply. oops. */
		/* XXXX should say to them 'oi! release that name!' */

		DEBUG(4,("unexpected name received: %s\n", namestr(ans_name)));
		return;
	}

	if (nmb->header.rcode == 0 && nmb->answers->rdata)
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

    	/* do an announce host */
    	do_announce_host(ANN_HostAnnouncement,
				n->my_name  , 0x00, d->myip,
				n->name.name, 0x1d, found_ip,
				n->ttl,
				n->my_name, n->server_type, n->my_comment);
	}
	else
	{
		/* XXXX negative name query response. no master exists. oops */
	}
}


/****************************************************************************
  response from a name query server check. states of type NAME_QUERY_DOM_SRV_CHK,
  NAME_QUERY_SRV_CHK, and NAME_QUERY_FIND_MST dealt with here.
  ****************************************************************************/
static void response_server_check(struct nmb_name *ans_name, 
		struct response_record *n, struct subnet_record *d)
{
    /* issue another state: this time to do a name status check */

    enum state_type cmd = (n->state == NAME_QUERY_DOM_SRV_CHK) ?
	      NAME_STATUS_DOM_SRV_CHK : NAME_STATUS_SRV_CHK;

    /* initiate a name status check on the server that replied */
    queue_netbios_packet(d,ClientNMB,NMB_STATUS, cmd,
				ans_name->name, ans_name->name_type,
				0,0,0,NULL,NULL,
				False,False,n->send_ip,n->reply_to_ip);
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
  int level = t==0x20 ? 4 : 0;
  int numnames = CVAL(p,0);
  BOOL found = False;

  DEBUG(level,("received %d names\n",numnames));

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
      if (NAME_CONFLICT (nb_flags)) { strcat(flags,"<CONFLICT> "); add=True;}
      if (NAME_ACTIVE   (nb_flags)) { strcat(flags,"<ACTIVE> "); add=True; }
      if (NAME_PERMANENT(nb_flags)) { strcat(flags,"<PERMANENT> "); add=True;}
      
      /* might as well update our namelist while we're at it */
      if (add)
	{
	  struct in_addr nameip;
	  enum name_source src;
	  
	  if (ismyip(ip)) {
	    nameip = ipzero;
	    src = SELF;
	  } else {
	    nameip = ip;
	    src = STATUS_QUERY;
	  }
	  add_netbios_entry(d,qname,type,nb_flags,2*60*60,src,nameip,True,bcast);
	} 

      /* we want the server name */
      if (serv_name && !*serv_name && !group && t == 0)
	{
	  StrnCpy(serv_name,qname,15);
	  serv_name[15] = 0;
	}
      
      /* looking for a name and type? */
      if (name && !found && (t == type))
	{
	  /* take a guess at some of the name types we're going to ask for.
	     evaluate whether they are group names or no... */
	  if (((t == 0x1b || t == 0x1d             ) && !group) ||
	      ((t == 0x20 || t == 0x1c || t == 0x1e) &&  group))
	    {
	      found = True;
	      make_nmb_name(name,qname,type,scope);
	    }
	}
      
      DEBUG(level,("\t%s(0x%x)\t%s\n",qname,type,flags));
    }
  DEBUG(level,("num_good_sends=%d num_good_receives=%d\n",
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

	if (interpret_node_status(d,nmb->answers->rdata,
	                          &name,name.name_type,serv_name,ip,bcast))
	{
		if (*serv_name)
		{
			sync_server(n->state,serv_name,
			            name.name,name.name_type, n->send_ip);
		}
	}
	else
	{
		DEBUG(1,("No 0x1d name type in interpret_node_status()\n"));
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

	if (nmb->header.rcode == 0 && nmb->answers->rdata)
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
	add_name_respond(d, n->fd, d->myip, n->response_id,&n->name,n->nb_flags,
					GET_TTL(0), register_ip,
					new_owner, n->reply_to_ip);
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

	if (nmb->header.rcode == 0 && nmb->answers->rdata)
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
			if ((work = find_workgroupstruct(d, ans_name->name, False)))
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
    case NAME_QUERY_DOM_SRV_CHK  : DEBUG(4,("MASTER_SVR_CHECK\n")); break;
    case NAME_QUERY_SRV_CHK      : DEBUG(4,("NAME_QUERY_SRV_CHK\n")); break;
    case NAME_QUERY_FIND_MST     : DEBUG(4,("NAME_QUERY_FIND_MST\n")); break;
    case NAME_QUERY_MST_CHK      : DEBUG(4,("NAME_QUERY_MST_CHK\n")); break;
    case NAME_QUERY_CONFIRM      : DEBUG(4,("NAME_QUERY_CONFIRM\n")); break;
    case NAME_QUERY_SYNC_LOCAL   : DEBUG(4,("NAME_QUERY_SYNC_LOCAL\n")); break;
    case NAME_QUERY_SYNC_REMOTE  : DEBUG(4,("NAME_QUERY_SYNC_REMOTE\n")); break;
    case NAME_QUERY_ANNOUNCE_HOST: DEBUG(4,("NAME_QUERY_ANNCE_HOST\n"));break;

    case NAME_REGISTER           : DEBUG(4,("NAME_REGISTER\n")); break;
    case NAME_REGISTER_CHALLENGE : DEBUG(4,("NAME_REGISTER_CHALLENGE\n"));break;

    case NAME_RELEASE            : DEBUG(4,("NAME_RELEASE\n")); break;

    case NAME_STATUS_DOM_SRV_CHK : DEBUG(4,("NAME_STAT_MST_CHK\n")); break;
    case NAME_STATUS_SRV_CHK     : DEBUG(4,("NAME_STATUS_SRV_CHK\n")); break;

    default: break;
  }
}

/****************************************************************************
  report any problems with the fact that a response has been received.

  (responses for certain types of operations are only expected from one host)
  ****************************************************************************/
static BOOL response_problem_check(struct response_record *n,
			struct nmb_packet *nmb, char *qname)
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
		  if (nmb->header.rcode == 0 && nmb->answers->rdata)
		  {
			int nb_flags = nmb->answers->rdata[0];

			if ((!NAME_GROUP(nb_flags)))
			{
			   /* oh dear. more than one person responded to a unique name.
				  there is either a network problem, a configuration problem
				  or a server is mis-behaving */

			   /* XXXX mark the name as in conflict, and then let the
				  person who just responded know that they must also mark it
				  as in conflict, and therefore must NOT use it.
                  see rfc1001.txt 15.1.3.5 */
					
               /* this may cause problems for some early versions of nmbd */

               switch (n->state)
               {
                case NAME_QUERY_FIND_MST:
                {
                  /* query for ^1^2__MSBROWSE__^2^1 expect lots of responses */
                  return False;
                }
    			case NAME_QUERY_ANNOUNCE_HOST:
    			case NAME_QUERY_DOM_SRV_CHK:
                case NAME_QUERY_SRV_CHK:
                case NAME_QUERY_MST_CHK:
                {
	              if (!strequal(qname,n->name.name))
	              {
		             /* one subnet, one master browser per workgroup */
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
             /* we have received a negative reply, having already received
                at least one response (pos/neg). something's really wrong! */

	         DEBUG(3,("wierd name query problem detected!\n"));
		     return True;
		  }
       }
    }
  }
  return False;
}

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
  		if (nmb->answers->rr_type != NMB_REL)
		{
			DEBUG(1,("Name release reply has wrong answer rr_type\n"));
			return False;
		}
        break;
    }

    case NAME_REGISTER:
    {
  		if (nmb->answers->rr_type != NMB_REG)
		{
			DEBUG(1,("Name register reply has wrong answer rr_type\n"));
			return False;
		}
        break;
    }

    case NAME_REGISTER_CHALLENGE: /* this is a query: we then do a register */
    case NAME_QUERY_CONFIRM:
    case NAME_QUERY_ANNOUNCE_HOST:
    case NAME_QUERY_SYNC_LOCAL:
    case NAME_QUERY_SYNC_REMOTE:
    case NAME_QUERY_DOM_SRV_CHK:
    case NAME_QUERY_SRV_CHK:
    case NAME_QUERY_FIND_MST:
    case NAME_QUERY_MST_CHK:
    {
		if (nmb->answers->rr_type != NMB_QUERY)
		{
			DEBUG(1,("Name query reply has wrong answer rr_type\n"));
			return False;
		}
		break;
    }
      
    case NAME_STATUS_DOM_SRV_CHK:
    case NAME_STATUS_SRV_CHK:
    {
		if (nmb->answers->rr_type != NMB_STATUS)
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
        response_name_release(d, p);
        break;
    }

    case NAME_REGISTER:
    {
       	response_name_reg(d, p);
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
		response_server_check(ans_name, n, d);
		break;
    }
      
    case NAME_STATUS_DOM_SRV_CHK:
    case NAME_STATUS_SRV_CHK:
    {
		response_name_status_check(p->ip, nmb, bcast, n, d);
		break;
    }
      
    case NAME_QUERY_ANNOUNCE_HOST:
    {
		response_announce_host(ans_name, nmb, n, d);
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
  struct nmb_name *question = &nmb->question.question_name;
  struct nmb_name *ans_name = NULL;
  char *qname = question->name;
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
    return;
  }

  if (nmb->answers == NULL)
  {
      /* hm. the packet received was a response, but with no answer. wierd! */
      DEBUG(2,("NMB packet response from %s (bcast=%s) - UNKNOWN\n",
	       inet_ntoa(p->ip), BOOLSTR(bcast)));
      return;
  }

  ans_name = &nmb->answers->rr_name;
  DEBUG(3,("response for %s from %s (bcast=%s)\n",
	   namestr(ans_name), inet_ntoa(p->ip), BOOLSTR(bcast)));
  
  debug_rr_type(nmb->answers->rr_type);

  n->num_msgs++; /* count number of responses received */
  n->repeat_count = 0; /* don't resend: see expire_netbios_packets() */

  debug_state_type(n->state);

  /* problem checking: multiple responses etc */
  if (response_problem_check(n, nmb, qname))
    return;

  /* now check whether the 'state' has received the correct type of response */
  if (!response_compatible(n, nmb))
    return;

  /* now deal with the current state */
  response_process(d, p, n, nmb, bcast, ans_name);
}


