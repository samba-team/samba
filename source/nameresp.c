/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios library routines
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
   
   Module name: nameresp.c

*/

#include "includes.h"

extern int ClientNMB;
extern int ClientDGRAM;

extern struct subnet_record *subnetlist;

extern int DEBUGLEVEL;

extern pstring scope;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;


/***************************************************************************
  deals with an entry before it dies
  **************************************************************************/
static void dead_netbios_entry(struct subnet_record *d,
				struct response_record *n)
{
  DEBUG(3,("Removing dead netbios entry for %s %s (num_msgs=%d)\n",
	   inet_ntoa(n->send_ip), namestr(&n->name), n->num_msgs));

  debug_state_type(n->state);

  switch (n->state)
  {
    case NAME_QUERY_CONFIRM:
    {
		if (!lp_wins_support()) return; /* only if we're a WINS server */

		if (n->num_msgs == 0)
        {
			/* oops. name query had no response. check that the name is
			   unique and then remove it from our WINS database */

			/* IMPORTANT: see query_refresh_names() */

			if ((!NAME_GROUP(n->nb_flags)))
			{
				struct subnet_record *d1 = find_subnet(ipgrp);
				if (d1)
				{
					/* remove the name that had been registered with us,
					   and we're now getting no response when challenging.
					   see rfc1001.txt 15.5.2
					 */
					remove_netbios_name(d1, n->name.name, n->name.name_type,
									REGISTER, n->send_ip);
				}
			}
		}
		break;
    }

	case NAME_QUERY_MST_CHK:
	{
	  /* if no response received, the master browser must have gone
		 down on that subnet, without telling anyone. */

	  /* IMPORTANT: see response_netbios_packet() */

	  if (n->num_msgs == 0)
		  browser_gone(n->name.name, n->send_ip);
	  break;
	}

	case NAME_RELEASE:
	{
	  /* if no response received, it must be OK for us to release the
		 name. nobody objected (including a potentially dead or deaf
		 WINS server) */

	  /* IMPORTANT: see response_name_release() */

	  if (ismyip(n->send_ip))
	  {
		name_unregister_work(d,n->name.name,n->name.name_type);
	  }
	  if (!n->bcast)
	  {
		 DEBUG(0,("WINS server did not respond to name release!\n"));
         /* XXXX whoops. we have problems. must deal with this */
	  }
	  break;
	}

	case NAME_REGISTER_CHALLENGE:
	{
		/* name challenge: no reply. we can reply to the person that
		   wanted the unique name and tell them that they can have it
		 */

		add_name_respond(d,n->fd,d->myip, n->response_id ,&n->name,
						n->nb_flags, GET_TTL(0),
						n->reply_to_ip, False, n->reply_to_ip);

	  if (!n->bcast)
	  {
		 DEBUG(1,("WINS server did not respond to name registration!\n"));
         /* XXXX whoops. we have problems. must deal with this */
	  }
      break;
	}

	case NAME_REGISTER:
	{
	  /* if no response received, and we are using a broadcast registration
		 method, it must be OK for us to register the name: nobody objected 
		 on that subnet. if we are using a WINS server, then the WINS
		 server must be dead or deaf.
	   */
	  if (n->bcast)
	  {
		/* broadcast method: implicit acceptance of the name registration
		   by not receiving any objections. */

		/* IMPORTANT: see response_name_reg() */

		name_register_work(d,n->name.name,n->name.name_type,
				n->nb_flags, n->ttl, n->reply_to_ip, n->bcast);
	  }
	  else
	  {
		/* received no response. rfc1001.txt states that after retrying,
		   we should assume the WINS server is dead, and fall back to
		   broadcasting (see bits about M nodes: can't find any right
           now) */
		
		DEBUG(1,("WINS server did not respond to name registration!\n"));
        /* XXXX whoops. we have problems. must deal with this */
	  }
	  break;
	}

	default:
	{
	  /* nothing to do but delete the dead expected-response structure */
	  /* this is normal. */
	  break;
	}
  }
}


/*******************************************************************
  remove old name response entries

  XXXX retry code needs to be added, including a retry wait period and a count
       see name_query() and name_status() for suggested implementation.

  ******************************************************************/
void expire_netbios_response_entries()
{
  struct subnet_record *d;

  for (d = subnetlist; d; d = d->next)
  {
    struct response_record *n, *nextn;

    for (n = d->responselist; n; n = nextn)
    {
	  nextn = n->next;

      if (n->repeat_time <= time(NULL))
	  {
		  if (n->repeat_count > 0)
		  {
			/* resend the entry */
  			initiate_netbios_packet(&n->response_id, n->fd, n->quest_type,
						n->name.name, n->name.name_type,
				      n->nb_flags, n->bcast, n->recurse, n->send_ip);

            n->repeat_time += n->repeat_interval; /* XXXX ms needed */
            n->repeat_count--;

		  }
		  else
		  {
              DEBUG(4,("timeout response %d for %s %s\n",
						n->response_id, namestr(&n->name),
                        inet_ntoa(n->send_ip)));

			  dead_netbios_entry    (d,n); /* process the non-response */
              remove_response_record(d,n); /* remove the non-response */

			  continue;
		   }
	  }
    }
  }
}


/****************************************************************************
  wrapper function to override a broadcast message and send it to the WINS
  name server instead, if it exists. if wins is false, and there has been no
  WINS server specified, the packet will NOT be sent.
  ****************************************************************************/
struct response_record *queue_netbios_pkt_wins(struct subnet_record *d,
				int fd,int quest_type,enum state_type state,
			    char *name,int name_type,int nb_flags, time_t ttl,
				int server_type, char *my_name, char *my_comment,
			    BOOL bcast,BOOL recurse,
				struct in_addr send_ip, struct in_addr reply_to_ip)
{
  /* XXXX note: please see rfc1001.txt section 10 for details on this
     function: it is currently inappropriate to use this - it will do
     for now - once there is a clarification of B, M and P nodes and
     which one samba is supposed to be
   */

  if ((!lp_wins_support()) && (*lp_wins_server()))
    {
      /* samba is not a WINS server, and we are using a WINS server */
      struct in_addr wins_ip;
      wins_ip = *interpret_addr2(lp_wins_server());

      if (!zero_ip(wins_ip))
	{
	  bcast = False;
	  send_ip = wins_ip;
	}
      else
	{
	  /* oops. smb.conf's wins server parameter MUST be a host_name 
	     or an ip_address. */
	  DEBUG(0,("invalid smb.conf parameter 'wins server'\n"));
	}
    }

  if (zero_ip(send_ip)) return NULL;

  return queue_netbios_packet(d,fd, quest_type, state, 
		       name, name_type, nb_flags, ttl,
               server_type,my_name,my_comment,
		       bcast, recurse, send_ip, reply_to_ip);
}


/****************************************************************************
  initiate a netbios name query to find someone's or someones' IP
  this is intended to be used (not exclusively) for broadcasting to
  master browsers (WORKGROUP(1d or 1b) or __MSBROWSE__(1)) to get
  complete lists across a wide area network
  ****************************************************************************/
struct response_record *queue_netbios_packet(struct subnet_record *d,
			int fd,int quest_type,enum state_type state,char *name,
			int name_type,int nb_flags, time_t ttl,
			int server_type, char *my_name, char *my_comment,
		    BOOL bcast,BOOL recurse,
			struct in_addr send_ip, struct in_addr reply_to_ip)
{
  struct in_addr wins_ip = ipgrp;
  struct response_record *n;
  uint16 id = 0xffff;

  /* ha ha. no. do NOT broadcast to 255.255.255.255: it's a pseudo address */
  if (ip_equal(wins_ip, send_ip)) return NULL;

  initiate_netbios_packet(&id, fd, quest_type, name, name_type,
				      nb_flags, bcast, recurse, send_ip);

  if (id == 0xffff) {
    DEBUG(4,("did not initiate netbios packet: %s\n", inet_ntoa(send_ip)));
    return NULL;
  }
  
  if ((n = make_response_queue_record(state,id,fd,
						quest_type,name,name_type,nb_flags,ttl,
						server_type,my_name, my_comment,
						bcast,recurse,send_ip,reply_to_ip)))
    {
      add_response_record(d,n);
      return n;
    }
   return NULL;
}
