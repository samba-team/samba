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
   
   Module name: namedbresp.c

*/

#include "includes.h"

extern int ClientNMB;
extern int ClientDGRAM;

extern struct subnet_record *subnetlist;

extern int DEBUGLEVEL;

extern pstring scope;
extern pstring myname;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;

int num_response_packets = 0;

/***************************************************************************
  add an expected response record into the list
  **************************************************************************/
void add_response_record(struct subnet_record *d,
				struct response_record *n)
{
  struct response_record *n2;

  if (!d) return;

  num_response_packets++; /* count of total number of packets still around */

  DEBUG(4,("adding response record id:%d num_records:%d\n",
                   n->response_id, num_response_packets));

  if (!d->responselist)
    {
      d->responselist = n;
      n->prev = NULL;
      n->next = NULL;
      return;
    }
  
  for (n2 = d->responselist; n2->next; n2 = n2->next) ;
  
  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}


/***************************************************************************
  remove an expected response record from the list
  **************************************************************************/
void remove_response_record(struct subnet_record *d,
				struct response_record *n)
{
	if (!d) return;

	if (n->prev) n->prev->next = n->next;
	if (n->next) n->next->prev = n->prev;

	if (d->responselist == n) d->responselist = n->next; 

	free(n);

	num_response_packets--; /* count of total number of packets still around */
}


/****************************************************************************
  create a name query response record
  **************************************************************************/
struct response_record *make_response_queue_record(enum state_type state,
				int id,uint16 fd,
				int quest_type, char *name,int type, int nb_flags, time_t ttl,
				int server_type, char *my_name, char *my_comment,
				BOOL bcast,BOOL recurse,
				struct in_addr send_ip, struct in_addr reply_to_ip)
{
  struct response_record *n;
	
  if (!name || !name[0]) return NULL;
	
  if (!(n = (struct response_record *)malloc(sizeof(*n)))) 
    return(NULL);

  n->response_id = id;
  n->state = state;
  n->fd = fd;
  n->quest_type = quest_type;
  make_nmb_name(&n->name, name, type, scope);
  n->nb_flags = nb_flags;
  n->ttl = ttl;
  n->server_type = server_type;
  n->bcast = bcast;
  n->recurse = recurse;
  n->send_ip = send_ip;
  n->reply_to_ip = reply_to_ip;
  StrnCpy(my_name   , n->my_name   , sizeof(n->my_name   )-1);
  StrnCpy(my_comment, n->my_comment, sizeof(n->my_comment)-1);

  n->repeat_interval = 1; /* XXXX should be in ms */
  n->repeat_count = 3; /* 3 retries */
  n->repeat_time = time(NULL) + n->repeat_interval; /* initial retry time */

  n->num_msgs = 0;

  return n;
}


/****************************************************************************
  find a response in a subnet's name query response list. 
  **************************************************************************/
struct response_record *find_response_record(struct subnet_record **d,
				uint16 id)
{  
  struct response_record *n;

  if (!d) return NULL;

  for ((*d) = subnetlist; (*d); (*d) = (*d)->next)
  {
    for (n = (*d)->responselist; n; n = n->next)
    {
      if (n->response_id == id) {
         DEBUG(4, ("found response record on %s: %d\n",
					inet_ntoa((*d)->bcast_ip), id));
         return n;
      }
    }
  }

  *d = NULL;

  return NULL;
}


