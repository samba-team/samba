/* 
   Unix SMB/CIFS implementation.

   packet handling for mailslot requests

   Copyright (C) Andrew Tridgell 2005
   
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

#include "includes.h"
#include "lib/events/events.h"
#include "dlinklist.h"
#include "libcli/nbt/libnbt.h"
#include "libcli/dgram/libdgram.h"
#include "lib/socket/socket.h"

/*
  destroy a mailslot handler
*/
static int dgram_mailslot_destructor(void *ptr)
{
	struct dgram_mailslot_handler *dgmslot = 
		talloc_get_type(ptr, struct dgram_mailslot_handler);
	
	DLIST_REMOVE(dgmslot->dgmsock->mailslot_handlers, dgmslot);
	return 0;
}

/*
  start listening on a mailslot. talloc_free() the handle to stop listening
*/
struct dgram_mailslot_handler *dgram_mailslot_listen(struct nbt_dgram_socket *dgmsock,
						     const char *mailslot_name,
						     dgram_mailslot_handler_t handler,
						     void *private)
{
	struct dgram_mailslot_handler *dgmslot;

	dgmslot = talloc(dgmsock, struct dgram_mailslot_handler);
	if (dgmslot == NULL) return NULL;

	dgmslot->dgmsock = dgmsock;
	dgmslot->mailslot_name = talloc_strdup(dgmslot, mailslot_name);
	if (dgmslot->mailslot_name == NULL) {
		talloc_free(dgmslot);
		return NULL;
	}
	dgmslot->handler = handler;
	dgmslot->private = private;

	DLIST_ADD(dgmsock->mailslot_handlers, dgmslot);
	talloc_set_destructor(dgmslot, dgram_mailslot_destructor);

	return dgmslot;
}

/*
  find the handler for a specific mailslot name
*/
struct dgram_mailslot_handler *dgram_mailslot_find(struct nbt_dgram_socket *dgmsock,
						   const char *mailslot_name)
{
	struct dgram_mailslot_handler *h;
	for (h=dgmsock->mailslot_handlers;h;h=h->next) {
		if (strcasecmp(h->mailslot_name, mailslot_name) == 0) {
			return h;
		}
	}
	return NULL;
}

/*
  check that a datagram packet is a valid mailslot request, and return the 
  mailslot name if it is, otherwise return NULL
*/
const char *dgram_mailslot_name(struct nbt_dgram_packet *packet)
{
	if (packet->msg_type != DGRAM_DIRECT_UNIQUE &&
	    packet->msg_type != DGRAM_DIRECT_GROUP &&
	    packet->msg_type != DGRAM_BCAST) {
		return NULL;
	}
	if (packet->data.msg.dgram_body_type != DGRAM_SMB) return NULL;
	if (packet->data.msg.body.smb.smb_command != SMB_TRANSACTION) return NULL;
	if (packet->data.msg.body.smb.smb_command != SMB_TRANSACTION) return NULL;
	return packet->data.msg.body.smb.body.trans.mailslot_name;
}


/*
  create a temporary mailslot handler for a reply mailslot, allocating
  a new mailslot name using the given base name and a random integer extension
*/
struct dgram_mailslot_handler *dgram_mailslot_temp(struct nbt_dgram_socket *dgmsock,
						   const char *mailslot_name,
						   dgram_mailslot_handler_t handler,
						   void *private)
{
	char *name;
	int i;
	struct dgram_mailslot_handler *dgmslot;

	/* try a 100 times at most */
	for (i=0;i<100;i++) {
		name = talloc_asprintf(dgmsock, "%s%u", 
				       mailslot_name,
				       generate_random() % UINT16_MAX);
		if (name == NULL) return NULL;
		if (dgram_mailslot_find(dgmsock, name)) {
			talloc_free(name);
			return NULL;
		}
		dgmslot = dgram_mailslot_listen(dgmsock, name, handler, private);
		talloc_free(name);
		return dgmslot;
	}
	DEBUG(2,("Unable to create temporary mailslot from %s\n", mailslot_name));
	return NULL;
}
