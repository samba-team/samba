/* 
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Jean François Micouleau      1998-2002.
   
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
#include "wins_repl.h"

/* we can exchange info with 64 partners at any given time */
WINS_PARTNER current_partners[64];
int total_current_partners;

/*******************************************************************
verify if we know this partner
********************************************************************/
BOOL check_partner(int assoc)
{
	int i;

	DEBUG(5,("check_partner: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==assoc)
			return True;

	return False;
}

/*******************************************************************
add a new entry to the list
********************************************************************/
BOOL add_partner(int client_assoc, int server_assoc, BOOL pull, BOOL push)
{
	DEBUG(5,("add_partner: total_current_partners: %d\n", total_current_partners));

	if (total_current_partners==64)
		return False;

	current_partners[total_current_partners].client_assoc=client_assoc;
	current_partners[total_current_partners].server_assoc=server_assoc;
	current_partners[total_current_partners].pull_partner=pull;
	current_partners[total_current_partners].push_partner=push;

	total_current_partners++;

	return True;
}

/*******************************************************************
remove an entry to the list
********************************************************************/
BOOL remove_partner(int client_assoc)
{
	int i,j;

	DEBUG(5,("remove_partner: total_current_partners: %d\n", total_current_partners));

	for (i=0; current_partners[i].client_assoc!=client_assoc && i<total_current_partners; i++)
		;
	
	if (i==total_current_partners)
		return False;

	for (j=i+1; j<total_current_partners; j++) {
		current_partners[j-1].client_assoc=current_partners[j].client_assoc;
		current_partners[j-1].server_assoc=current_partners[j].server_assoc;
		current_partners[j-1].pull_partner=current_partners[j].pull_partner;
		current_partners[j-1].push_partner=current_partners[j].push_partner;
		current_partners[j-1].partner_server.s_addr=current_partners[j].partner_server.s_addr;
		current_partners[j-1].other_server.s_addr=current_partners[j].other_server.s_addr;
	}

	total_current_partners--;

	return True;
}

/*******************************************************************
link the client and server context
********************************************************************/
BOOL update_server_partner(int client_assoc, int server_assoc)
{
	int i;
	
	DEBUG(5,("update_server_partner: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==client_assoc) {
			current_partners[i].server_assoc=server_assoc;
			return True;
		}

	return False;
}

/*******************************************************************
verify if it's a pull partner
********************************************************************/
BOOL check_pull_partner(int assoc)
{
	int i;
	
	DEBUG(5,("check_pull_partner: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==assoc &&
		    current_partners[i].pull_partner==True)
			return True;

	return False;
}

/*******************************************************************
verify if it's a push partner
********************************************************************/
BOOL check_push_partner(int assoc)
{
	int i;
	
	DEBUG(5,("check_push_partner: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==assoc &&
		    current_partners[i].push_partner==True)
			return True;

	return False;
}

/*******************************************************************
return the server ctx linked to the client ctx
********************************************************************/
int get_server_assoc(int assoc)
{
	int i;
	
	DEBUG(5,("get_server_assoc: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==assoc)
			return current_partners[i].server_assoc;

	return 0;
}


/*******************************************************************
link the client and server context
********************************************************************/
BOOL write_server_assoc_table(int client_assoc, struct in_addr partner, struct in_addr server)
{
	int i;
	
	DEBUG(5,("write_server_assoc_table: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==client_assoc) {
			current_partners[i].partner_server=partner;
			current_partners[i].other_server=server;
			return True;
		}

	return False;
}

/*******************************************************************
link the client and server context
********************************************************************/
BOOL get_server_assoc_table(int client_assoc, struct in_addr *partner, struct in_addr *server)
{
	int i;
	
	DEBUG(5,("get_server_assoc_table: total_current_partners: %d\n", total_current_partners));

	for (i=0; i<total_current_partners; i++)
		if (current_partners[i].client_assoc==client_assoc) {
			partner->s_addr=current_partners[i].partner_server.s_addr;
			server->s_addr=current_partners[i].other_server.s_addr;
			return True;
		}

	return False;
}


