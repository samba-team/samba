/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-2002
   Copyright (C) Christopher R. Hertel 2000

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


/* how long a server is marked dead for */
#define DEATH_TIME 600

/* a list of wins server that are marked dead. */
static struct wins_dead {
	struct in_addr ip;
	time_t revival; /* when it will be revived */
	struct wins_dead *next, *prev;
} *dead_servers;


/*
  see if an ip is on the dead list
*/
static int wins_is_dead(struct in_addr ip)
{
	struct wins_dead *d;
	for (d=dead_servers; d; d=d->next) {
		if (ip_equal(ip, d->ip)) {
			/* it might be due for revival */
			if (d->revival <= time(NULL)) {
				DEBUG(4,("Reviving wins server %s\n", inet_ntoa(ip)));
				DLIST_REMOVE(dead_servers, d);
				free(d);
				return 0;
			}
			return 1;
		}
	}
	return 0;
}

/*
  mark a wins server as temporarily dead
*/
void wins_srv_died(struct in_addr ip)
{
	struct wins_dead *d;

	if (is_zero_ip(ip) || wins_is_dead(ip)) {
		return;
	}

	d = (struct wins_dead *)malloc(sizeof(*d));
	if (!d) return;

	d->ip = ip;
	d->revival = time(NULL) + DEATH_TIME;

	DEBUG(4,("Marking wins server %s dead for %u seconds\n", inet_ntoa(ip), DEATH_TIME));

	DLIST_ADD(dead_servers, d);
}

/*
  return the total number of wins servers, dead or not
*/
unsigned long wins_srv_count(void)
{
	char **list;
	int count = 0;

	list = lp_wins_server_list();
	for (count=0; list && list[count]; count++) /* nop */ ;

	DEBUG(6,("Found %u wins servers in list\n", count));
	return count;
}

/*
  return the IP of the currently active wins server, or the zero IP otherwise
*/
struct in_addr wins_srv_ip(void)
{
	char **list;
	struct in_addr ip;
	int i;

	list = lp_wins_server_list();
	if (!list || !list[0]) {
		zero_ip(&ip);
		return ip;
	}

	/* find the first live one */
	for (i=0; list[i]; i++) {
		ip = *interpret_addr2(list[i]);
		if (!wins_is_dead(ip)) {
			DEBUG(6,("Current wins server is %s\n", inet_ntoa(ip)));
			return ip;
		}
	}

	/* damn, they are all dead. Keep trying the primary until they revive */
	ip = *interpret_addr2(list[0]);

	return ip;
}
