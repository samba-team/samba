/*
   Unix SMB/CIFS implementation.
   Samba wins server helper functions
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

/*
  this is pretty much a complete rewrite of the earlier code. The main
  aim of the rewrite is to add support for having multiple wins server
  lists, so Samba can register with multiple groups of wins servers
  and each group has a failover list of wins servers.

  Central to the way it all works is the idea of a wins server
  'tag'. A wins tag is a label for a group of wins servers. For
  example if you use

      wins server = fred:192.168.2.10 mary:192.168.3.199 fred:192.168.2.61

  then you would have two groups of wins servers, one tagged with the
  name 'fred' and the other with the name 'mary'. I would usually
  recommend using interface names instead of 'fred' and 'mary' but
  they can be any alpha string.

  Now, how does it all work. Well, nmbd needs to register each of its
  IPs with each of its names once with each group of wins servers. So
  it tries registering with the first one mentioned in the list, then
  if that fails it marks that WINS server dead and moves onto the next
  one. 

  In the client code things are a bit different. As each of the groups
  of wins servers is a separate name space we need to try each of the
  groups until we either succeed or we run out of wins servers to
  try. If we get a negative response from a wins server then that
  means the name doesn't exist in that group, so we give up on that
  group and move to the next group. If we don't get a response at all
  then maybe the wins server is down, in which case we need to
  failover to the next one for that group.

  confused yet? (tridge)
*/


/* how long a server is marked dead for */
#define DEATH_TIME 600

/* a list of wins server that are marked dead from the point of view
   of a given source address. We keep a separate dead list for each src address
   to cope with multiple interfaces that are not routable to each other
  */
static struct wins_dead {
	struct in_addr dest_ip;
	struct in_addr src_ip;
	time_t revival; /* when it will be revived */
	struct wins_dead *next, *prev;
} *dead_servers;

/* an internal convenience structure for an IP with a short string tag
   attached */
struct tagged_ip {
	fstring tag;
	struct in_addr ip;
};

/*
  see if an ip is on the dead list
*/
BOOL wins_srv_is_dead(struct in_addr wins_ip, struct in_addr src_ip)
{
	struct wins_dead *d;
	for (d=dead_servers; d; d=d->next) {
		if (ip_equal(wins_ip, d->dest_ip) && ip_equal(src_ip, d->src_ip)) {
			/* it might be due for revival */
			if (d->revival <= time(NULL)) {
				fstring src_name;
				fstrcpy(src_name, inet_ntoa(src_ip));
				DEBUG(4,("Reviving wins server %s for source %s\n", 
					 inet_ntoa(wins_ip), src_name));
				DLIST_REMOVE(dead_servers, d);
				free(d);
				return False;
			}
			return True;
		}
	}
	return False;
}


/*
  mark a wins server as being alive (for the moment)
*/
void wins_srv_alive(struct in_addr wins_ip, struct in_addr src_ip)
{
	struct wins_dead *d;
	for (d=dead_servers; d; d=d->next) {
		if (ip_equal(wins_ip, d->dest_ip) && ip_equal(src_ip, d->src_ip)) {
			fstring src_name;
			fstrcpy(src_name, inet_ntoa(src_ip));
			DEBUG(4,("Reviving wins server %s for source %s\n", 
				 inet_ntoa(wins_ip), src_name));
			DLIST_REMOVE(dead_servers, d);
			return;
		}
	}
}


/*
  mark a wins server as temporarily dead
*/
void wins_srv_died(struct in_addr wins_ip, struct in_addr src_ip)
{
	struct wins_dead *d;
	fstring src_name;

	if (is_zero_ip(wins_ip) || wins_srv_is_dead(wins_ip, src_ip)) {
		return;
	}

	d = (struct wins_dead *)malloc(sizeof(*d));
	if (!d) return;

	d->dest_ip = wins_ip;
	d->src_ip = src_ip;
	d->revival = time(NULL) + DEATH_TIME;

	fstrcpy(src_name, inet_ntoa(src_ip));

	DEBUG(4,("Marking wins server %s dead for %u seconds from source %s\n", 
		 inet_ntoa(wins_ip), DEATH_TIME, src_name));

	DLIST_ADD(dead_servers, d);
}

/*
  return the total number of wins servers, dead or not
*/
unsigned wins_srv_count(void)
{
	const char **list;
	int count = 0;

	if (lp_wins_support()) {
		/* simple - just talk to ourselves */
		return 1;
	}

	list = lp_wins_server_list();
	for (count=0; list && list[count]; count++)
		/* nop */ ;

	return count;
}

/*
  parse an IP string that might be in tagged format
  the result is a tagged_ip structure containing the tag
  and the ip in in_addr format. If there is no tag then
  use the tag '*'
*/
static void parse_ip(struct tagged_ip *ip, const char *str)
{
	char *s = strchr(str, ':');
	if (!s) {
		fstrcpy(ip->tag, "*");
		ip->ip = *interpret_addr2(str);
		return;
	} 

	ip->ip = *interpret_addr2(s+1);
	fstrcpy(ip->tag, str);
	s = strchr(ip->tag, ':');
	if (s) *s = 0;
}



/*
  return the list of wins server tags. A 'tag' is used to distinguish
  wins server as either belonging to the same name space or a separate
  name space. Usually you would setup your 'wins server' option to
  list one or more wins server per interface and use the interface
  name as your tag, but you are free to use any tag you like.
*/
char **wins_srv_tags(void)
{
	char **ret = NULL;
	int count=0, i, j;
	const char **list;

	if (lp_wins_support()) {
		/* give the caller something to chew on. This makes
		   the rest of the logic simpler (ie. less special cases) */
		ret = (char **)malloc(sizeof(char *)*2);
		if (!ret) return NULL;
		ret[0] = strdup("*");
		ret[1] = NULL;
		return ret;
	}

	list = lp_wins_server_list();
	if (!list)
		return NULL;

	/* yes, this is O(n^2) but n is very small */
	for (i=0;list[i];i++) {
		struct tagged_ip t_ip;
		
		parse_ip(&t_ip, list[i]);

		/* see if we already have it */
		for (j=0;j<count;j++) {
			if (strcmp(ret[j], t_ip.tag) == 0) {
				break;
			}
		}

		if (j != count) {
			/* we already have it. Move along */
			continue;
		}

		/* add it to the list */
		ret = (char **)Realloc(ret, (count+2) * sizeof(char *));
		ret[count] = strdup(t_ip.tag);
		if (!ret[count]) break;
		count++;
	}

	if (count) {
		/* make sure we null terminate */
		ret[count] = NULL;
	}

	return ret;
}

/* free a list of wins server tags given by wins_srv_tags */
void wins_srv_tags_free(char **list)
{
	int i;
	if (!list) return;
	for (i=0; list[i]; i++) {
		free(list[i]);
	}
	free(list);
}


/*
  return the IP of the currently active wins server for the given tag,
  or the zero IP otherwise
*/
struct in_addr wins_srv_ip_tag(const char *tag, struct in_addr src_ip)
{
	const char **list;
	int i;
	struct tagged_ip t_ip;

	/* if we are a wins server then we always just talk to ourselves */
	if (lp_wins_support()) {
		extern struct in_addr loopback_ip;
		return loopback_ip;
	}

	list = lp_wins_server_list();
	if (!list || !list[0]) {
		struct in_addr ip;
		zero_ip(&ip);
		return ip;
	}

	/* find the first live one for this tag */
	for (i=0; list[i]; i++) {
		parse_ip(&t_ip, list[i]);
		if (strcmp(tag, t_ip.tag) != 0) {
			/* not for the right tag. Move along */
			continue;
		}
		if (!wins_srv_is_dead(t_ip.ip, src_ip)) {
			fstring src_name;
			fstrcpy(src_name, inet_ntoa(src_ip));
			DEBUG(6,("Current wins server for tag '%s' with source %s is %s\n", 
				 tag, 
				 src_name,
				 inet_ntoa(t_ip.ip)));
			return t_ip.ip;
		}
	}
	
	/* they're all dead - try the first one until they revive */
	for (i=0; list[i]; i++) {
		parse_ip(&t_ip, list[i]);
		if (strcmp(tag, t_ip.tag) != 0) {
			continue;
		}
		return t_ip.ip;
	}

	/* this can't happen?? */
	zero_ip(&t_ip.ip);
	return t_ip.ip;
}


/*
  return a count of the number of IPs for a particular tag, including
  dead ones
*/
unsigned wins_srv_count_tag(const char *tag)
{
	const char **list;
	int i, count=0;

	/* if we are a wins server then we always just talk to ourselves */
	if (lp_wins_support()) {
		return 1;
	}

	list = lp_wins_server_list();
	if (!list || !list[0]) {
		return 0;
	}

	/* find the first live one for this tag */
	for (i=0; list[i]; i++) {
		struct tagged_ip t_ip;
		parse_ip(&t_ip, list[i]);
		if (strcmp(tag, t_ip.tag) == 0) {
			count++;
		}
	}

	return count;
}
