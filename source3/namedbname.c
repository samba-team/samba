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
   
   Module name: namedbname.c

   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   04 jul 96: lkcl@pires.co.uk
   created module namedbname containing name database functions
*/

#include "includes.h"

extern int DEBUGLEVEL;

extern pstring scope;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;

extern struct subnet_record *subnetlist;

#define WINS_LIST "wins.dat"


/****************************************************************************
  true if two netbios names are equal
****************************************************************************/
BOOL name_equal(struct nmb_name *n1,struct nmb_name *n2)
{
  return n1->name_type == n2->name_type &&
		 strequal(n1->name ,n2->name ) &&
         strequal(n1->scope,n2->scope);
}


/****************************************************************************
  true if the netbios name is ^1^2__MSBROWSE__^2^1

  note: this name is registered if as a master browser or backup browser
  you are responsible for a workgroup (when you announce a domain by
  broadcasting on your local subnet, you announce it as coming from this
  name: see announce_host()).

  **************************************************************************/
BOOL ms_browser_name(char *name, int type)
{
  return strequal(name,MSBROWSE) && type == 0x01;
}


/****************************************************************************
  add a netbios name into the namelist
  **************************************************************************/
static void add_name(struct subnet_record *d, struct name_record *n)
{
  struct name_record *n2;

  if (!d) return;

  if (!d->namelist)
  {
    d->namelist = n;
    n->prev = NULL;
    n->next = NULL;
    return;
  }

  for (n2 = d->namelist; n2->next; n2 = n2->next) ;

  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}


/****************************************************************************
  remove a name from the namelist. The pointer must be an element just 
  retrieved
  **************************************************************************/
void remove_name(struct subnet_record *d, struct name_record *n)
{
  struct name_record *nlist;
  if (!d) return;

  nlist = d->namelist;

  while (nlist && nlist != n) nlist = nlist->next;

  if (nlist)
  {
    if (nlist->next) nlist->next->prev = nlist->prev;
    if (nlist->prev) nlist->prev->next = nlist->next;
    free(nlist);
  }
}


/****************************************************************************
  find a name in a namelist.
  **************************************************************************/
struct name_record *find_name(struct name_record *n,
			struct nmb_name *name,
			int search, struct in_addr ip)
{
	struct name_record *ret;
  
	for (ret = n; ret; ret = ret->next)
	{
		if (name_equal(&ret->name,name))
		{
			/* self search: self names only */
			if ((search&FIND_SELF) == FIND_SELF && ret->source != SELF)
				continue;
	  
			/* zero ip is either samba's ip or a way of finding a
			   name without needing to know the ip address */
			if (zero_ip(ip) || ip_equal(ip, ret->ip))
			{
				return ret;
			}
		}
	}
    return NULL;
}


/****************************************************************************
  find a name in the domain database namelist 
  search can be any of:
  FIND_SELF - look exclusively for names the samba server has added for itself
  FIND_LOCAL - look for names in the local subnet record.
  FIND_WINS - look for names in the WINS record
  **************************************************************************/
struct name_record *find_name_search(struct subnet_record **d,
			struct nmb_name *name,
			int search, struct in_addr ip)
{
	if (d == NULL) return NULL; /* bad error! */
	
    if ((search & FIND_LOCAL) == FIND_LOCAL)
	{
		if (*d != NULL)
        {
			return find_name((*d)->namelist, name, search, ip);
		}
        else
        {
			DEBUG(4,("local find_name_search with a NULL subnet pointer\n"));
            return NULL;
		}
	}

	if ((search & FIND_WINS) != FIND_WINS) return NULL;

	if (*d == NULL)
	{
		/* find WINS subnet record */
		*d = find_subnet(ipgrp);
    }

	if (*d == NULL) return NULL;

	return find_name((*d)->namelist, name, search, ip);
}


/****************************************************************************
  dump a copy of the name table
  **************************************************************************/
void dump_names(void)
{
  struct name_record *n;
  struct subnet_record *d;
  fstring fname, fnamenew;
  time_t t = time(NULL);
  
  FILE *f;
  
  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,WINS_LIST);
  strcpy(fnamenew,fname);
  strcat(fnamenew,".");
  
  f = fopen(fnamenew,"w");
  
  if (!f)
  {
    DEBUG(4,("Can't open %s - %s\n",fnamenew,strerror(errno)));
  }
  
  DEBUG(3,("Dump of local name table:\n"));
  
  for (d = subnetlist; d; d = d->next)
   for (n = d->namelist; n; n = n->next)
    {
      if (f && ip_equal(d->bcast_ip, ipgrp) && n->source == REGISTER)
      {
        fstring data;

      /* XXXX i have little imagination as to how to output nb_flags as
         anything other than as a hexadecimal number :-) */

        sprintf(data, "%s#%02x %s %2x %ld",
	       n->name.name,n->name.name_type, /* XXXX ignore the scope for now */
	       inet_ntoa(n->ip),
	       n->nb_flags,
	       n->death_time);
	    fprintf(f, "%s\n", data);
      }

	  DEBUG(3,("%15s ", inet_ntoa(d->bcast_ip)));
	  DEBUG(3,("%15s ", inet_ntoa(d->mask_ip)));
      DEBUG(3,("%-19s %15s NB=%2x TTL=%ld \n",
	       namestr(&n->name),
	       inet_ntoa(n->ip),
	       n->nb_flags,
           n->death_time?n->death_time-t:0));
    }

  fclose(f);
  unlink(fname);
  chmod(fnamenew,0644);
  rename(fnamenew,fname);   

  DEBUG(3,("Wrote wins database %s\n",fname));
}


/****************************************************************************
load a netbios name database file
****************************************************************************/
void load_netbios_names(void)
{
  struct subnet_record *d = find_subnet(ipgrp);
  fstring fname;

  FILE *f;
  pstring line;

  if (!d) return;

  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,WINS_LIST);

  f = fopen(fname,"r");

  if (!f) {
    DEBUG(2,("Can't open wins database file %s\n",fname));
    return;
  }

  while (!feof(f))
    {
      pstring name_str, ip_str, ttd_str, nb_flags_str;

      pstring name;
      int type = 0;
      int nb_flags;
      time_t ttd;
	  struct in_addr ipaddr;

	  enum name_source source;

      char *ptr;
	  int count = 0;

      char *p;

      if (!fgets_slash(line,sizeof(pstring),f)) continue;

      if (*line == '#') continue;

	ptr = line;

	if (next_token(&ptr,name_str    ,NULL)) ++count;
	if (next_token(&ptr,ip_str      ,NULL)) ++count;
	if (next_token(&ptr,ttd_str     ,NULL)) ++count;
	if (next_token(&ptr,nb_flags_str,NULL)) ++count;

	if (count <= 0) continue;

	if (count != 4) {
	  DEBUG(0,("Ill formed wins line"));
	  DEBUG(0,("[%s]: name#type ip nb_flags abs_time\n",line));
	  continue;
	}

      /* netbios name. # divides the name from the type (hex): netbios#xx */
      strcpy(name,name_str);

      p = strchr(name,'#');

      if (p) {
	    *p = 0;
	    sscanf(p+1,"%x",&type);
      }

      /* decode the netbios flags (hex) and the time-to-die (seconds) */
	  sscanf(nb_flags_str,"%x",&nb_flags);
	  sscanf(ttd_str,"%ld",&ttd);

	  ipaddr = *interpret_addr2(ip_str);

      if (ip_equal(ipaddr,ipzero)) {
         source = SELF;
      }
      else
      {
         source = REGISTER;
      }

      DEBUG(4, ("add WINS line: %s#%02x %s %ld %2x\n",
	       name,type, inet_ntoa(ipaddr), ttd, nb_flags));

      /* add all entries that have 60 seconds or more to live */
      if (ttd - 60 < time(NULL) || ttd == 0)
      {
        time_t t = (ttd?ttd-time(NULL):0) / 3;

        /* add netbios entry read from the wins.dat file. IF it's ok */
        add_netbios_entry(d,name,type,nb_flags,t,source,ipaddr,True,True);
      }
    }

  fclose(f);
}


/****************************************************************************
  remove an entry from the name list
  ****************************************************************************/
void remove_netbios_name(struct subnet_record *d,
			char *name,int type, enum name_source source,
			 struct in_addr ip)
{
  struct nmb_name nn;
  struct name_record *n;

  make_nmb_name(&nn, name, type, scope);
  n = find_name_search(&d, &nn, FIND_LOCAL, ip);
  
  if (n && n->source == source) remove_name(d,n);
}


/****************************************************************************
  add an entry to the name list.

  this is a multi-purpose function.

  it adds samba's own names in to its records on each interface, keeping a
  record of whether it is a master browser, domain master, or WINS server.

  it also keeps a record of WINS entries.

  ****************************************************************************/
struct name_record *add_netbios_entry(struct subnet_record *d,
		char *name, int type, int nb_flags, 
		int ttl, enum name_source source, struct in_addr ip,
		BOOL new_only,BOOL wins)
{
  struct name_record *n;
  struct name_record *n2=NULL;
  int search = 0;
  BOOL self = source == SELF;

  /* add the name to the WINS list if the name comes from a directed query */
  search |= wins ? FIND_WINS : FIND_LOCAL;
  /* search for SELF names only */
  search |= self ? FIND_SELF : 0;

  if (!self)
  {
    if (!wins && type != 0x1b)
    {
       /* the only broadcast (non-WINS) names we are adding are ours
          (SELF) and PDC type names */
       return NULL;
    }
  }

  n = (struct name_record *)malloc(sizeof(*n));
  if (!n) return(NULL);

  bzero((char *)n,sizeof(*n));

  make_nmb_name(&n->name,name,type,scope);

  if ((n2 = find_name_search(&d, &n->name, search, new_only?ipzero:ip)))
  {
    free(n);
    if (new_only || (n2->source==SELF && source!=SELF)) return n2;
    n = n2;
  }

  if (ttl)
     n->death_time = time(NULL)+ttl*3;
  n->refresh_time = time(NULL)+GET_TTL(ttl);

  n->ip = ip;
  n->nb_flags = nb_flags;
  n->source = source;
  
  if (!n2) add_name(d,n);

  DEBUG(3,("Added netbios name %s at %s ttl=%d nb_flags=%2x\n",
	        namestr(&n->name),inet_ntoa(ip),ttl,nb_flags));

  return(n);
}


/*******************************************************************
  expires old names in the namelist
  ******************************************************************/
void expire_names(time_t t)
{
	struct name_record *n;
	struct name_record *next;
	struct subnet_record *d;

	/* expire old names */
	for (d = subnetlist; d; d = d->next)
	{
	  for (n = d->namelist; n; n = next)
		{
		  if (n->death_time && n->death_time < t)
		{
		  DEBUG(3,("Removing dead name %s\n", namestr(&n->name)));
		  
		  next = n->next;
		  
		  if (n->prev) n->prev->next = n->next;
		  if (n->next) n->next->prev = n->prev;
		  
		  if (d->namelist == n) d->namelist = n->next; 
		  
		  free(n);
		}
		  else
		{
		  next = n->next;
		}
		}
	}
}


/***************************************************************************
  reply to a name query
  ****************************************************************************/
struct name_record *search_for_name(struct subnet_record **d,
					struct nmb_name *question,
				    struct in_addr ip, int Time, int search)
{
  int name_type = question->name_type;
  char *qname = question->name;
  BOOL dns_type = name_type == 0x20 || name_type == 0;
  
  struct name_record *n;
  
  DEBUG(3,("Search for %s from %s - ", namestr(question), inet_ntoa(ip)));
  
  /* first look up name in cache */
  n = find_name_search(d,question,search,ip);
  
  if (*d == NULL) return NULL;

  DEBUG(4,("subnet %s ", inet_ntoa((*d)->bcast_ip)));

  /* now try DNS lookup. */
  if (!n)
    {
      struct in_addr dns_ip;
      unsigned long a;
      
      /* only do DNS lookups if the query is for type 0x20 or type 0x0 */
      if (!dns_type && name_type != 0x1b)
	{
	  DEBUG(3,("types 0x20 0x1b 0x0 only: name not found\n"));
	  return NULL;
	}
      
      /* look it up with DNS */      
      a = interpret_addr(qname);
      
      putip((char *)&dns_ip,(char *)&a);
      
      if (!a)
	{
	  /* no luck with DNS. We could possibly recurse here XXXX */
	  DEBUG(3,("no recursion.\n"));
      /* add the fail to our WINS cache of names. give it 1 hour in the cache */
	  add_netbios_entry(*d,qname,name_type,NB_ACTIVE,60*60,DNSFAIL,dns_ip,
						True, True);
	  return NULL;
	}
      
      /* add it to our WINS cache of names. give it 2 hours in the cache */
      n = add_netbios_entry(*d,qname,name_type,NB_ACTIVE,2*60*60,DNS,dns_ip,
						True,True);
      
      /* failed to add it? yikes! */
      if (!n) return NULL;
    }
  
  /* is our entry already dead? */
  if (n->death_time)
    {
      if (n->death_time < Time) return False;
    }
  
  /* it may have been an earlier failure */
  if (n->source == DNSFAIL)
    {
      DEBUG(3,("DNSFAIL\n"));
      return NULL;
    }
  
  DEBUG(3,("OK %s\n",inet_ntoa(n->ip)));      
  
  return n;
}


