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
extern struct in_addr wins_ip;
extern BOOL updatedlists;

extern struct subnet_record *subnetlist;

#define WINS_LIST "wins.dat"

uint16 nb_type = 0; /* samba's NetBIOS name type */


/****************************************************************************
  samba's NetBIOS name type

  XXXX maybe functionality could be set: B, M, P or H name registration
  and resolution could be set through nb_type. just a thought.  
  ****************************************************************************/
void set_samba_nb_type(void)
{
  if (lp_wins_support() || (*lp_wins_server()))
  {
    nb_type = NB_MFLAG; /* samba is a 'hybrid' node type */
  }
  else
  {
    nb_type = NB_BFLAG; /* samba is broadcast-only node type */
  }
}


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

  if((d == wins_client_subnet) && lp_wins_support())
    updatedlists = True;
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

    if(nlist == d->namelist)
      d->namelist = nlist->next;

    if(nlist->ip_flgs != NULL)
      free(nlist->ip_flgs);
    free(nlist);
  }

  if((d == wins_client_subnet) && lp_wins_support())
    updatedlists = True;
}


/****************************************************************************
  find a name in a subnet.
  **************************************************************************/
struct name_record *find_name_on_subnet(struct subnet_record *d,
			struct nmb_name *name, BOOL self_only)
{
  struct name_record *n = d->namelist;
  struct name_record *ret;
  
  for (ret = n; ret; ret = ret->next)
  {
    if (name_equal(&ret->name,name))
    {
      /* self search: self names only */
      if (self_only && (ret->source != SELF))
      {
        continue;
      }
      DEBUG(9,("find_name_on_subnet: on subnet %s - found name %s(%02x) source=%d\n", 
                inet_ntoa(d->bcast_ip), name->name, name->name_type, ret->source));
      return ret;
    }
  }
  DEBUG(9,("find_name_on_subnet: on subnet %s - name %s(%02x) NOT FOUND\n", 
            inet_ntoa(d->bcast_ip), name->name, name->name_type));
  return NULL;
}

/****************************************************************************
  dump a copy of the name table
  **************************************************************************/
void dump_names(void)
{
  struct name_record *n;
  fstring fname, fnamenew;
  time_t t = time(NULL);
  
  FILE *f;
 
  if(lp_wins_support() == False || wins_client_subnet == NULL)
    return;
 
  fstrcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,WINS_LIST);
  fstrcpy(fnamenew,fname);
  strcat(fnamenew,".");
  
  f = fopen(fnamenew,"w");
  
  if (!f)
  {
    DEBUG(3,("Can't open %s - %s\n",fnamenew,strerror(errno)));
    return;
  }
  
  DEBUG(4,("Dump of WINS name table:\n"));
  
  for (n = wins_client_subnet->namelist; n; n = n->next)
   {
     int i;

     DEBUG(4,("%15s ", inet_ntoa(wins_client_subnet->bcast_ip)));
     DEBUG(4,("%15s ", inet_ntoa(wins_client_subnet->mask_ip)));
     DEBUG(4,("%-19s TTL=%ld ",
	       namestr(&n->name),
	       n->death_time?n->death_time-t:0));

     for (i = 0; i < n->num_ips; i++)
      {
        DEBUG(4,("%15s NB=%2x source=%d",
                 inet_ntoa(n->ip_flgs[i].ip),
		    n->ip_flgs[i].nb_flags,n->source));

      }
     DEBUG(4,("\n"));

     if (f && ((n->source == REGISTER) || (n->source == SELF)))
      {
      /* XXXX i have little imagination as to how to output nb_flags as
         anything other than as a hexadecimal number :-) */

        fprintf(f, "%s#%02x %ld ",
	       n->name.name,n->name.name_type, /* XXXX ignore scope for now */
	       n->death_time);

        for (i = 0; i < n->num_ips; i++)
        {
           fprintf(f, "%s %2x%c ",
                inet_ntoa(n->ip_flgs[i].ip),
                n->ip_flgs[i].nb_flags, (n->source == REGISTER ? 'R' : 'S'));
        }
        fprintf(f, "\n");
      }

  }

  fclose(f);
  unlink(fname);
  chmod(fnamenew,0644);
  rename(fnamenew,fname);   

  DEBUG(3,("Wrote wins database %s\n",fname));
}


/****************************************************************************
  load a netbios name database file

  XXXX we cannot cope with loading Internet Group names, yet
  ****************************************************************************/
void load_netbios_names(void)
{
  struct subnet_record *d = wins_client_subnet;
  fstring fname;

  FILE *f;
  pstring line;

  if (!d) return;

  fstrcpy(fname,lp_lockdir());
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
      unsigned int nb_flags;
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
	if (next_token(&ptr,ttd_str     ,NULL)) ++count;
	if (next_token(&ptr,ip_str      ,NULL)) ++count;
	if (next_token(&ptr,nb_flags_str,NULL)) ++count;

	if (count <= 0) continue;

	if (count != 4) {
	  DEBUG(0,("Ill formed wins line"));
	  DEBUG(0,("[%s]: name#type abs_time ip nb_flags\n",line));
	  continue;
	}

      /* Deal with SELF or REGISTER name encoding. Default is REGISTER 
         for compatibility with old nmbds. */
      if(nb_flags_str[strlen(nb_flags_str)-1] == 'S')
      {
        DEBUG(5,("Ignoring SELF name %s\n", line));
        continue;
      }

      if(nb_flags_str[strlen(nb_flags_str)-1] == 'R')
        nb_flags_str[strlen(nb_flags_str)-1] = '\0';

      /* netbios name. # divides the name from the type (hex): netbios#xx */
      pstrcpy(name,name_str);

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

      DEBUG(4, ("add WINS line: %s#%02x %ld %s %2x\n",
	       name,type, ttd, inet_ntoa(ipaddr), nb_flags));

      /* add all entries that have 60 seconds or more to live */
      if (ttd - 60 > time(NULL) || ttd == 0)
      {
        time_t t = (ttd?ttd-time(NULL):0) / 3;

        /* add netbios entry read from the wins.dat file. IF it's ok */
        add_netbios_entry(d,name,type,nb_flags,t,source,ipaddr,True);
      }
    }

  fclose(f);
}


/****************************************************************************
  remove an entry from the name list
  ****************************************************************************/
void remove_netbios_name(struct subnet_record *d,
			char *name,int type, enum name_source source)
{
  struct nmb_name nn;
  struct name_record *n;

  make_nmb_name(&nn, name, type, scope);
  n = find_name_on_subnet(d, &nn, FIND_ANY_NAME);
  
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
		char *name, int type, int nb_flags, int ttl, 
                enum name_source source, struct in_addr ip, BOOL new_only)
{
  struct name_record *n;
  struct name_record *n2=NULL;
  BOOL self = (source == SELF) ? FIND_SELF_NAME : FIND_ANY_NAME;
  /* It's a WINS add if we're adding to the wins_client_subnet. */
  BOOL wins = ( wins_client_subnet && (d == wins_client_subnet));

  if(d == NULL)
  {
    DEBUG(0,("add_netbios_entry: called with NULL subnet record. This is a bug - \
please report this.!\n"));
    return NULL;
  }

  if (!self)
  {
    if (!wins && (type != 0x1b))
    {
       /* the only broadcast (non-WINS) names we are adding are ours
          (SELF) and Domain Master type names */
       return NULL;
    }
    if(wins && (type == 0x1d))
    {
      /* Do not allow any 0x1d names to be registered in a WINS,
         database although we return success for them.
       */
      return NULL;
    }
  }

  n = (struct name_record *)malloc(sizeof(*n));
  if (!n) return(NULL);

  bzero((char *)n,sizeof(*n));

  n->num_ips = 1; /* XXXX ONLY USE THIS FUNCTION FOR ONE ENTRY */
  n->ip_flgs = (struct nmb_ip*)malloc(sizeof(*n->ip_flgs) * n->num_ips);
  if (!n->ip_flgs)
  {
     free(n);
     return NULL;
  }

  bzero((char *)n->ip_flgs, sizeof(*n->ip_flgs) * n->num_ips);

  make_nmb_name(&n->name,name,type,scope);

  if ((n2 = find_name_on_subnet(d, &n->name, self)))
  {
    free(n->ip_flgs);
    free(n);
    if (new_only || (n2->source==SELF && source!=SELF)) return n2;
    n = n2;
  }

  if (ttl)
     n->death_time = time(NULL)+ttl*3;
  n->refresh_time = time(NULL)+GET_TTL(ttl);

  /* XXXX only one entry expected with this function */
  n->ip_flgs[0].ip = ip;
  n->ip_flgs[0].nb_flags = nb_flags;

  n->source = source;
  
  if (!n2) add_name(d,n);

  DEBUG(3,("Added netbios name %s at %s ttl=%d nb_flags=%2x to interface %s\n",
	   namestr(&n->name),inet_ntoa(ip),ttl,nb_flags,
	   wins ? "WINS" : (char *)inet_ntoa(d->bcast_ip)));

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
  for (d = FIRST_SUBNET; d; d = NEXT_SUBNET_INCLUDING_WINS(d))
  {
    for (n = d->namelist; n; n = next)
    {
      next = n->next;
      if (n->death_time && n->death_time < t)
      {
        if (n->source == SELF) 
        {
          DEBUG(3,("not expiring SELF name %s\n", namestr(&n->name)));
                    n->death_time += 300;
          continue;
        }
        DEBUG(3,("Removing dead name %s\n", namestr(&n->name)));
		  
        if (n->prev) n->prev->next = n->next;
        if (n->next) n->next->prev = n->prev;
		  
        if (d->namelist == n) d->namelist = n->next; 
		  
        if(n->ip_flgs != NULL)
          free(n->ip_flgs);
        free(n);
      }
    }
  }
}


