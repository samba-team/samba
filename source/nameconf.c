/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) David Chappell 1996-1998
   
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

   30 July 96: David.Chappell@mail.trincoll.edu
   Expanded multiple workgroup domain master browser support.

*/

/*
** nameconf.c
** These functions dispense information from smbbrowse.conf.
**
**
*/

#include "includes.h"
extern int DEBUGLEVEL;

extern fstring myworkgroup;

#if 0
struct smbbrowse_parms
    {
    char *name;
    BOOL (*reader)(char *string, void *toset);
    } smbbrowse_table[] =
{
    {"preferred master", NULL},
    {"local master", NULL},
    {"domain master", NULL}
} ;
#endif

/*
** Structure for the list of workgroups from smbbrowse.conf.  This 
** structure should only be manipulated thru the functions in this file.
** That is why it is not defined in a header file.
*/
struct smbbrowse
{
    char work_name[16];               /* workgroup name */
    char browsing_alias[16];          /* alias for our role in this workgroup */
    struct server_identity *my_names; /* a list of server name we should appear here as */
    BOOL should_workgroup_member;     /* should we try to become a member of this workgroup? */
    BOOL should_local_master;         /* should we try to become a master browser? */
    BOOL should_domain_master;        /* should we try to become the domain master browser? */
} ;

/* The whole list */
static struct smbbrowse *smbbrowse_workgroups = (struct smbbrowse*)NULL;

/* The size of the list */
static int array_size = 0;

/* The next available space in the list */
static int nexttoken = 0;

int get_num_workgroups(void)
{
    return nexttoken;
}

/*
** This makes a new workgroup structure, possibly taking an 
** old one as a model.
*/
static struct smbbrowse *new_workgroup(struct smbbrowse *model,
				       char *workgroup_name,
				       char *default_name)
{
    struct smbbrowse *new;

    if( ! (array_size > nexttoken) )
    {
    array_size += 10;
    smbbrowse_workgroups = (struct smbbrowse*)realloc(smbbrowse_workgroups,
                array_size * sizeof(struct smbbrowse));
    }

    new = &smbbrowse_workgroups[nexttoken];

    if(model != (struct smbbrowse *)NULL )
    memcpy(new, model, sizeof(struct smbbrowse));
    else
        memset(new, 0, sizeof(struct smbbrowse));

    StrnCpy(new->work_name, workgroup_name, 15);
    strupper(new->work_name);
        
	if (strequal(myworkgroup, workgroup_name))
      StrnCpy(new->browsing_alias, default_name, 15);
    else
      sprintf(new->browsing_alias, "%.14s%x", default_name, nexttoken);
    strupper(new->browsing_alias);

	DEBUG(4,("wg: %s alias: %s token: %x\n",
		new->work_name, new->browsing_alias, nexttoken));

    nexttoken++;
    return new;
}

/*
** If fed a workgroup name, this function returns its token number.
** If the workgroup does not exist a new token is assigned unless
** new workgroups are not allowed.
*/
int conf_workgroup_name_to_token(char *workgroup_name,char *default_name)
{
    int idx;
    
    /* Look for an existing instance. */
    for(idx=0; idx < nexttoken; idx++)
    {
        if(strequal(workgroup_name, smbbrowse_workgroups[idx].work_name))
        {
            return idx;
        }
    }
    
    /* See if creating new ones in admissable. */
    for(idx=0; idx < nexttoken; idx++)
    {
        if(strequal("*", smbbrowse_workgroups[idx].work_name))
        {
            struct smbbrowse *w = new_workgroup(&smbbrowse_workgroups[idx],
                                                workgroup_name, default_name);
            w->should_workgroup_member = False;

            return (nexttoken - 1);
        }
    }

    /* Not allowed */
    DEBUG(4, ("refusing to allow new workgroup\n"));
    return -1;
}

/*
** This is a workgroups array bounds checker.
*/
static int range_check(int token)
{
    if(token < 0 || token >= nexttoken)
    {
    DEBUG(0, ("range_check(): failed\n"));
        return True;
        }
        
    return False;
}

/*
** Given a token, return the name.
*/
char *conf_workgroup_name(int token)
{
    if(range_check(token))
        return (char*)NULL;
    
    return smbbrowse_workgroups[token].work_name;
}

/*
** Given a token, return True if we should try
** to become a master browser.
*/
int conf_should_workgroup_member(int token)
    {

    if(range_check(token))
        return False;
    
    return smbbrowse_workgroups[token].should_workgroup_member;
    }

/*
** Given a token, return True if we should try
** to become a master browser.
*/
int conf_should_local_master(int token)
    {
    if(range_check(token))
        return False;
    
    return smbbrowse_workgroups[token].should_local_master;
    }

/*
** Given a token, return True if we should try
** to become a domain master browser.
*/
int conf_should_domain_master(int token)
    {
    if(range_check(token))
        return False;
    
    return smbbrowse_workgroups[token].should_domain_master;
    }

/*
** Given a token, return the name.
*/
char *conf_browsing_alias(int token)
    {
    if(range_check(token))
        return (char*)NULL;

    return smbbrowse_workgroups[token].browsing_alias;
    }

/*
** Return the server comment which should be used with the
** browsing alias.
*/
char *conf_browsing_alias_comment(int token)
{
    if(range_check(token))
        return (char*) NULL;
        
    return "Browser";
    }       

/*
** Given an alias name for this server, return the name of the workgroup 
** for which it is the browsing alias.
*/
char *conf_alias_to_workgroup(char *alias)
{
    int x;
    
	DEBUG(4,("alias_to_workgroup: %s", alias));

    for(x=0; x < nexttoken; x++)
    {
		DEBUG(4,("%s ", smbbrowse_workgroups[x].browsing_alias));

        if(strequal(alias, smbbrowse_workgroups[x].browsing_alias))
        {
			DEBUG(4,("OK\n"));
            return smbbrowse_workgroups[x].work_name;
        }
    }
	DEBUG(4,("not found\n"));
    return (char*)NULL;
}

/*
** Given an alias name for this server, return the name of the workgroup 
** for which it is the browsing alias.
*/
int conf_alias_to_token(char *alias)
{
    int x;
    
    for(x=0; x < nexttoken; x++)
    {
        if(strequal(alias, smbbrowse_workgroups[x].browsing_alias))
        {
            return x;
        }
    }
    return -1;
}

/*
** Since there is no smbbrowse.conf file, we will fill in 
** the structures with information from the smb.conf file.
*/
static void default_smbbrowse_conf(char *default_name)
{
    struct smbbrowse *w;
    
    /* The workgroup specified in smb.conf */
    w = new_workgroup((struct smbbrowse *)NULL, myworkgroup, default_name);
    w->should_local_master = lp_preferred_master();
    w->should_domain_master = lp_domain_master();
    w->should_workgroup_member = True;

    /* default action: allow any new workgroup to be added */
    w = new_workgroup((struct smbbrowse *)NULL, "*", default_name);
    w->should_local_master = False;
    w->should_domain_master = False;
    w->should_workgroup_member = False;
}

/*
** This function is called from main().
*/
void read_smbbrowse_conf(char *default_name)
{
  FILE *f = fopen(BROWSEFILE,"r");
  if (f)
  {
    while (!feof(f))
    {
      pstring line;
      char *ptr;
      int count = 0;
  
      pstring work_name;
      struct smbbrowse *w;

      if (!fgets_slash(line,sizeof(pstring),f)) continue;
  
      if (*line == '#') continue;
  
      strcpy(work_name,"");
        
      ptr = line;
        
      if (next_token(&ptr, work_name, NULL)) ++count;
        
      if (count <= 0) continue;
        
      w = new_workgroup((struct smbbrowse *)NULL, work_name, default_name);
      w->should_local_master = lp_local_master();
      w->should_domain_master = lp_domain_master();
      w->should_workgroup_member = True;
    }

    fclose(f);
  }
  else
  {
    DEBUG(2,("Can't open browse configuration file %s\n",BROWSEFILE));
  }
  default_smbbrowse_conf(default_name);    
}


