/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Luke Kenneth Casson Leighton 1994-1998
   Copyright (C) Jeremy Allison 1994-1998
   
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

extern int DEBUGLEVEL;

extern pstring scope;
extern pstring myname;
extern fstring myworkgroup;
extern char **my_netbios_names;
extern struct in_addr ipzero;
extern struct in_addr allones_ip;

extern uint16 samba_nb_type; /* Samba's NetBIOS type. */

static void become_domain_master_browser_bcast(char *);

/*******************************************************************
  Unbecome a domain master browser - name release success function.
  ******************************************************************/

static void unbecome_dmb_success(struct subnet_record *subrec,
                                 struct userdata_struct *userdata,
                                 struct nmb_name *released_name,
                                 struct in_addr released_ip)
{
  struct work_record *work = find_workgroup_on_subnet(subrec, released_name->name);
  struct server_record *servrec;

  if(!work)
  {
    DEBUG(0,("unbecome_dmb_success: Cannot find workgroup %s on subnet %s\n",
             released_name->name, subrec->subnet_name));
    return;
  }

  if((servrec = find_server_in_workgroup( work, myname)) == NULL)
  {
    DEBUG(0,("unbecome_dmb_success: Error - cannot find server %s \
in workgroup %s on subnet %s\n",
       myname, released_name->name, subrec->subnet_name));
    return;
  }

  /* Set the state in the workgroup structure. */
  work->dom_state = DOMAIN_NONE;

  /* Update our server status. */
  servrec->serv.type &= ~SV_TYPE_DOMAIN_MASTER;

  /* Tell the namelist writer to write out a change. */
  subrec->work_changed = True;

  /* Remove any list of local master browsers we are syncing with. */
  remove_workgroup_lmb_browsers(released_name->name);

  /* Delete the known domain master browser name from the workgroup
     struct. */
  bzero((char *)&work->dmb_name, sizeof(work->dmb_name));
  putip((char *)&work->dmb_addr, &ipzero);

  DEBUG(0,("\n%s ***** Samba server %s has stopped being a domain master browser \
for workgroup %s on subnet %s *****\n\n", timestring(), myname, work->work_group, subrec->subnet_name));

}

/*******************************************************************
  Unbecome a domain master browser - name release fail function.
  ******************************************************************/

static void unbecome_dmb_fail(struct subnet_record *subrec,
                                 struct response_record *rrec,
                                 struct nmb_name *released_name)
{
  DEBUG(0,("unbecome_dmb_fail: Failed to unbecome domain master browser for \
workgroup %s on subnet %s.\n", released_name->name, subrec->subnet_name));
}

/*******************************************************************
  Unbecome a domain master browser.
  ******************************************************************/

void unbecome_domain_master(char *workgroup_name)
{   
  struct subnet_record *subrec;

  for (subrec = FIRST_SUBNET; subrec; subrec = NEXT_SUBNET_INCLUDING_UNICAST(subrec))
  {
    struct work_record *work = find_workgroup_on_subnet(subrec, workgroup_name);

    if(work && (work->dom_state == DOMAIN_MST))
    {
      struct name_record *namerec;
      struct nmb_name nmbname;
      make_nmb_name(&nmbname,workgroup_name,0x1b,scope);

      /* We can only do this if we are a domain master already. */
      DEBUG(2,("unbecome_domain_master: attempting to stop being a domain \
master browser for workgroup %s on subnet %s\n",
              work->work_group, subrec->subnet_name));
   
      /* Find the WORKGROUP<1b> name on the subnet namelist. */
      if((namerec = find_name_on_subnet(subrec, &nmbname, FIND_SELF_NAME))==NULL)
      {
        DEBUG(0,("unbecome_domain_master: Cannot find name %s on subnet %s.\n",
                namestr(&nmbname), subrec->subnet_name));
        continue;
      }
      release_name(subrec, namerec, 
                   unbecome_dmb_success,
                   unbecome_dmb_fail,
                   NULL);
    }
  }
} 

/****************************************************************************
  Fail to become a Domain Master Browser on a subnet.
  ****************************************************************************/

static void become_domain_master_fail(struct subnet_record *subrec,
                                      struct response_record *rrec,
                                      struct nmb_name *fail_name)
{
  struct work_record *work = find_workgroup_on_subnet(subrec, fail_name->name);
  struct server_record *servrec;

  if(!work)
  {
    DEBUG(0,("become_domain_master_fail: Error - cannot find \
workgroup %s on subnet %s\n", fail_name->name, subrec->subnet_name));
    return;
  }

  /* Set the state back to DOMAIN_NONE. */
  work->dom_state = DOMAIN_NONE;

  if((servrec = find_server_in_workgroup( work, myname)) == NULL)
  {
    DEBUG(0,("become_domain_master_fail: Error - cannot find server %s \
in workgroup %s on subnet %s\n",
       myname, work->work_group, subrec->subnet_name));
    return;
  }

  /* Update our server status. */
  servrec->serv.type &= ~SV_TYPE_DOMAIN_MASTER;

  /* Tell the namelist writer to write out a change. */
  subrec->work_changed = True;

  DEBUG(0,("become_domain_master_fail: Failed to become a domain master browser for \
workgroup %s on subnet %s. Couldn't register name %s.\n",
       work->work_group, subrec->subnet_name, namestr(fail_name)));
}

/****************************************************************************
  Become a Domain Master Browser on a subnet.
  ****************************************************************************/

static void become_domain_master_stage2(struct subnet_record *subrec, 
                                        struct userdata_struct *userdata,
                                        struct nmb_name *registered_name,
                                        uint16 nb_flags,
                                        int ttl, struct in_addr registered_ip)
{
  struct work_record *work = find_workgroup_on_subnet( subrec, registered_name->name);
  struct server_record *servrec;

  if(!work)
  {
    DEBUG(0,("become_domain_master_stage2: Error - cannot find \
workgroup %s on subnet %s\n", registered_name->name, subrec->subnet_name));
    return;
  }

  if((servrec = find_server_in_workgroup( work, myname)) == NULL)
  {
    DEBUG(0,("become_domain_master_stage2: Error - cannot find server %s \
in workgroup %s on subnet %s\n", 
       myname, registered_name->name, subrec->subnet_name));
    work->dom_state = DOMAIN_NONE;
    return;
  }

  /* Set the state in the workgroup structure. */
  work->dom_state = DOMAIN_MST; /* Become domain master. */

  /* Update our server status. */
  servrec->serv.type |= (SV_TYPE_NT|SV_TYPE_DOMAIN_MASTER);

  /* Tell the namelist writer to write out a change. */
  subrec->work_changed = True;

  DEBUG(0,("\n%s ***** Samba server %s is now a domain master browser for \
workgroup %s on subnet %s *****\n\n", timestring(),myname, work->work_group, 
subrec->subnet_name));

  if(subrec == unicast_subnet)
  {
    struct nmb_name nmbname;
    struct in_addr my_first_ip;

    /* Put our name and first IP address into the 
       workgroup struct as domain master browser. This
       will stop us syncing with ourself if we are also
       a local master browser. */

    make_nmb_name(&nmbname, myname, 0x20, scope);

    work->dmb_name = nmbname;
    /* Pick the first interface ip address as the domain master browser ip. */
    my_first_ip = *iface_n_ip(0);

    putip((char *)&work->dmb_addr, &my_first_ip);

    /* We successfully registered by unicast with the
       WINS server.  We now expect to become the domain
       master on the local subnets. If this fails, it's
       probably a 1.9.16p2 to 1.9.16p11 server's fault.

       This is a configuration issue that should be addressed
       by the network administrator - you shouldn't have
       several machines configured as a domain master browser
       for the same WINS scope (except if they are 1.9.17 or
       greater, and you know what you're doing.

       see docs/DOMAIN.txt.

     */
    become_domain_master_browser_bcast(work->work_group);
  }
}

/****************************************************************************
  Start the name registration process when becoming a Domain Master Browser
  on a subnet.
  ****************************************************************************/

static void become_domain_master_stage1(struct subnet_record *subrec, char *wg_name)
{ 
  struct work_record *work;

  DEBUG(2,("become_domain_master_stage1: Becoming domain master browser for \
workgroup %s on subnet %s\n", wg_name, subrec->subnet_name));

  /* First, find the workgroup on the subnet. */
  if((work = find_workgroup_on_subnet( subrec, wg_name )) == NULL)
  {
    DEBUG(0,("become_domain_master_stage1: Error - unable to find workgroup %s on subnet %s.\n",
          wg_name, subrec->subnet_name));
    return;
  }

  DEBUG(3,("become_domain_master_stage1: go to first stage: register <1b> name\n"));
  work->dom_state = DOMAIN_WAIT;

  /* WORKGROUP<1b> is the domain master browser name. */
  register_name(subrec, work->work_group,0x1b,samba_nb_type,
                become_domain_master_stage2,
                become_domain_master_fail, NULL);
}

/****************************************************************************
  Function called when a query for a WORKGROUP<1b> name succeeds.
  This is normally a fail condition as it means there is already
  a domain master browser for a workgroup and we were trying to
  become one.
****************************************************************************/

static void become_domain_master_query_success(struct subnet_record *subrec,
                        struct userdata_struct *userdata,
                        struct nmb_name *nmbname, struct in_addr ip, 
                        struct res_rec *rrec)
{
  /* If the given ip is not ours, then we can't become a domain
     controler as the name is already registered.
   */

 /* BUG note. Samba 1.9.16p11 servers seem to return the broadcast
    address or zero ip for this query. Pretend this is ok. */

  if(ismyip(ip) || ip_equal(allones_ip, ip) || ip_equal(ipzero, ip))
  {
    DEBUG(3,("become_domain_master_query_success: Our address (%s) returned \
in query for name %s (domain master browser name) on subnet %s. \
Continuing with domain master code.\n", 
           inet_ntoa(ip), namestr(nmbname), subrec->subnet_name));

    become_domain_master_stage1(subrec, nmbname->name);
  }
  else
  {
    DEBUG(0,("%s become_domain_master_query_success: There is already a domain \
master browser at IP %s for workgroup %s registered on subnet %s.\n",
          timestring(), inet_ntoa(ip), nmbname->name, subrec->subnet_name));
  }
}

/****************************************************************************
  Function called when a query for a WORKGROUP<1b> name fails.
  This is normally a success condition as it then allows us to register
  our own Domain Master Browser name.
  ****************************************************************************/

static void become_domain_master_query_fail(struct subnet_record *subrec,
                                    struct response_record *rrec,
                                    struct nmb_name *question_name, int fail_code)
{
  /* If the query was unicast, and the error is not NAM_ERR (name didn't exist),
     then this is a failure. Otherwise, not finding the name is what we want. */
  if((subrec == unicast_subnet) && (fail_code != NAM_ERR))
  {
    DEBUG(0,("become_domain_master_query_fail: Error %d returned when \
querying WINS server for name %s.\n", 
                  fail_code, namestr(question_name)));
    return;
  }

  /* Otherwise - not having the name allows us to register it. */
  become_domain_master_stage1(subrec, question_name->name);
}

/****************************************************************************
  Attempt to become a domain master browser on all broadcast subnets.
  ****************************************************************************/

static void become_domain_master_browser_bcast(char *workgroup_name)
{
  struct subnet_record *subrec;

  for (subrec = FIRST_SUBNET; subrec; subrec = NEXT_SUBNET_EXCLUDING_UNICAST(subrec))
  { 
    struct work_record *work = find_workgroup_on_subnet(subrec, workgroup_name);

    if (work && (work->dom_state == DOMAIN_NONE))
    {
      struct nmb_name nmbname;
      make_nmb_name(&nmbname,workgroup_name,0x1b,scope);

      /*
       * Check for our name on the given broadcast subnet first, only initiate
       * further processing if we cannot find it.
       */

      if (find_name_on_subnet(subrec, &nmbname, FIND_SELF_NAME) == NULL)
      {
        DEBUG(0,("become_domain_master_browser_bcast: At time %s attempting to become domain \
master browser on workgroup %s on subnet %s\n", timestring(), 
                 workgroup_name, subrec->subnet_name));

        /* Send out a query to establish whether there's a 
           domain controller on the local subnet. If not,
           we can become a domain controller. 
         */

        DEBUG(0,("become_domain_master_browser_bcast: querying subnet %s \
for domain master browser on workgroup %s\n", subrec->subnet_name, workgroup_name));

        query_name(subrec, nmbname.name, nmbname.name_type,
                   become_domain_master_query_success, 
                   become_domain_master_query_fail,
                   NULL);
      }
    }
  }
}

/****************************************************************************
  Attempt to become a domain master browser by registering with WINS.
  ****************************************************************************/

static void become_domain_master_browser_wins(char *workgroup_name)
{
  struct work_record *work;

  work = find_workgroup_on_subnet(unicast_subnet, workgroup_name);

  if (work && (work->dom_state == DOMAIN_NONE))
  {
    struct nmb_name nmbname;

    make_nmb_name(&nmbname,workgroup_name,0x1b,scope);

    /*
     * Check for our name on the unicast subnet first, only initiate
     * further processing if we cannot find it.
     */

    if (find_name_on_subnet(unicast_subnet, &nmbname, FIND_SELF_NAME) == NULL)
    {
      DEBUG(0,("%s become_domain_master_browser_wins: attempting to become domain \
master browser on workgroup %s, subnet %s.\n",
      timestring(), workgroup_name, unicast_subnet->subnet_name));

      /* Send out a query to establish whether there's a 
         domain master broswer registered with WINS. If not,
         we can become a domain master browser. 
       */

      DEBUG(0,("become_domain_master_browser_wins: querying WINS server at IP %s \
for domain master browser name %s on workgroup %s\n",
         inet_ntoa(unicast_subnet->myip), namestr(&nmbname), workgroup_name));

      query_name(unicast_subnet, nmbname.name, nmbname.name_type,
                   become_domain_master_query_success,
                   become_domain_master_query_fail,
                   NULL);
    }
  }
}

/****************************************************************************
  Add the domain logon server and domain master browser names
  if we are set up to do so.
  **************************************************************************/

void add_domain_names(time_t t)
{
  static time_t lastrun = 0;

  if ((lastrun != 0) && (t < lastrun + (CHECK_TIME_ADD_DOM_NAMES * 60)))
    return;

  lastrun = t;

  /* Do the "internet group" - <1c> names. */
  if (lp_domain_logons())
    add_logon_names();

  /* Do the domain master names. */
  if(lp_domain_master())
  {
    if(we_are_a_wins_client())
    {
      /* We register the WORKGROUP<1b> name with the WINS
         server first, and call add_domain_master_bcast()
         only if this is successful.

         This results in domain logon services being gracefully provided,
         as opposed to the aggressive nature of 1.9.16p2 to 1.9.16p11.
         1.9.16p2 to 1.9.16p11 - due to a bug in namelogon.c,
         cannot provide domain master / domain logon services.
       */
      become_domain_master_browser_wins(myworkgroup);
    }
    else
      become_domain_master_browser_bcast(myworkgroup);
  }
}
