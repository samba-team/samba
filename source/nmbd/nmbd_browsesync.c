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
#include "smb.h"

extern int DEBUGLEVEL;
extern pstring scope;
extern struct in_addr ipzero;
extern pstring myname;
extern fstring myworkgroup;

/* This is our local master browser list database. */
extern struct browse_cache_record *lmb_browserlist;

static struct work_record *call_work;
static struct subnet_record *call_subrec;

/*******************************************************************
  This is the NetServerEnum callback.
  ******************************************************************/

static void callback(char *sname, uint32 stype, char *comment)
{
  struct work_record *work;

  stype &= ~SV_TYPE_LOCAL_LIST_ONLY;

  if (stype & SV_TYPE_DOMAIN_ENUM) 
  {
    /* See if we can find the workgroup on this subnet. */
    if(( work = find_workgroup_on_subnet( call_subrec, sname )) != NULL)
    {
      /* We already know about this workgroup - update the ttl. */
      update_workgroup_ttl( work, lp_max_ttl() );
    }
    else
    {
      /* Create the workgroup on the subnet. */
      create_workgroup_on_subnet( call_subrec, sname, lp_max_ttl() );
    }
  }
  else
  {
    /* Server entry. */
    struct server_record *servrec;

    work = call_work;

    if(( servrec = find_server_in_workgroup( work, sname )) != NULL)
    {
      /* Check that this is not a locally known server - if so ignore the
         entry. */
      if(!(servrec->serv.type & SV_TYPE_LOCAL_LIST_ONLY))
      {
        /* We already know about this server - update the ttl. */
        update_server_ttl(servrec, lp_max_ttl() );
        /* Update the type. */
        servrec->serv.type = stype;
      }
    }
    else
    {
      /* Create the server in the workgroup. */ 
      create_server_on_workgroup(work, sname,stype,lp_max_ttl(),comment);
    }
  }
}

/*******************************************************************
  Synchronise browse lists with another browse server.
  Log in on the remote server's SMB port to their IPC$ service,
  do a NetServerEnum and update our server and workgroup databases.
******************************************************************/

static void sync_browse_lists(struct subnet_record *subrec, struct work_record *work,
		       char *name, int nm_type, struct in_addr ip, BOOL local)
{
  extern fstring local_machine;
  static struct cli_state cli;
  uint32 local_type = local ? SV_TYPE_LOCAL_LIST_ONLY : 0;

  DEBUG(2,("%s: sync_browse_lists: Sync browse lists with server %s<%02x> at IP %s for workgroup %s\n",
     timestring(), name, nm_type, inet_ntoa(ip), work->work_group ));

  /* Check we're not trying to sync with ourselves. This can happen if we are
     a domain *and* a local master browser. */
  if(ismyip(ip))
  {
    DEBUG(2,("sync_browse_lists: We are both a domain and a local master browser for workgroup %s. \
Do not sync with ourselves.\n", work->work_group ));
    return;
  }

  if (!cli_initialise(&cli) || !cli_connect(&cli, name, &ip))
  {
    DEBUG(0,("sync_browse_lists: Failed to start browse sync with %s\n", name));
    return;
  }

  if (!cli_session_request(&cli, name, nm_type, local_machine))
  {
    DEBUG(0,("sync_browse_lists: %s rejected the browse sync session\n",name));
    cli_shutdown(&cli);
    return;
  }

  if (!cli_negprot(&cli))
  {
    DEBUG(0,("sync_browse_lists: %s rejected the negprot\n",name));
    cli_shutdown(&cli);
    return;
  }

  if (!cli_session_setup(&cli, "", "", 1, "", 0, work->work_group))
  {
    DEBUG(0,("sync_browse_lists: %s rejected the browse sync sessionsetup\n", 
             name));
    cli_shutdown(&cli);
    return;
  }

  if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1))
  {
    DEBUG(0,("sync_browse_lists: %s refused browse sync IPC$ connect\n", name));
    cli_shutdown(&cli);
    return;
  }

  call_work = work;
  call_subrec = subrec;

  /* Fetch a workgroup list. */
  cli_NetServerEnum(&cli, work->work_group, 
                    local_type|SV_TYPE_DOMAIN_ENUM,
                    callback);

  /* Now fetch a server list. */
  cli_NetServerEnum(&cli, work->work_group, 
                    local?SV_TYPE_LOCAL_LIST_ONLY:SV_TYPE_ALL,
                    callback);

  cli_shutdown(&cli);
}

/****************************************************************************
As a domain master browser, do a sync with a local master browser.
**************************************************************************/

static void sync_with_lmb(struct browse_cache_record *browc)
{                     
  struct work_record *work;

  if (!(work = find_workgroup_on_subnet(unicast_subnet, browc->work_group))) {
      DEBUG(0, ("sync_with_lmb: failed to get a \
workgroup for a local master browser cache entry workgroup %s, server %s\n", 
                browc->work_group, browc->lmb_name));
      return;
  }

  /* We should only be doing this if we are a domain master browser for
     the given workgroup. Ensure this is so. */

  if(!AM_DOMAIN_MASTER_BROWSER(work))
  {
    DEBUG(0,("sync_with_lmb: We are trying to sync with a local master browser %s \
for workgroup %s and we are not a domain master browser on this workgroup. Error !\n",
        browc->lmb_name, browc->work_group));
    return;
  }

  DEBUG(2, ("sync_with_lmb: Initiating sync with local master browser %s<0x20> at IP %s for \
workgroup %s\n", browc->lmb_name, inet_ntoa(browc->ip), browc->work_group));

  sync_browse_lists(unicast_subnet, work, browc->lmb_name, 0x20, browc->ip, True);

  browc->sync_time += (CHECK_TIME_DMB_TO_LMB_SYNC * 60);
}

/****************************************************************************
Sync or expire any local master browsers.
**************************************************************************/

void dmb_expire_and_sync_browser_lists(time_t t)
{
  static time_t last_run = 0;
  struct browse_cache_record *browc;

  /* Only do this every 20 seconds. */  
  if (t - last_run < 20) 
   return;

  last_run = t;

  expire_lmb_browsers(t);

  for (browc = lmb_browserlist; browc; browc = browc->next)
  {
    if (browc->sync_time < t)
      sync_with_lmb(browc);
  }
}

/****************************************************************************
As a local master browser, send an announce packet to the domain master browser.
**************************************************************************/

static void announce_local_master_browser_to_domain_master_browser( struct work_record *work)
{
  pstring outbuf;
  char *p;

  if(ismyip(work->dmb_addr))
  {
    DEBUG(2,("announce_local_master_browser_to_domain_master_browser: We are both a domain \
and a local master browser for workgroup %s. \
Do not announce to ourselves.\n", work->work_group ));
    return;
  }

  bzero(outbuf,sizeof(outbuf));
  p = outbuf;
  CVAL(p,0) = ANN_MasterAnnouncement;
  p++;

  StrnCpy(p,myname,15);
  strupper(p);
  p = skip_string(p,1);

  DEBUG(4,("announce_local_master_browser_to_domain_master_browser: Sending local master announce \
to %s for workgroup %s.\n", namestr(&work->dmb_name), work->work_group ));

  send_mailslot(True, BROWSE_MAILSLOT, outbuf,PTR_DIFF(p,outbuf),
          myname, 0x0, work->dmb_name.name, 0x0, work->dmb_addr, FIRST_SUBNET->myip);

}

/****************************************************************************
As a local master browser, do a sync with a domain master browser.
**************************************************************************/

static void sync_with_dmb(struct work_record *work)
{
  DEBUG(2, ("sync_with_dmb: Initiating sync with domain master browser %s at IP %s for \
workgroup %s\n", namestr(&work->dmb_name), inet_ntoa(work->dmb_addr), work->work_group));

  sync_browse_lists(unicast_subnet, work, work->dmb_name.name, work->dmb_name.name_type, 
                    work->dmb_addr, False);
}

/****************************************************************************
  Function called when a node status query to a domain master browser IP succeeds.
****************************************************************************/

static void domain_master_node_status_success(struct subnet_record *subrec,
                                              struct userdata_struct *userdata,
                                              struct res_rec *answers,
                                              struct in_addr from_ip)
{
  struct work_record *work = find_workgroup_on_subnet( subrec, userdata->data);

  if(work == NULL)
  {
    DEBUG(0,("domain_master_node_status_success: Unable to find workgroup %s on subnet %s.\n",
              userdata->data, subrec->subnet_name));
    return;
  }

  DEBUG(3,("domain_master_node_status_success: Success in node status for workgroup %s from ip %s\n",
            work->work_group, inet_ntoa(from_ip) ));

  /* Go through the list of names found at answers->rdata and look for
     the first SERVER<0x20> name. */

  if(answers->rdata != NULL)
  {
    char *p = answers->rdata;
    int numnames = CVAL(p, 0);

    p += 1;

    while (numnames--)
    {
      char qname[17];
      uint16 nb_flags;
      int name_type;

      StrnCpy(qname,p,15);
      name_type = CVAL(p,15);
      nb_flags = get_nb_flags(&p[16]);
      trim_string(qname,NULL," ");

      p += 18;

      if(!(nb_flags & NB_GROUP) && (name_type == 0x20))
      {
        struct nmb_name nmbname;

        make_nmb_name(&nmbname, qname, name_type, scope);

        /* Copy the dmb name and IP address
           into the workgroup struct. */

        work->dmb_name = nmbname;
        putip((char *)&work->dmb_addr, &from_ip);

        /* Do the local master browser announcement to the domain
           master browser name and IP. */
        announce_local_master_browser_to_domain_master_browser( work );

        /* Now synchronise lists with the domain master browser. */
        sync_with_dmb(work);
        break;
      }
    }
  }
  else
    DEBUG(0,("domain_master_node_status_success: Failed to find a SERVER<0x20> \
name in reply from IP %s.\n", inet_ntoa(from_ip) ));
}

/****************************************************************************
  Function called when a node status query to a domain master browser IP fails.
****************************************************************************/

static void domain_master_node_status_fail(struct subnet_record *subrec,
                       struct response_record *rrec)
{
  struct userdata_struct *userdata = rrec->userdata;

  DEBUG(0,("domain_master_node_status_fail: Doing a node status request to \
the domain master browser for workgroup %s at IP %s failed. Cannot sync browser \
lists.\n", userdata->data, inet_ntoa(rrec->packet->ip) ));

}

/****************************************************************************
  Function called when a query for a WORKGROUP<1b> name succeeds.
****************************************************************************/

static void find_domain_master_name_query_success(struct subnet_record *subrec,
                        struct userdata_struct *userdata_in,
                        struct nmb_name *q_name, struct in_addr answer_ip, struct res_rec *rrec)
{
  /* 
   * Unfortunately, finding the IP address of the Domain Master Browser,
   * as we have here, is not enough. We need to now do a sync to the
   * SERVERNAME<0x20> NetBIOS name, as only recent NT servers will
   * respond to the SMBSERVER name. To get this name from IP
   * address we do a Node status request, and look for the first
   * NAME<0x20> in the response, and take that as the server name.
   * We also keep a cache of the Domain Master Browser name for this
   * workgroup in the Workgroup struct, so that if the same IP addess
   * is returned every time, we don't need to do the node status
   * request.
   */

  struct work_record *work;
  struct nmb_name nmbname;
  struct userdata_struct *userdata;

  if (!(work = find_workgroup_on_subnet(subrec, q_name->name))) {
      DEBUG(0, ("find_domain_master_name_query_success: failed to find \
workgroup %s\n", q_name->name ));
    return;
  }

  /* First check if we already have a dmb for this workgroup. */

  if(!ip_equal(work->dmb_addr, ipzero) && ip_equal(work->dmb_addr, answer_ip))
  {
    /* Do the local master browser announcement to the domain
       master browser name and IP. */
    announce_local_master_browser_to_domain_master_browser( work );

    /* Now synchronise lists with the domain master browser. */
    sync_with_dmb(work);
    return;
  }
  else
    putip((char *)&work->dmb_addr, &ipzero);

  /* Now initiate the node status request. */
  bzero((char *)&nmbname, sizeof(nmbname));
  nmbname.name[0] = '*';

  /* Put the workgroup name into the userdata so we know
     what workgroup we're talking to when the reply comes
     back. */

  /* Setup the userdata_struct - this is copied so we can use
     a stack variable for this. */
  if((userdata = (struct userdata_struct *)malloc(sizeof(struct userdata_struct) + sizeof(fstring)+1)) == NULL)
  {
    DEBUG(0, ("find_domain_master_name_query_success: malloc fail.\n"));
    return;
  }

  userdata->copy_fn = NULL;
  userdata->free_fn = NULL;
  userdata->userdata_len = strlen(work->work_group)+1;
  pstrcpy(userdata->data, work->work_group);

  node_status( subrec, &nmbname, answer_ip, 
               domain_master_node_status_success,
               domain_master_node_status_fail,
               userdata);

  free((char *)userdata);
}

/****************************************************************************
  Function called when a query for a WORKGROUP<1b> name fails.
  ****************************************************************************/
static void find_domain_master_name_query_fail(struct subnet_record *subrec,
                                    struct response_record *rrec,
                                    struct nmb_name *question_name, int fail_code)
{
  DEBUG(0,("find_domain_master_name_query_fail: Unable to find the Domain Master \
Browser name %s for the workgroup %s. Unable to sync browse lists in this workgroup.\n",
        namestr(question_name), question_name->name ));
}

/****************************************************************************
As a local master browser for a workgroup find the domain master browser
name, announce ourselves as local master browser to it and then pull the
full domain browse lists from it onto the given subnet.
**************************************************************************/

void announce_and_sync_with_domain_master_browser( struct subnet_record *subrec,
                                                   struct work_record *work)
{
  struct nmb_name nmbname;

  /* Only do this if we are using a WINS server. */
  if(we_are_a_wins_client() == False)
  {
    DEBUG(10,("announce_and_sync_with_domain_master_browser: Ignoring as we are not a WINS client.\n"));
    return;
  }

  make_nmb_name(&nmbname,work->work_group,0x1b,scope);

  /* First, query for the WORKGROUP<1b> name from the WINS server. */
  query_name(unicast_subnet, nmbname.name, nmbname.name_type,
             find_domain_master_name_query_success,
             find_domain_master_name_query_fail,
             NULL);

}

/****************************************************************************
  Function called when a node status query to a domain master browser IP succeeds.
  This function is only called on query to a Samba 1.9.18 or above WINS server.

  Note that adding the workgroup name is enough for this workgroup to be
  browsable by clients, as clients query the WINS server or broadcast 
  nets for the WORKGROUP<1b> name when they want to browse a workgroup
  they are not in. We do not need to do a sync with this Domain Master
  Browser in order for our browse clients to see machines in this workgroup.
  JRA.
****************************************************************************/

static void get_domain_master_name_node_status_success(struct subnet_record *subrec,
                                              struct userdata_struct *userdata,
                                              struct res_rec *answers,
                                              struct in_addr from_ip)
{
  struct work_record *work;

  DEBUG(3,("get_domain_master_name_node_status_success: Success in node status from ip %s\n",
            inet_ntoa(from_ip) ));

  /* 
   * Go through the list of names found at answers->rdata and look for
   * the first WORKGROUP<0x1b> name.
   */

  if(answers->rdata != NULL)
  {
    char *p = answers->rdata;
    int numnames = CVAL(p, 0);

    p += 1;

    while (numnames--)
    {
      char qname[17];
      uint16 nb_flags;
      int name_type;

      StrnCpy(qname,p,15);
      name_type = CVAL(p,15);
      nb_flags = get_nb_flags(&p[16]);
      trim_string(qname,NULL," ");

      p += 18;

      if(!(nb_flags & NB_GROUP) && (name_type == 0x1b))
      {

        DEBUG(5,("get_domain_master_name_node_status_success: IP %s is a domain \
master browser for workgroup %s. Adding this name.\n", inet_ntoa(from_ip), qname ));

        /* 
         * If we don't already know about this workgroup, add it
         * to the workgroup list on the unicast_subnet.
         */
        if((work = find_workgroup_on_subnet( subrec, qname)) == NULL)
	{
          /* 
           * Add it - with an hour in the cache.
           */
          if((work = create_workgroup_on_subnet(subrec, qname, 60*60))==NULL)
            return;
        }
        break;
      }
    }
  }
  else
    DEBUG(0,("get_domain_master_name_node_status_success: Failed to find a WORKGROUP<0x1b> \
name in reply from IP %s.\n", inet_ntoa(from_ip) ));
}

/****************************************************************************
  Function called when a node status query to a domain master browser IP fails.
****************************************************************************/

static void get_domain_master_name_node_status_fail(struct subnet_record *subrec,
                       struct response_record *rrec)
{
  DEBUG(0,("get_domain_master_name_node_status_fail: Doing a node status request to \
the domain master browser at IP %s failed. Cannot get workgroup name.\n", 
      inet_ntoa(rrec->packet->ip) ));

}
/****************************************************************************
  Function called when a query for *<1b> name succeeds.
****************************************************************************/

static void find_all_domain_master_names_query_success(struct subnet_record *subrec,
                        struct userdata_struct *userdata_in,
                        struct nmb_name *q_name, struct in_addr answer_ip, struct res_rec *rrec)
{
  /* 
   * We now have a list of all the domain master browsers for all workgroups
   * that have registered with the WINS server. Now do a node status request
   * to each one and look for the first 1b name in the reply. This will be
   * the workgroup name that we will add to the unicast subnet as a 'non-local'
   * workgroup.
   */

  struct nmb_name nmbname;
  struct in_addr send_ip;
  int i;

  DEBUG(5,("find_all_domain_master_names_query_succes: Got answer from WINS server of %d \
IP addresses for Domain Master Browsers.\n", rrec->rdlength / 6 ));

  for(i = 0; i < rrec->rdlength / 6; i++)
  {
    /* Initiate the node status requests. */
    bzero((char *)&nmbname, sizeof(nmbname));
    nmbname.name[0] = '*';

    putip((char *)&send_ip, (char *)&rrec->rdata[(i*6) + 2]);

    /* 
     * Don't send node status requests to ourself.
     */

    if(ismyip( send_ip ))
    {
      DEBUG(5,("find_all_domain_master_names_query_succes: Not sending node status \
to our own IP %s.\n", inet_ntoa(send_ip) ));
      continue;
    }

    DEBUG(5,("find_all_domain_master_names_query_succes: sending node status request to \
IP %s.\n", inet_ntoa(send_ip) ));

    node_status( subrec, &nmbname, send_ip, 
                 get_domain_master_name_node_status_success,
                 get_domain_master_name_node_status_fail,
                 NULL);
  }
}

/****************************************************************************
  Function called when a query for *<1b> name fails.
  ****************************************************************************/
static void find_all_domain_master_names_query_fail(struct subnet_record *subrec,
                                    struct response_record *rrec,
                                    struct nmb_name *question_name, int fail_code)
{
  DEBUG(10,("find_domain_master_name_query_fail: WINS server did not reply to a query \
for name %s. This means it is probably not a Samba 1.9.18 or above WINS server.\n",
        namestr(question_name) ));
}

/****************************************************************************
 If we are a domain master browser on the unicast subnet, do a query to the
 WINS server for the *<1b> name. This will only work to a Samba WINS server,
 so ignore it if we fail. If we succeed, contact each of the IP addresses in
 turn and do a node status request to them. If this succeeds then look for a
 <1b> name in the reply - this is the workgroup name. Add this to the unicast
 subnet. This is expensive, so we only do this every 15 minutes.
**************************************************************************/

void collect_all_workgroup_names_from_wins_server(time_t t)
{
  static time_t lastrun = 0;
  struct work_record *work;
  struct nmb_name nmbname;

  /* Only do this if we are using a WINS server. */
  if(we_are_a_wins_client() == False)
    return;

  /* Check to see if we are a domain master browser on the unicast subnet. */
  if((work = find_workgroup_on_subnet( unicast_subnet, myworkgroup)) == NULL)
  {
    DEBUG(0,("collect_all_workgroup_names_from_wins_server: Cannot find my workgroup %s on subnet %s.\n",
              myworkgroup, unicast_subnet->subnet_name ));
    return;
  }

  if(!AM_DOMAIN_MASTER_BROWSER(work))
    return;

  if ((lastrun != 0) && (t < lastrun + (15 * 60)))
    return;
     
  lastrun = t;

  make_nmb_name(&nmbname,"*",0x1b,scope);

  /* First, query for the *<1b> name from the WINS server. */
  query_name(unicast_subnet, nmbname.name, nmbname.name_type,
             find_all_domain_master_names_query_success,
             find_all_domain_master_names_query_fail,
             NULL);
} 
