
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*  this module apparently provides an implementation of DCE/RPC over a
 *  named pipe (IPC$ connection using SMBtrans).  details of DCE/RPC
 *  documentation are available (in on-line form) from the X-Open group.
 *
 *  this module should provide a level of abstraction between SMB
 *  and DCE/RPC, while minimising the amount of mallocs, unnecessary
 *  data copies, and network traffic.
 *
 *  in this version, which takes a "let's learn what's going on and
 *  get something running" approach, there is additional network
 *  traffic generated, but the code should be easier to understand...
 *
 *  ... if you read the docs.  or stare at packets for weeks on end.
 *
 */

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/* array lookup of well-known RID aliases.  the purpose of these escapes me.. */
/* XXXX this structure should not have the well-known RID groups added to it,
   i.e the DOMAIN_GROUP_RID_ADMIN/USER/GUEST.  */
rid_name domain_alias_rids[] = 
{
	{ DOMAIN_ALIAS_RID_ADMINS       , "admins" },
	{ DOMAIN_ALIAS_RID_USERS        , "users" },
	{ DOMAIN_ALIAS_RID_GUESTS       , "guests" },
	{ DOMAIN_ALIAS_RID_POWER_USERS  , "power_users" },

	{ DOMAIN_ALIAS_RID_ACCOUNT_OPS  , "account_ops" },
	{ DOMAIN_ALIAS_RID_SYSTEM_OPS   , "system_ops" },
	{ DOMAIN_ALIAS_RID_PRINT_OPS    , "print_ops" },
	{ DOMAIN_ALIAS_RID_BACKUP_OPS   , "backup_ops" },
	{ DOMAIN_ALIAS_RID_REPLICATOR   , "replicator" },
	{ 0                             , NULL }
};

/* array lookup of well-known Domain RID users. */
rid_name domain_user_rids[] = 
{
	{ DOMAIN_USER_RID_ADMIN         , "Administrator" },
	{ DOMAIN_USER_RID_GUEST         , "Guest" },
	{ 0                             , NULL }
};

/* array lookup of well-known Domain RID groups. */
rid_name domain_group_rids[] = 
{
	{ DOMAIN_GROUP_RID_ADMINS       , "domain admins" },
	{ DOMAIN_GROUP_RID_USERS        , "domain users" },
	{ DOMAIN_GROUP_RID_GUESTS       , "domain guests" },
	{ 0                             , NULL }
};


int make_dom_gids(char *gids_str, DOM_GID **ppgids)
{
  char *ptr;
  pstring s2;
  int count;
  DOM_GID *gids;

  *ppgids = NULL;

  DEBUG(4,("make_dom_gids: %s\n", gids_str));

  if (gids_str == NULL || *gids_str == 0)
    return 0;

  for (count = 0, ptr = gids_str; next_token(&ptr, s2, NULL); count++)
    ;

  gids = (DOM_GID *)malloc( sizeof(DOM_GID) * count );
  if(!gids)
  {
    DEBUG(0,("make_dom_gids: malloc fail !\n"));
    return 0;
  }

  for (count = 0, ptr = gids_str; next_token(&ptr, s2, NULL) && 
                       count < LSA_MAX_GROUPS; count++) 
  {
    /* the entries are of the form GID/ATTR, ATTR being optional.*/
    char *attr;
    uint32 rid = 0;
    int i;

    attr = strchr(s2,'/');
    if (attr)
      *attr++ = 0;

    if (!attr || !*attr)
      attr = "7"; /* default value for attribute is 7 */

    /* look up the RID string and see if we can turn it into a rid number */
    for (i = 0; domain_alias_rids[i].name != NULL; i++)
    {
      if (strequal(domain_alias_rids[i].name, s2))
      {
        rid = domain_alias_rids[i].rid;
        break;
      }
    }

    if (rid == 0)
      rid = atoi(s2);

    if (rid == 0)
    {
      DEBUG(1,("make_dom_gids: unknown well-known alias RID %s/%s\n", s2, attr));
      count--;
    }
    else
    {
      gids[count].g_rid = rid;
      gids[count].attr  = atoi(attr);

      DEBUG(5,("group id: %d attr: %d\n", gids[count].g_rid, gids[count].attr));
    }
  }

  *ppgids = gids;
  return count;
}

/*******************************************************************
 turns a DCE/RPC request into a DCE/RPC reply

 this is where the data really should be split up into an array of
 headers and data sections.

 ********************************************************************/
BOOL create_rpc_reply(pipes_struct *p,
				uint32 data_start, uint32 data_end)
{
	DEBUG(5,("create_rpc_reply: data_start: %d data_end: %d max_tsize: %d\n",
	          data_start, data_end, p->hdr_ba.bba.max_tsize));

	mem_buf_init(&(p->rhdr.data), 0);
	mem_alloc_data(p->rhdr.data, 0x18);

	p->rhdr.align = 4;
	p->rhdr.io = False;

	p->hdr_resp.alloc_hint = data_end - data_start; /* calculate remaining data to be sent */
	p->hdr.pkt_type = RPC_RESPONSE; /* mark header as an rpc response */

	/* set up rpc header (fragmentation issues) */
	if (data_start == 0)
	{
		p->hdr.flags = RPC_FLG_FIRST;
	}
	else
	{
		p->hdr.flags = 0;
	}

	if (p->hdr_resp.alloc_hint + 0x18 <= p->hdr_ba.bba.max_tsize)
	{
		p->hdr.flags |= RPC_FLG_LAST;
		p->hdr.frag_len = p->hdr_resp.alloc_hint + 0x18;
	}
	else
	{
		p->hdr.frag_len = p->hdr_ba.bba.max_tsize;
	}

	p->rhdr.data->offset.start = 0;
	p->rhdr.data->offset.end   = 0x18;

	/* store the header in the data stream */
	p->rhdr.offset = 0;
	smb_io_rpc_hdr   ("hdr", &(p->hdr   ), &(p->rhdr), 0);
	smb_io_rpc_hdr_resp("resp", &(p->hdr_resp), &(p->rhdr), 0);

	return p->rhdr.data != NULL && p->rhdr.offset == 0x18;
}


/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
static BOOL api_rpc_command(pipes_struct *p, 
				char *rpc_name, struct api_struct *api_rpc_cmds,
				prs_struct *data)
{
	int fn_num;
	DEBUG(4,("api_rpc_command: %s op 0x%x - ", rpc_name, p->hdr_req.opnum));

	for (fn_num = 0; api_rpc_cmds[fn_num].name; fn_num++)
	{
		if (api_rpc_cmds[fn_num].opnum == p->hdr_req.opnum && api_rpc_cmds[fn_num].fn != NULL)
		{
			DEBUG(3,("api_rpc_command: %s\n", api_rpc_cmds[fn_num].name));
			break;
		}
	}

	if (api_rpc_cmds[fn_num].name == NULL)
	{
		DEBUG(4, ("unknown\n"));
		return False;
	}

	/* start off with 1024 bytes, and a large safety margin too */
	mem_buf_init(&(p->rdata.data), SAFETY_MARGIN);
	mem_alloc_data(p->rdata.data, 1024);

	p->rdata.io = False;
	p->rdata.align = 4;

	p->rdata.data->offset.start = 0;
	p->rdata.data->offset.end   = 0xffffffff;

	/* do the actual command */
	p->rdata.offset = 0; 
	api_rpc_cmds[fn_num].fn(p->uid, data, &(p->rdata));

	if (p->rdata.data == NULL || p->rdata.offset == 0)
	{
		mem_free_data(p->rdata.data);
		return False;
	}

	mem_realloc_data(p->rdata.data, p->rdata.offset);

    DEBUG(10,("called %s\n", rpc_name));

	return True;
}


/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
BOOL api_rpcTNP(pipes_struct *p, char *rpc_name, struct api_struct *api_rpc_cmds,
				prs_struct *data)
{
	if (data == NULL || data->data == NULL)
	{
		DEBUG(2,("%s: NULL data received\n", rpc_name));
		return False;
	}

	/* read the rpc header */
	smb_io_rpc_hdr_req("req", &(p->hdr_req), data, 0);

	/* interpret the command */
	if (!api_rpc_command(p, rpc_name, api_rpc_cmds, data))
	{
		return False;
	}

	/* create the rpc header */
	if (!create_rpc_reply(p, 0, p->rdata.offset))
	{
		return False;
	}

	p->frag_len_left   = p->hdr.frag_len - p->file_offset;
	p->next_frag_start = p->hdr.frag_len; 
	
	/* set up the data chain */
	p->rhdr.data->offset.start = 0;
	p->rhdr.data->offset.end   = p->rhdr.offset;
	p->rhdr.data->next = p->rdata.data;

	p->rdata.data->offset.start = p->rhdr.data->offset.end;
	p->rdata.data->offset.end   = p->rhdr.data->offset.end + p->rdata.offset;
	p->rdata.data->next = NULL;

	return True;
}


/*******************************************************************
 gets a domain user's groups
 ********************************************************************/
void get_domain_user_groups(char *domain_groups, char *user)
{
	pstring tmp;

	if (domain_groups == NULL || user == NULL) return;

	/* any additional groups this user is in.  e.g power users */
	pstrcpy(domain_groups, lp_domain_groups());

	/* can only be a user or a guest.  cannot be guest _and_ admin */
	if (user_in_list(user, lp_domain_guest_group()))
	{
		slprintf(tmp, sizeof(tmp) - 1, " %ld/7 ", DOMAIN_GROUP_RID_GUESTS);
		pstrcat(domain_groups, tmp);

		DEBUG(3,("domain guest group access %s granted\n", tmp));
	}
	else
	{
		slprintf(tmp, sizeof(tmp) -1, " %ld/7 ", DOMAIN_GROUP_RID_USERS);
		pstrcat(domain_groups, tmp);

		DEBUG(3,("domain group access %s granted\n", tmp));

		if (user_in_list(user, lp_domain_admin_group()))
		{
			slprintf(tmp, sizeof(tmp) - 1, " %ld/7 ", DOMAIN_GROUP_RID_ADMINS);
			pstrcat(domain_groups, tmp);

			DEBUG(3,("domain admin group access %s granted\n", tmp));
		}
	}
}


/*******************************************************************
 lookup_group_name
 ********************************************************************/
uint32 lookup_group_name(uint32 rid, char *group_name, uint32 *type)
{
	int i = 0; 
	(*type) = SID_NAME_DOM_GRP;

	DEBUG(5,("lookup_group_name: rid: %d", rid));

	while (domain_group_rids[i].rid != rid && domain_group_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_group_rids[i].rid != 0)
	{
		fstrcpy(group_name, domain_group_rids[i].name);
		DEBUG(5,(" = %s\n", group_name));
		return 0x0;
	}

	DEBUG(5,(" none mapped\n"));
	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_alias_name
 ********************************************************************/
uint32 lookup_alias_name(uint32 rid, char *alias_name, uint32 *type)
{
	int i = 0; 
	(*type) = SID_NAME_WKN_GRP;

	DEBUG(5,("lookup_alias_name: rid: %d", rid));

	while (domain_alias_rids[i].rid != rid && domain_alias_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_alias_rids[i].rid != 0)
	{
		fstrcpy(alias_name, domain_alias_rids[i].name);
		DEBUG(5,(" = %s\n", alias_name));
		return 0x0;
	}

	DEBUG(5,(" none mapped\n"));
	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_user_name
 ********************************************************************/
uint32 lookup_user_name(uint32 rid, char *user_name, uint32 *type)
{
	struct sam_disp_info *disp_info;
	int i = 0;
	(*type) = SID_NAME_USER;

	DEBUG(5,("lookup_user_name: rid: %d", rid));

	/* look up the well-known domain user rids first */
	while (domain_user_rids[i].rid != rid && domain_user_rids[i].rid != 0)
	{
		i++;
	}

	if (domain_user_rids[i].rid != 0)
	{
		fstrcpy(user_name, domain_user_rids[i].name);
		DEBUG(5,(" = %s\n", user_name));
		return 0x0;
	}

	/* ok, it's a user.  find the user account */
	become_root(True);
	disp_info = getsamdisprid(rid);
	unbecome_root(True);

	if (disp_info != NULL)
	{
		fstrcpy(user_name, disp_info->smb_name);
		DEBUG(5,(" = %s\n", user_name));
		return 0x0;
	}

	DEBUG(5,(" none mapped\n"));
	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_group_rid
 ********************************************************************/
uint32 lookup_group_rid(char *group_name, uint32 *rid)
{
	char *grp_name;
	int i = -1; /* start do loop at -1 */

	do /* find, if it exists, a group rid for the group name*/
	{
		i++;
		(*rid) = domain_group_rids[i].rid;
		grp_name = domain_group_rids[i].name;

	} while (grp_name != NULL && !strequal(grp_name, group_name));

	return (grp_name != NULL) ? 0 : 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_alias_rid
 ********************************************************************/
uint32 lookup_alias_rid(char *alias_name, uint32 *rid)
{
	char *als_name;
	int i = -1; /* start do loop at -1 */

	do /* find, if it exists, a alias rid for the alias name*/
	{
		i++;
		(*rid) = domain_alias_rids[i].rid;
		als_name = domain_alias_rids[i].name;

	} while (als_name != NULL && !strequal(als_name, alias_name));

	return (als_name != NULL) ? 0 : 0xC0000000 | NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_user_rid
 ********************************************************************/
uint32 lookup_user_rid(char *user_name, uint32 *rid)
{
	struct smb_passwd *smb_pass;
	(*rid) = 0;

	/* find the user account */
	become_root(True);
	smb_pass = getsmbpwnam(user_name);
	unbecome_root(True);

	if (smb_pass != NULL)
	{
		/* lkclXXXX SHOULD use name_to_rid() here! */
		(*rid) = smb_pass->smb_userid;
		return 0x0;
	}

	return 0xC0000000 | NT_STATUS_NONE_MAPPED;
}
