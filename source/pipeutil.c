
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB utility routines
   Copyright (C) Andrew Tridgell 1992-1997,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997.
   Copyright (C) Paul Ashton  1997.
   
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "trans2.h"

extern int DEBUGLEVEL;

/* this function is due to be replaced */
void initrpcreply(char *inbuf, char *q)
{
	uint32 callid;

	SCVAL(q, 0, 5); q++; /* RPC version 5 */
	SCVAL(q, 0, 0); q++; /* minor version 0 */
	SCVAL(q, 0, 2); q++; /* RPC response packet */
	SCVAL(q, 0, 3); q++; /* first frag + last frag */
	RSIVAL(q, 0, 0x10000000); q += 4; /* packed data representation */
	RSSVAL(q, 0, 0); q += 2; /* fragment length, fill in later */
	SSVAL(q, 0, 0); q += 2; /* authentication length */
	callid = RIVAL(inbuf, 12);
	RSIVAL(q, 0, callid); q += 4; /* call identifier - match incoming RPC */
	SIVAL(q, 0, 0x18); q += 4; /* allocation hint (no idea) */
	SSVAL(q, 0, 0); q += 2; /* presentation context identifier */
	SCVAL(q, 0, 0); q++; /* cancel count */
	SCVAL(q, 0, 0); q++; /* reserved */
}

/* this function is due to be replaced */
void endrpcreply(char *inbuf, char *q, int datalen, int rtnval, int *rlen)
{
	SSVAL(q, 8, datalen + 4);
	SIVAL(q,0x10,datalen+4-0x18); /* allocation hint */
	SIVAL(q, datalen, rtnval);
	*rlen = datalen + 4;
	{ int fd; fd = open("/tmp/rpc", O_RDWR); write(fd, q, datalen + 4); }
}

/* Group and User RID username mapping function */
BOOL name_to_rid(char *user_name, uint32 *u_rid, uint32 *g_rid)
{
    struct passwd *pw = Get_Pwnam(user_name, False);

	if (u_rid == NULL || g_rid == NULL || user_name == NULL)
	{
		return False;
	}

    if (!pw)
	{
      DEBUG(1,("Username %s is invalid on this system\n", user_name));
      return False;
    }

	if (user_in_list(user_name, lp_domain_guest_users()))
	{
		*u_rid = DOMAIN_USER_RID_GUEST;
	}
	else if (user_in_list(user_name, lp_domain_admin_users()))
	{
		*u_rid = DOMAIN_USER_RID_ADMIN;
	}
	else
	{
		/* turn the unix UID into a Domain RID.  this is what the posix
		   sub-system does (adds 1000 to the uid) */
		*u_rid = (uint32)(pw->pw_uid + 1000);
	}

	/* absolutely no idea what to do about the unix GID to Domain RID mapping */
	*g_rid = (uint32)(pw->pw_gid + 1000);

	return True;
}


/* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
char *dom_sid_to_string(DOM_SID *sid)
{
  static pstring sidstr;
  char subauth[16];
  int i;
  uint32 ia = (sid->id_auth[5]) +
              (sid->id_auth[4] << 8 ) +
              (sid->id_auth[3] << 16) +
              (sid->id_auth[2] << 24);

  sprintf(sidstr, "S-%d-%d", sid->sid_rev_num, ia);

  for (i = 0; i < sid->num_auths; i++)
  {
    sprintf(subauth, "-%d", sid->sub_auths[i]);
    strcat(sidstr, subauth);
  }

  DEBUG(5,("dom_sid_to_string returning %s\n", sidstr));
  return sidstr;
}

int make_dom_sids(char *sids_str, DOM_SID *sids, int max_sids)
{
	char *ptr;
	pstring s2;
	int count;

	DEBUG(4,("make_dom_sids: %s\n", sids_str));

	if (sids_str == NULL || *sids_str == 0) return 0;

	for (count = 0, ptr = sids_str; next_token(&ptr, s2, NULL) && count < max_sids; count++) 
	{
		make_dom_sid(&sids[count], s2);
	}

	return count;
}

/* array lookup of well-known RID aliases.  the purpose of these escapes me.. */
/* XXXX this structure should not have the well-known RID groups added to it,
   i.e the DOMAIN_GROUP_RID_ADMIN/USER/GUEST.  */
static struct
{
	uint32 rid;
	char   *rid_name;

} rid_lookups[] = 
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

int make_dom_gids(char *gids_str, DOM_GID *gids)
{
	char *ptr;
	pstring s2;
	int count;

	DEBUG(4,("make_dom_gids: %s\n", gids_str));

	if (gids_str == NULL || *gids_str == 0) return 0;

	for (count = 0, ptr = gids_str; next_token(&ptr, s2, NULL) && count < LSA_MAX_GROUPS; count++) 
	{
		/* the entries are of the form GID/ATTR, ATTR being optional.*/
		char *attr;
		uint32 rid = 0;
		int i;

		attr = strchr(s2,'/');
		if (attr) *attr++ = 0;
		if (!attr || !*attr) attr = "7"; /* default value for attribute is 7 */

		/* look up the RID string and see if we can turn it into a rid number */
		for (i = 0; rid_lookups[i].rid_name != NULL; i++)
		{
			if (strequal(rid_lookups[i].rid_name, s2))
			{
				rid = rid_lookups[i].rid;
				break;
			}
		}

		if (rid == 0) rid = atoi(s2);

		if (rid == 0)
		{
			DEBUG(1,("make_dom_gids: unknown well-known alias RID %s/%s\n",
			          s2, attr));
			count--;
		}
		else
		{
			gids[count].g_rid = rid;
			gids[count].attr  = atoi(attr);

			DEBUG(5,("group id: %d attr: %d\n",
			          gids[count].g_rid,
			          gids[count].attr));
		}
	}

	return count;
}

int create_rpc_request(uint32 call_id, uint8 op_num, char *q, int data_len)
{
	RPC_HDR_RR hdr;

	make_rpc_hdr_rr(&hdr, RPC_REQUEST, call_id, data_len, op_num);
	return smb_io_rpc_hdr_rr(False, &hdr, q, q, 4, 0) - q;
}

int create_rpc_reply(uint32 call_id, char *q, int data_len)
{
	RPC_HDR_RR hdr;

	make_rpc_hdr_rr(&hdr, RPC_RESPONSE, call_id, data_len, 0);
	return smb_io_rpc_hdr_rr(False, &hdr, q, q, 4, 0) - q;
}

