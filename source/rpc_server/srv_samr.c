/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Marc Jacobsen			    1999,
 *  Copyright (C) Jean François Micouleau      1998-2001,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002-2003.
 *
 * 	Split into interface and implementation modules by,
 *
 *  Copyright (C) Jeremy Allison                    2001.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is the interface to the SAMR code.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*******************************************************************
 ********************************************************************/

static bool proxy_samr_call(pipes_struct *p, uint8 opnum)
{
	struct api_struct *fns;
	int n_fns;

	samr_get_pipe_fns(&fns, &n_fns);

	if (opnum >= n_fns) {
		return false;
	}

	if (fns[opnum].opnum != opnum) {
		smb_panic("SAMR function table not sorted");
	}

	return fns[opnum].fn(p);
}

/*******************************************************************
 api_samr_close_hnd
 ********************************************************************/

static bool api_samr_close_hnd(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CLOSE);
}

/*******************************************************************
 api_samr_open_domain
 ********************************************************************/

static bool api_samr_open_domain(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_OPENDOMAIN);
}

/*******************************************************************
 api_samr_get_usrdom_pwinfo
 ********************************************************************/

static bool api_samr_get_usrdom_pwinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_GETUSERPWINFO);
}

/*******************************************************************
 api_samr_set_sec_obj
 ********************************************************************/

static bool api_samr_set_sec_obj(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_SETSECURITY);
}

/*******************************************************************
 api_samr_query_sec_obj
 ********************************************************************/

static bool api_samr_query_sec_obj(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYSECURITY);
}

/*******************************************************************
 api_samr_enum_dom_users
 ********************************************************************/

static bool api_samr_enum_dom_users(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_ENUMDOMAINUSERS);
}

/*******************************************************************
 api_samr_enum_dom_groups
 ********************************************************************/

static bool api_samr_enum_dom_groups(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_ENUMDOMAINGROUPS);
}

/*******************************************************************
 api_samr_enum_dom_aliases
 ********************************************************************/

static bool api_samr_enum_dom_aliases(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_ENUMDOMAINALIASES);
}

/*******************************************************************
 api_samr_query_dispinfo
 ********************************************************************/

static bool api_samr_query_dispinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYDISPLAYINFO);
}

/*******************************************************************
 api_samr_query_aliasinfo
 ********************************************************************/

static bool api_samr_query_aliasinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYALIASINFO);
}

/*******************************************************************
 api_samr_lookup_names
 ********************************************************************/

static bool api_samr_lookup_names(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_LOOKUPNAMES);
}

/*******************************************************************
 api_samr_chgpasswd_user
 ********************************************************************/

static bool api_samr_chgpasswd_user(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CHANGEPASSWORDUSER2);
}

/*******************************************************************
 api_samr_lookup_rids
 ********************************************************************/

static bool api_samr_lookup_rids(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_LOOKUPRIDS);
}

/*******************************************************************
 api_samr_open_user
 ********************************************************************/

static bool api_samr_open_user(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_OPENUSER);
}

/*******************************************************************
 api_samr_query_userinfo
 ********************************************************************/

static bool api_samr_query_userinfo(pipes_struct *p)
{
	SAMR_Q_QUERY_USERINFO q_u;
	SAMR_R_QUERY_USERINFO r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!samr_io_q_query_userinfo("", &q_u, data, 0)){
		DEBUG(0,("api_samr_query_userinfo: unable to unmarshall SAMR_Q_QUERY_USERINFO.\n"));
		return False;
	}

	r_u.status = _samr_query_userinfo(p, &q_u, &r_u);

	/* store the response in the SMB stream */
	if(!samr_io_r_query_userinfo("", &r_u, rdata, 0)) {
		DEBUG(0,("api_samr_query_userinfo: unable to marshall SAMR_R_QUERY_USERINFO.\n"));
		return False;
	}

	return True;
}

/*******************************************************************
 api_samr_query_usergroups
 ********************************************************************/

static bool api_samr_query_usergroups(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_GETGROUPSFORUSER);
}

/*******************************************************************
 api_samr_query_domain_info
 ********************************************************************/

static bool api_samr_query_domain_info(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYDOMAININFO);
}

/*******************************************************************
 api_samr_create_user
 ********************************************************************/

static bool api_samr_create_user(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CREATEUSER2);
}

/*******************************************************************
 api_samr_connect_anon
 ********************************************************************/

static bool api_samr_connect_anon(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CONNECT);
}

/*******************************************************************
 api_samr_connect
 ********************************************************************/

static bool api_samr_connect(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CONNECT2);
}

/*******************************************************************
 api_samr_connect4
 ********************************************************************/

static bool api_samr_connect4(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CONNECT4);
}

/*******************************************************************
 api_samr_chgpasswd_user3
 ********************************************************************/

static bool api_samr_chgpasswd_user3(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CHANGEPASSWORDUSER3);
}

/*******************************************************************
 api_samr_connect5
 ********************************************************************/

static bool api_samr_connect5(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CONNECT5);
}

/**********************************************************************
 api_samr_lookup_domain
 **********************************************************************/

static bool api_samr_lookup_domain(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_LOOKUPDOMAIN);
}

/**********************************************************************
 api_samr_enum_domains
 **********************************************************************/

static bool api_samr_enum_domains(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_ENUMDOMAINS);
}

/*******************************************************************
 api_samr_open_alias
 ********************************************************************/

static bool api_samr_open_alias(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_OPENALIAS);
}

/*******************************************************************
 api_samr_set_userinfo
 ********************************************************************/

static bool api_samr_set_userinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_SETUSERINFO);
}

/*******************************************************************
 api_samr_set_userinfo2
 ********************************************************************/

static bool api_samr_set_userinfo2(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_SETUSERINFO2);
}

/*******************************************************************
 api_samr_query_useraliases
 ********************************************************************/

static bool api_samr_query_useraliases(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_GETALIASMEMBERSHIP);
}

/*******************************************************************
 api_samr_query_aliasmem
 ********************************************************************/

static bool api_samr_query_aliasmem(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_GETMEMBERSINALIAS);
}

/*******************************************************************
 api_samr_query_groupmem
 ********************************************************************/

static bool api_samr_query_groupmem(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYGROUPMEMBER);
}

/*******************************************************************
 api_samr_add_aliasmem
 ********************************************************************/

static bool api_samr_add_aliasmem(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_ADDALIASMEMBER);
}

/*******************************************************************
 api_samr_del_aliasmem
 ********************************************************************/

static bool api_samr_del_aliasmem(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_DELETEALIASMEMBER);
}

/*******************************************************************
 api_samr_add_groupmem
 ********************************************************************/

static bool api_samr_add_groupmem(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_ADDGROUPMEMBER);
}

/*******************************************************************
 api_samr_del_groupmem
 ********************************************************************/

static bool api_samr_del_groupmem(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_DELETEGROUPMEMBER);
}

/*******************************************************************
 api_samr_delete_dom_user
 ********************************************************************/

static bool api_samr_delete_dom_user(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_DELETEUSER);
}

/*******************************************************************
 api_samr_delete_dom_group
 ********************************************************************/

static bool api_samr_delete_dom_group(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_DELETEDOMAINGROUP);
}

/*******************************************************************
 api_samr_delete_dom_alias
 ********************************************************************/

static bool api_samr_delete_dom_alias(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_DELETEDOMALIAS);
}

/*******************************************************************
 api_samr_create_dom_group
 ********************************************************************/

static bool api_samr_create_dom_group(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CREATEDOMAINGROUP);
}

/*******************************************************************
 api_samr_create_dom_alias
 ********************************************************************/

static bool api_samr_create_dom_alias(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_CREATEDOMALIAS);
}

/*******************************************************************
 api_samr_query_groupinfo
 ********************************************************************/

static bool api_samr_query_groupinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYGROUPINFO);
}

/*******************************************************************
 api_samr_set_groupinfo
 ********************************************************************/

static bool api_samr_set_groupinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_SETGROUPINFO);
}

/*******************************************************************
 api_samr_set_aliasinfo
 ********************************************************************/

static bool api_samr_set_aliasinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_SETALIASINFO);
}

/*******************************************************************
 api_samr_get_dom_pwinfo
 ********************************************************************/

static bool api_samr_get_dom_pwinfo(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_GETDOMPWINFO);
}

/*******************************************************************
 api_samr_open_group
 ********************************************************************/

static bool api_samr_open_group(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_OPENGROUP);
}

/*******************************************************************
 api_samr_remove_sid_foreign_domain
 ********************************************************************/

static bool api_samr_remove_sid_foreign_domain(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_REMOVEMEMBERFROMFOREIGNDOMAIN);
}

/*******************************************************************
 api_samr_query_dom_info2
 ********************************************************************/

static bool api_samr_query_domain_info2(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_QUERYDOMAININFO2);
}

/*******************************************************************
 api_samr_set_dom_info
 ********************************************************************/

static bool api_samr_set_dom_info(pipes_struct *p)
{
	return proxy_samr_call(p, NDR_SAMR_SETDOMAININFO);
}

/*******************************************************************
 array of \PIPE\samr operations
 ********************************************************************/

static struct api_struct api_samr_cmds [] =
{
      {"SAMR_CLOSE_HND"         , SAMR_CLOSE_HND        , api_samr_close_hnd        },
      {"SAMR_CONNECT"           , SAMR_CONNECT          , api_samr_connect          },
      {"SAMR_CONNECT_ANON"      , SAMR_CONNECT_ANON     , api_samr_connect_anon     },
      {"SAMR_ENUM_DOMAINS"      , SAMR_ENUM_DOMAINS     , api_samr_enum_domains     },
      {"SAMR_ENUM_DOM_USERS"    , SAMR_ENUM_DOM_USERS   , api_samr_enum_dom_users   },

      {"SAMR_ENUM_DOM_GROUPS"   , SAMR_ENUM_DOM_GROUPS  , api_samr_enum_dom_groups  },
      {"SAMR_ENUM_DOM_ALIASES"  , SAMR_ENUM_DOM_ALIASES , api_samr_enum_dom_aliases },
      {"SAMR_QUERY_USERALIASES" , SAMR_QUERY_USERALIASES, api_samr_query_useraliases},
      {"SAMR_QUERY_ALIASMEM"    , SAMR_QUERY_ALIASMEM   , api_samr_query_aliasmem   },
      {"SAMR_QUERY_GROUPMEM"    , SAMR_QUERY_GROUPMEM   , api_samr_query_groupmem   },
      {"SAMR_ADD_ALIASMEM"      , SAMR_ADD_ALIASMEM     , api_samr_add_aliasmem     },
      {"SAMR_DEL_ALIASMEM"      , SAMR_DEL_ALIASMEM     , api_samr_del_aliasmem     },
      {"SAMR_ADD_GROUPMEM"      , SAMR_ADD_GROUPMEM     , api_samr_add_groupmem     },
      {"SAMR_DEL_GROUPMEM"      , SAMR_DEL_GROUPMEM     , api_samr_del_groupmem     },

      {"SAMR_DELETE_DOM_USER"   , SAMR_DELETE_DOM_USER  , api_samr_delete_dom_user  },
      {"SAMR_DELETE_DOM_GROUP"  , SAMR_DELETE_DOM_GROUP , api_samr_delete_dom_group },
      {"SAMR_DELETE_DOM_ALIAS"  , SAMR_DELETE_DOM_ALIAS , api_samr_delete_dom_alias },
      {"SAMR_CREATE_DOM_GROUP"  , SAMR_CREATE_DOM_GROUP , api_samr_create_dom_group },
      {"SAMR_CREATE_DOM_ALIAS"  , SAMR_CREATE_DOM_ALIAS , api_samr_create_dom_alias },
      {"SAMR_LOOKUP_NAMES"      , SAMR_LOOKUP_NAMES     , api_samr_lookup_names     },
      {"SAMR_OPEN_USER"         , SAMR_OPEN_USER        , api_samr_open_user        },
      {"SAMR_QUERY_USERINFO"    , SAMR_QUERY_USERINFO   , api_samr_query_userinfo   },
      {"SAMR_SET_USERINFO"      , SAMR_SET_USERINFO     , api_samr_set_userinfo     },
      {"SAMR_SET_USERINFO2"     , SAMR_SET_USERINFO2    , api_samr_set_userinfo2    },

      {"SAMR_QUERY_DOMAIN_INFO" , SAMR_QUERY_DOMAIN_INFO, api_samr_query_domain_info},
      {"SAMR_QUERY_USERGROUPS"  , SAMR_QUERY_USERGROUPS , api_samr_query_usergroups },
      {"SAMR_QUERY_DISPINFO"    , SAMR_QUERY_DISPINFO   , api_samr_query_dispinfo   },
      {"SAMR_QUERY_DISPINFO3"   , SAMR_QUERY_DISPINFO3  , api_samr_query_dispinfo   },
      {"SAMR_QUERY_DISPINFO4"   , SAMR_QUERY_DISPINFO4  , api_samr_query_dispinfo   },

      {"SAMR_QUERY_ALIASINFO"   , SAMR_QUERY_ALIASINFO  , api_samr_query_aliasinfo  },
      {"SAMR_QUERY_GROUPINFO"   , SAMR_QUERY_GROUPINFO  , api_samr_query_groupinfo  },
      {"SAMR_SET_GROUPINFO"     , SAMR_SET_GROUPINFO    , api_samr_set_groupinfo    },
      {"SAMR_SET_ALIASINFO"     , SAMR_SET_ALIASINFO    , api_samr_set_aliasinfo    },
      {"SAMR_CREATE_USER"       , SAMR_CREATE_USER      , api_samr_create_user      },
      {"SAMR_LOOKUP_RIDS"       , SAMR_LOOKUP_RIDS      , api_samr_lookup_rids      },
      {"SAMR_GET_DOM_PWINFO"    , SAMR_GET_DOM_PWINFO   , api_samr_get_dom_pwinfo   },
      {"SAMR_CHGPASSWD_USER"    , SAMR_CHGPASSWD_USER   , api_samr_chgpasswd_user   },
      {"SAMR_OPEN_ALIAS"        , SAMR_OPEN_ALIAS       , api_samr_open_alias       },
      {"SAMR_OPEN_GROUP"        , SAMR_OPEN_GROUP       , api_samr_open_group       },
      {"SAMR_OPEN_DOMAIN"       , SAMR_OPEN_DOMAIN      , api_samr_open_domain      },
      {"SAMR_REMOVE_SID_FOREIGN_DOMAIN"       , SAMR_REMOVE_SID_FOREIGN_DOMAIN      , api_samr_remove_sid_foreign_domain      },
      {"SAMR_LOOKUP_DOMAIN"     , SAMR_LOOKUP_DOMAIN    , api_samr_lookup_domain    },

      {"SAMR_QUERY_SEC_OBJECT"  , SAMR_QUERY_SEC_OBJECT , api_samr_query_sec_obj    },
      {"SAMR_SET_SEC_OBJECT"    , SAMR_SET_SEC_OBJECT   , api_samr_set_sec_obj      },
      {"SAMR_GET_USRDOM_PWINFO" , SAMR_GET_USRDOM_PWINFO, api_samr_get_usrdom_pwinfo},
      {"SAMR_QUERY_DOMAIN_INFO2", SAMR_QUERY_DOMAIN_INFO2, api_samr_query_domain_info2},
      {"SAMR_SET_DOMAIN_INFO"   , SAMR_SET_DOMAIN_INFO  , api_samr_set_dom_info     },
      {"SAMR_CONNECT4"          , SAMR_CONNECT4         , api_samr_connect4         },
      {"SAMR_CHGPASSWD_USER3"   , SAMR_CHGPASSWD_USER3  , api_samr_chgpasswd_user3  },
      {"SAMR_CONNECT5"          , SAMR_CONNECT5         , api_samr_connect5         }
};

void samr2_get_pipe_fns( struct api_struct **fns, int *n_fns )
{
	*fns = api_samr_cmds;
	*n_fns = sizeof(api_samr_cmds) / sizeof(struct api_struct);
}


NTSTATUS rpc_samr2_init(void)
{
  return rpc_pipe_register_commands(SMB_RPC_INTERFACE_VERSION, "samr", "lsass", api_samr_cmds,
				    sizeof(api_samr_cmds) / sizeof(struct api_struct));
}
