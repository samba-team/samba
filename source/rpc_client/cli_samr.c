/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Elrond                            2000
   
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
#include "rpc_parse.h"
#include "rpc_client.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
do a SAMR change user password command
****************************************************************************/
BOOL samr_chgpasswd_user( struct cli_connection *con, 
		const char *srv_name, const char *user_name,
		const char nt_newpass[516], const uchar nt_oldhash[16],
		const char lm_newpass[516], const uchar lm_oldhash[16])
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CHGPASSWD_USER q_e;
	BOOL valid_pwc = False;

	/* create and send a MSRPC command with api SAMR_CHGPASSWD_USER */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Change User Password. server:%s username:%s\n",
	        srv_name, user_name));

	make_samr_q_chgpasswd_user(&q_e, srv_name, user_name,
	                           nt_newpass, nt_oldhash,
	                           lm_newpass, lm_oldhash);

	/* turn parameters into data stream */
	if (samr_io_q_chgpasswd_user("", &q_e, &data, 0) &&
	    rpc_con_pipe_req(con, SAMR_CHGPASSWD_USER, &data, &rdata))
	{
		SAMR_R_CHGPASSWD_USER r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		samr_io_r_chgpasswd_user("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_CHGPASSWD_USER: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			valid_pwc = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pwc;
}


/****************************************************************************
do a SAMR unknown 0x38 command
****************************************************************************/
BOOL samr_get_dom_pwinfo(struct cli_connection *con, const char *srv_name)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_GET_DOM_PWINFO q_e;
	BOOL valid_un8 = False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_USERS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Query Domain Password Info server:%s\n", srv_name));

	make_samr_q_get_dom_pwinfo(&q_e, srv_name);

	/* turn parameters into data stream */
	if (samr_io_q_get_dom_pwinfo("", &q_e, &data, 0) &&
	    rpc_con_pipe_req(con, SAMR_GET_DOM_PWINFO, &data, &rdata))
	{
		SAMR_R_GET_DOM_PWINFO r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		samr_io_r_get_dom_pwinfo("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
#if 0
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_GET_DOM_PWINFO: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}
#endif
		if (p)
		{
			valid_un8 = True;
		}
	}
	else
	{
		DEBUG(4,("samr_unknown38: rpc_con_pipe_req failed\n"));
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_un8;
}

/****************************************************************************
do a SAMR unknown 0x8 command
****************************************************************************/
BOOL samr_query_dom_info(  POLICY_HND *domain_pol, uint16 switch_value,
				SAM_UNK_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_DOMAIN_INFO q_e;
	BOOL valid_un8 = False;

	DEBUG(4,("SAMR Unknown 8 switch:%d\n", switch_value));

	if (domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_USERS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_dom_info(&q_e, domain_pol, switch_value);

	/* turn parameters into data stream */
	if (samr_io_q_query_dom_info("", &q_e, &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_QUERY_DOMAIN_INFO, &data, &rdata))
	{
		SAMR_R_QUERY_DOMAIN_INFO r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		r_e.ctr = ctr;
		samr_io_r_query_dom_info("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_DOMAIN_INFO: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			valid_un8 = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_un8;
}

/****************************************************************************
do a SAMR enumerate Domains
****************************************************************************/
uint32 samr_enum_domains(  POLICY_HND *pol,
				uint32 *start_idx, uint32 size,
				struct acct_info **sam,
				uint32 *num_sam_domains)
{
	uint32 status = 0x0;
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOMAINS q_e;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_domains == NULL || sam == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER | 0xC0000000;
	}

	/* create and send a MSRPC command with api SAMR_ENUM_DOMAINS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_enum_domains(&q_e, pol, *start_idx, size);

	/* turn parameters into data stream */
	if (samr_io_q_enum_domains("", &q_e, &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_ENUM_DOMAINS, &data, &rdata))
	{
		SAMR_R_ENUM_DOMAINS r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		samr_io_r_enum_domains("", &r_e, &rdata, 0);

		status = r_e.status;
		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_ENUM_DOMAINS: %s\n", get_nt_error_msg(r_e.status)));
			p = (r_e.status == STATUS_MORE_ENTRIES);
		}

		if (p)
		{
			uint32 i = (*num_sam_domains);
			uint32 j = 0;
			uint32 name_idx = 0;

			(*num_sam_domains) += r_e.num_entries2;
			(*sam) = (struct acct_info*) Realloc((*sam),
			       sizeof(struct acct_info) * (*num_sam_domains));
				    
			if ((*sam) == NULL)
			{
				(*num_sam_domains) = 0;
				i = 0;
			}

			for (j = 0; i < (*num_sam_domains) && j < r_e.num_entries2; j++, i++)
			{
				(*sam)[i].rid = r_e.sam[j].rid;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[j].hdr_name.buffer)
				{
					unistr2_to_ascii((*sam)[i].acct_name, &r_e.uni_dom_name[name_idx], sizeof((*sam)[i].acct_name)-1);
					name_idx++;
				}
				DEBUG(5,("samr_enum_domains: idx: %4d rid: %8x acct: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name));
			}
			(*start_idx) = r_e.next_idx;
		}
		else if (status == 0x0)
		{
			status = NT_STATUS_INVALID_PARAMETER | 0xC0000000;
		}

		if (r_e.sam != NULL)
		{
			free(r_e.sam);
		}
		if (r_e.uni_dom_name != NULL)
		{
			free(r_e.uni_dom_name);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return status;
}

/****************************************************************************
do a SAMR enumerate groups
****************************************************************************/
uint32 samr_enum_dom_groups(  POLICY_HND *pol,
				uint32 *start_idx, uint32 size,
				struct acct_info **sam,
				uint32 *num_sam_groups)
{
	uint32 status = 0x0;
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOM_GROUPS q_e;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_groups == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER | 0xC0000000;
	}

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_GROUPS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_enum_dom_groups(&q_e, pol, *start_idx, size);

	/* turn parameters into data stream */
	if (samr_io_q_enum_dom_groups("", &q_e, &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_ENUM_DOM_GROUPS, &data, &rdata))
	{
		SAMR_R_ENUM_DOM_GROUPS r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		samr_io_r_enum_dom_groups("", &r_e, &rdata, 0);

		status = r_e.status;
		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_ENUM_DOM_GROUPS: %s\n", get_nt_error_msg(r_e.status)));
			p = (r_e.status == STATUS_MORE_ENTRIES);
		}

		if (p)
		{
			uint32 i = (*num_sam_groups);
			uint32 j = 0;
			uint32 name_idx = 0;

			(*num_sam_groups) += r_e.num_entries2;
			(*sam) = (struct acct_info*) Realloc((*sam),
			       sizeof(struct acct_info) * (*num_sam_groups));
				    
			if ((*sam) == NULL)
			{
				(*num_sam_groups) = 0;
				i = 0;
			}

			for (j = 0; i < (*num_sam_groups) && j < r_e.num_entries2; j++, i++)
			{
				(*sam)[i].rid = r_e.sam[j].rid;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[j].hdr_name.buffer)
				{
					unistr2_to_ascii((*sam)[i].acct_name, &r_e.uni_grp_name[name_idx], sizeof((*sam)[i].acct_name)-1);
					name_idx++;
				}
				DEBUG(5,("samr_enum_dom_groups: idx: %4d rid: %8x acct: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name));
			}
			(*start_idx) = r_e.next_idx;
		}
		else if (status == 0x0)
		{
			status = NT_STATUS_INVALID_PARAMETER | 0xC0000000;
		}

		if (r_e.sam != NULL)
		{
			free(r_e.sam);
		}
		if (r_e.uni_grp_name != NULL)
		{
			free(r_e.uni_grp_name);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return status;
}

/****************************************************************************
do a SAMR enumerate aliases
****************************************************************************/
uint32 samr_enum_dom_aliases(  POLICY_HND *pol,
				uint32 *start_idx, uint32 size,
				struct acct_info **sam,
				uint32 *num_sam_aliases)
{
	uint32 status = 0x0;
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOM_ALIASES q_e;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_aliases == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER | 0xC0000000;
	}

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_ALIASES */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_enum_dom_aliases(&q_e, pol, *start_idx, size);

	/* turn parameters into data stream */
	if (samr_io_q_enum_dom_aliases("", &q_e, &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_ENUM_DOM_ALIASES, &data, &rdata))
	{
		SAMR_R_ENUM_DOM_ALIASES r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		samr_io_r_enum_dom_aliases("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_ENUM_DOM_ALIASES: %s\n", get_nt_error_msg(r_e.status)));
			p = (r_e.status == STATUS_MORE_ENTRIES);
		}

		if (p)
		{
			uint32 i = (*num_sam_aliases);
			uint32 j = 0;
			uint32 name_idx = 0;

			(*num_sam_aliases) += r_e.num_entries2;
			(*sam) = (struct acct_info*) Realloc((*sam),
			       sizeof(struct acct_info) * (*num_sam_aliases));
				    
			if ((*sam) == NULL)
			{
				(*num_sam_aliases) = 0;
				i = 0;
			}

			for (j = 0; i < (*num_sam_aliases) && j < r_e.num_entries2; j++, i++)
			{
				(*sam)[i].rid = r_e.sam[j].rid;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[j].hdr_name.buffer)
				{
					unistr2_to_ascii((*sam)[i].acct_name, &r_e.uni_grp_name[name_idx], sizeof((*sam)[i].acct_name)-1);
					name_idx++;
				}
				DEBUG(5,("samr_enum_dom_aliases: idx: %4d rid: %8x acct: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name));
			}
			(*start_idx) = r_e.next_idx;
		}
		else if (status == 0x0)
		{
			status = NT_STATUS_INVALID_PARAMETER | 0xC0000000;
		}

		if (r_e.sam != NULL)
		{
			free(r_e.sam);
		}
		if (r_e.uni_grp_name != NULL)
		{
			free(r_e.uni_grp_name);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return status;
}

/****************************************************************************
do a SAMR enumerate users
****************************************************************************/
uint32 samr_enum_dom_users(  POLICY_HND *pol, uint32 *start_idx, 
				uint16 acb_mask, uint16 unk_1, uint32 size,
				struct acct_info **sam,
				uint32 *num_sam_users)
{
	uint32 status = 0x0;
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOM_USERS q_e;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_users == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER | 0xC0000000;
	}

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_USERS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_enum_dom_users(&q_e, pol, *start_idx,
	                           acb_mask, unk_1, size);

	/* turn parameters into data stream */
	if (samr_io_q_enum_dom_users("", &q_e, &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_ENUM_DOM_USERS, &data, &rdata))
	{
		SAMR_R_ENUM_DOM_USERS r_e;
		BOOL p;

		ZERO_STRUCT(r_e);

		samr_io_r_enum_dom_users("", &r_e, &rdata, 0);

		status = r_e.status;
		p = rdata.offset != 0;

		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_ENUM_DOM_USERS: %s\n", get_nt_error_msg(r_e.status)));
			p = (r_e.status == STATUS_MORE_ENTRIES);
		}

		if (p)
		{
			uint32 i = (*num_sam_users);
			uint32 j = 0;
			uint32 name_idx = 0;

			(*num_sam_users) += r_e.num_entries2;
			if ((*num_sam_users) != 0)
			{
				(*sam) = g_renew(struct acct_info, (*sam),
			                 (*num_sam_users));
			}
				    
			if ((*sam) == NULL)
			{
				(*num_sam_users) = 0;
				i = 0;
			}

			for (j = 0; i < (*num_sam_users) && j < r_e.num_entries2; j++, i++)
			{
				(*sam)[i].rid = r_e.sam[j].rid;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[j].hdr_name.buffer)
				{
					unistr2_to_ascii((*sam)[i].acct_name, &r_e.uni_acct_name[name_idx], sizeof((*sam)[i].acct_name)-1);
					name_idx++;
				}
				DEBUG(5,("samr_enum_dom_users: idx: %4d rid: %8x acct: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name));
			}
			(*start_idx) = r_e.next_idx;
		}
		else if (status == 0x0)
		{
			status = NT_STATUS_INVALID_PARAMETER | 0xC0000000;
		}

		safe_free(r_e.sam);
		safe_free(r_e.uni_acct_name);
	}
	else
	{
		status = NT_STATUS_ACCESS_DENIED | 0xC0000000;
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return status;
}

/****************************************************************************
do a SAMR Connect
****************************************************************************/
BOOL samr_connect(  const char *srv_name, uint32 access_mask,
				POLICY_HND *connect_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CONNECT q_o;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_SAMR, &con))
	{
		return False;
	}

	DEBUG(4,("SAMR Open Policy server:%s access_mask:%x\n",
				srv_name, access_mask));

	if (srv_name == NULL || connect_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CONNECT */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_connect(&q_o, srv_name, access_mask);

	/* turn parameters into data stream */
	if (samr_io_q_connect("", &q_o,  &data, 0) &&
	    rpc_con_pipe_req(con, SAMR_CONNECT, &data, &rdata))
	{
		SAMR_R_CONNECT r_o;
		BOOL p;

		samr_io_r_connect("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_CONNECT: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*connect_pol = r_o.connect_pol;
			valid_pol = register_policy_hnd(get_global_hnd_cache(),
			                                cli_con_sec_ctx(con),
			                                connect_pol,
			                                access_mask) &&
			            set_policy_con(get_global_hnd_cache(),
			                                 connect_pol, con,
			                                 cli_connection_unlink);
			if (valid_pol)
			{
				policy_hnd_set_name(get_global_hnd_cache(),
						    connect_pol,
						    "SAM_CONNECT");
			}
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Query Security Object
****************************************************************************/
BOOL samr_query_sec_obj(  const POLICY_HND *pol,
				uint32 type,
				SEC_DESC_BUF *buf)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_SEC_OBJ q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Query Sec Object: type %x\n", type));

	if (pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_SEC_OBJ */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_sec_obj(&q_o, pol, type);

	/* turn parameters into data stream */
	if (samr_io_q_query_sec_obj("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_QUERY_SEC_OBJECT, &data, &rdata))
	{
		SAMR_R_QUERY_SEC_OBJ r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		samr_io_r_query_sec_obj("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_SEC_OBJ: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
			buf->sec = r_o.buf.sec;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open User
****************************************************************************/
BOOL samr_open_user(  const POLICY_HND *pol,
				uint32 unk_0, uint32 rid, 
				POLICY_HND *user_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_USER q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open User.  unk_0: %08x RID:%x\n",
	          unk_0, rid));

	if (pol == NULL || user_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_USER */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_open_user(&q_o, pol, unk_0, rid);

	/* turn parameters into data stream */
	if (samr_io_q_open_user("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_OPEN_USER, &data, &rdata))
	{
		SAMR_R_OPEN_USER r_o;
		BOOL p;

		samr_io_r_open_user("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_OPEN_USER: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*user_pol = r_o.user_pol;
			valid_pol = cli_pol_link(user_pol, pol);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open Alias
****************************************************************************/
BOOL samr_open_alias(  const POLICY_HND *domain_pol,
				uint32 flags, uint32 rid,
				POLICY_HND *alias_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_ALIAS q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open Alias. RID:%x\n", rid));

	if (alias_pol == NULL || domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_ALIAS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_open_alias(&q_o, domain_pol, flags, rid);

	/* turn parameters into data stream */
	if (samr_io_q_open_alias("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_OPEN_ALIAS, &data, &rdata))
	{
		SAMR_R_OPEN_ALIAS r_o;
		BOOL p;

		samr_io_r_open_alias("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_OPEN_ALIAS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*alias_pol = r_o.pol;
			valid_pol = cli_pol_link(alias_pol, domain_pol);

			if (valid_pol)
			{
				policy_hnd_set_name(get_global_hnd_cache(),
						    alias_pol,
						    "SAM_ALIAS");
			}
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Delete Alias Member
****************************************************************************/
BOOL samr_del_aliasmem(  POLICY_HND *alias_pol, DOM_SID *sid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_DEL_ALIASMEM q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || sid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_DEL_ALIASMEM */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Delete Alias Member.\n"));

	/* store the parameters */
	make_samr_q_del_aliasmem(&q_o, alias_pol, sid);

	/* turn parameters into data stream */
	if (samr_io_q_del_aliasmem("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(alias_pol, SAMR_DEL_ALIASMEM, &data, &rdata))
	{
		SAMR_R_DEL_ALIASMEM r_o;
		BOOL p;

		samr_io_r_del_aliasmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_DEL_ALIASMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Add Alias Member
****************************************************************************/
BOOL samr_add_aliasmem(  POLICY_HND *alias_pol, DOM_SID *sid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ADD_ALIASMEM q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || sid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ADD_ALIASMEM */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Add Alias Member.\n"));

	/* store the parameters */
	make_samr_q_add_aliasmem(&q_o, alias_pol, sid);

	/* turn parameters into data stream */
	if (samr_io_q_add_aliasmem("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(alias_pol, SAMR_ADD_ALIASMEM, &data, &rdata))
	{
		SAMR_R_ADD_ALIASMEM r_o;
		BOOL p;

		samr_io_r_add_aliasmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_ADD_ALIASMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Delete Domain Alias
****************************************************************************/
BOOL samr_delete_dom_alias(  POLICY_HND *alias_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_DELETE_DOM_ALIAS q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL) return False;

	/* delete and send a MSRPC command with api SAMR_DELETE_DOM_ALIAS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Delete Domain Alias.\n"));

	/* store the parameters */
	make_samr_q_delete_dom_alias(&q_o, alias_pol);

	/* turn parameters into data stream */
	if (samr_io_q_delete_dom_alias("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(alias_pol, SAMR_DELETE_DOM_ALIAS, &data, &rdata))
	{
		SAMR_R_DELETE_DOM_ALIAS r_o;
		BOOL p;

		samr_io_r_delete_dom_alias("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_DELETE_DOM_ALIAS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Create Domain User
****************************************************************************/
uint32 samr_create_dom_user(  POLICY_HND *domain_pol, const char *acct_name,
				uint32 unk_0, uint32 unk_1,
				POLICY_HND *user_pol, uint32 *rid)
{
	prs_struct data;
	prs_struct rdata;
	uint32 status = NT_STATUS_INVALID_PARAMETER | 0xC0000000;

	SAMR_Q_CREATE_USER q_o;

	if (user_pol == NULL || domain_pol == NULL || acct_name == NULL || rid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CREATE_USER */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Create Domain User. Name:%s\n", acct_name));

	/* store the parameters */
	make_samr_q_create_user(&q_o, domain_pol, acct_name, unk_0, unk_1);

	/* turn parameters into data stream */
	if (samr_io_q_create_user("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_CREATE_USER, &data, &rdata))
	{
		SAMR_R_CREATE_USER r_o;
		BOOL p;

		samr_io_r_create_user("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		status = r_o.status;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_CREATE_USER: %s\n", get_nt_error_msg(r_o.status)));
			p = r_o.status != NT_STATUS_USER_EXISTS;
		}

		if (p)
		{
			*user_pol = r_o.user_pol;
			*rid = r_o.user_rid;
			if (!cli_pol_link(user_pol, domain_pol))
			{
				status = NT_STATUS_INVALID_HANDLE | 0xC0000000;
			}
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return status;
}

/****************************************************************************
do a SAMR Create Domain Alias
****************************************************************************/
BOOL samr_create_dom_alias(  POLICY_HND *domain_pol, const char *acct_name,
				POLICY_HND *alias_pol, uint32 *rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CREATE_DOM_ALIAS q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || domain_pol == NULL || acct_name == NULL || rid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CREATE_DOM_ALIAS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Create Domain Alias. Name:%s\n", acct_name));

	/* store the parameters */
	make_samr_q_create_dom_alias(&q_o, domain_pol, acct_name);

	/* turn parameters into data stream */
	if (samr_io_q_create_dom_alias("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_CREATE_DOM_ALIAS, &data, &rdata))
	{
		SAMR_R_CREATE_DOM_ALIAS r_o;
		BOOL p;

		samr_io_r_create_dom_alias("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_CREATE_DOM_ALIAS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*alias_pol = r_o.alias_pol;
			*rid = r_o.rid;
			valid_pol = cli_pol_link(alias_pol, domain_pol);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Get Alias Info
****************************************************************************/
BOOL samr_query_aliasinfo(  POLICY_HND *alias_pol, uint16 switch_value,
				ALIAS_INFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_ALIASINFO q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || ctr == NULL) return False;

	/* create and send a MSRPC command with api SAMR_GET_ALIASINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Get Alias Info\n"));

	/* store the parameters */
	make_samr_q_query_aliasinfo(&q_o, alias_pol, switch_value);

	/* turn parameters into data stream */
	if (samr_io_q_query_aliasinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(alias_pol, SAMR_QUERY_ALIASINFO, &data, &rdata))
	{
		SAMR_R_QUERY_ALIASINFO r_o;
		BOOL p;

		/* get alias info */
		r_o.ctr = ctr;

		samr_io_r_query_aliasinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_ALIASINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Set Alias Info
****************************************************************************/
BOOL samr_set_aliasinfo(  POLICY_HND *alias_pol, ALIAS_INFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_SET_ALIASINFO q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || ctr == NULL) return False;

	/* create and send a MSRPC command with api SAMR_SET_ALIASINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Set Alias Info\n"));

	/* store the parameters */
	make_samr_q_set_aliasinfo(&q_o, alias_pol, ctr);

	/* turn parameters into data stream */
	if (samr_io_q_set_aliasinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(alias_pol, SAMR_SET_ALIASINFO, &data, &rdata))
	{
		SAMR_R_SET_ALIASINFO r_o;
		BOOL p;

		samr_io_r_set_aliasinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_SET_ALIASINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open Group
****************************************************************************/
BOOL samr_open_group(  const POLICY_HND *domain_pol,
				uint32 flags, uint32 rid,
				POLICY_HND *group_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_GROUP q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open Group. RID:%x\n", rid));

	if (group_pol == NULL || domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_GROUP */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_open_group(&q_o, domain_pol, flags, rid);

	/* turn parameters into data stream */
	if (samr_io_q_open_group("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_OPEN_GROUP, &data, &rdata))
	{
		SAMR_R_OPEN_GROUP r_o;
		BOOL p;

		samr_io_r_open_group("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_OPEN_GROUP: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*group_pol = r_o.pol;
			valid_pol = cli_pol_link(group_pol, domain_pol);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Delete Group Member
****************************************************************************/
BOOL samr_del_groupmem(  POLICY_HND *group_pol, uint32 rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_DEL_GROUPMEM q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_DEL_GROUPMEM */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Delete Group Member.\n"));

	/* store the parameters */
	make_samr_q_del_groupmem(&q_o, group_pol, rid);

	/* turn parameters into data stream */
	if (samr_io_q_del_groupmem("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(group_pol, SAMR_DEL_GROUPMEM, &data, &rdata))
	{
		SAMR_R_DEL_GROUPMEM r_o;
		BOOL p;

		samr_io_r_del_groupmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_DEL_GROUPMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Add Group Member
****************************************************************************/
BOOL samr_add_groupmem(  POLICY_HND *group_pol, uint32 rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ADD_GROUPMEM q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ADD_GROUPMEM */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Add Group Member.\n"));

	/* store the parameters */
	make_samr_q_add_groupmem(&q_o, group_pol, rid);

	/* turn parameters into data stream */
	if (samr_io_q_add_groupmem("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(group_pol, SAMR_ADD_GROUPMEM, &data, &rdata))
	{
		SAMR_R_ADD_GROUPMEM r_o;
		BOOL p;

		samr_io_r_add_groupmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_ADD_GROUPMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Delete Domain User
****************************************************************************/
BOOL samr_delete_dom_user(  POLICY_HND *user_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_DELETE_DOM_USER q_o;
	BOOL valid_pol = False;

	if (user_pol == NULL) return False;

	/* delete and send a MSRPC command with api SAMR_DELETE_DOM_USER */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Delete Domain User.\n"));

	/* store the parameters */
	make_samr_q_delete_dom_user(&q_o, user_pol);

	/* turn parameters into data stream */
	if (samr_io_q_delete_dom_user("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(user_pol, SAMR_DELETE_DOM_USER, &data, &rdata))
	{
		SAMR_R_DELETE_DOM_USER r_o;
		BOOL p;

		samr_io_r_delete_dom_user("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_DELETE_DOM_USER: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Delete Domain Group
****************************************************************************/
BOOL samr_delete_dom_group(  POLICY_HND *group_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_DELETE_DOM_GROUP q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL) return False;

	/* delete and send a MSRPC command with api SAMR_DELETE_DOM_GROUP */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Delete Domain Group.\n"));

	/* store the parameters */
	make_samr_q_delete_dom_group(&q_o, group_pol);

	/* turn parameters into data stream */
	if (samr_io_q_delete_dom_group("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(group_pol, SAMR_DELETE_DOM_GROUP, &data, &rdata))
	{
		SAMR_R_DELETE_DOM_GROUP r_o;
		BOOL p;

		samr_io_r_delete_dom_group("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_DELETE_DOM_GROUP: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Create Domain Group
****************************************************************************/
BOOL samr_create_dom_group(  POLICY_HND *domain_pol, const char *acct_name,
				uint32 access_mask,
				POLICY_HND *group_pol, uint32 *rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CREATE_DOM_GROUP q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL || domain_pol == NULL || acct_name == NULL || rid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CREATE_DOM_GROUP */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Create Domain Group. Name:%s\n", acct_name));

	/* store the parameters */
	make_samr_q_create_dom_group(&q_o, domain_pol, acct_name, access_mask);

	/* turn parameters into data stream */
	if (samr_io_q_create_dom_group("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_CREATE_DOM_GROUP, &data, &rdata))
	{
		SAMR_R_CREATE_DOM_GROUP r_o;
		BOOL p;

		samr_io_r_create_dom_group("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_CREATE_DOM_GROUP: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*group_pol = r_o.pol;
			*rid = r_o.rid;
			valid_pol = cli_pol_link(group_pol, domain_pol);
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Set Group Info
****************************************************************************/
BOOL samr_set_groupinfo(  POLICY_HND *group_pol, GROUP_INFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_SET_GROUPINFO q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL || ctr == NULL) return False;

	/* create and send a MSRPC command with api SAMR_SET_GROUPINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Set Group Info\n"));

	/* store the parameters */
	make_samr_q_set_groupinfo(&q_o, group_pol, ctr);

	/* turn parameters into data stream */
	if (samr_io_q_set_groupinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(group_pol, SAMR_SET_GROUPINFO, &data, &rdata))
	{
		SAMR_R_SET_GROUPINFO r_o;
		BOOL p;

		samr_io_r_set_groupinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_SET_GROUPINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Unknown 2d
****************************************************************************/
BOOL samr_unknown_2d(  const POLICY_HND *domain_pol,
				const DOM_SID *sid)
{
	pstring sid_str;
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_UNKNOWN_2D q_o;
	BOOL valid_pol = False;

	if (DEBUGLEVEL >= 4)
	{
		sid_to_string(sid_str, sid);
		DEBUG(4,("SAMR Unknown 0x2d.  SID:%s\n", sid_str));
	}

	if (sid == NULL || domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_UNKNOWN_2D */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_unknown_2d(&q_o, domain_pol, sid);

	/* turn parameters into data stream */
	if (samr_io_q_unknown_2d("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(domain_pol, SAMR_UNKNOWN_2D, &data, &rdata))
	{
		SAMR_R_UNKNOWN_2D r_o;
		BOOL p;

		samr_io_r_unknown_2d("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_UNKNOWN_2D: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_pol;
}

BOOL samr_open_domain(  const POLICY_HND *connect_pol,
			  uint32 ace_perms,
			  const DOM_SID *sid,
			  POLICY_HND *domain_pol)
{
	return isamr_open_domain(connect_pol, ace_perms, sid, domain_pol) ==
		NT_STATUS_NOPROBLEMO;
}

/****************************************************************************
do a SAMR Open Domain
****************************************************************************/
uint32 isamr_open_domain(  const POLICY_HND *connect_pol,
			  uint32 ace_perms,
			  const DOM_SID *sid,
			  POLICY_HND *domain_pol)
{
	pstring sid_str;
	prs_struct data;
	prs_struct rdata;
	SAMR_R_OPEN_DOMAIN r_o;
	SAMR_Q_OPEN_DOMAIN q_o;

	r_o.status = NT_STATUS_UNSUCCESSFUL;

	if (DEBUGLEVEL >= 4)
	{
		sid_to_string(sid_str, sid);
		DEBUG(4,("SAMR Open Domain.  SID:%s Permissions:%x\n",
					sid_str, ace_perms));
	}

	if (connect_pol == NULL || sid == NULL || domain_pol == NULL) 
		return NT_STATUS_INVALID_PARAMETER;

	/* create and send a MSRPC command with api SAMR_OPEN_DOMAIN */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_open_domain(&q_o, connect_pol, ace_perms, sid);

	/* turn parameters into data stream */
	if (samr_io_q_open_domain("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(connect_pol, SAMR_OPEN_DOMAIN, &data, &rdata))
	{
		BOOL p;

		samr_io_r_open_domain("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_OPEN_DOMAIN: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			*domain_pol = r_o.domain_pol;
			if (!cli_pol_link(domain_pol, connect_pol)) {
				r_o.status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			}
			policy_hnd_set_name(get_global_hnd_cache(),
					    domain_pol, "SAM_DOMAIN");
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return r_o.status;
}

/****************************************************************************
do a SAMR Query Lookup Domain
****************************************************************************/
BOOL samr_query_lookup_domain(  POLICY_HND *pol, const char *dom_name,
			      DOM_SID *dom_sid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_LOOKUP_DOMAIN q_o;
	BOOL valid_query = False;

	if (pol == NULL || dom_name == NULL || dom_sid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_LOOKUP_DOMAIN */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Query Lookup Domain.\n"));

	/* store the parameters */
	make_samr_q_lookup_domain(&q_o, pol, dom_name);

	/* turn parameters into data stream */
	if (samr_io_q_lookup_domain("", &q_o, &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_LOOKUP_DOMAIN, &data, &rdata))
	{
		SAMR_R_LOOKUP_DOMAIN r_o;
		BOOL p;

		samr_io_r_lookup_domain("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_LOOKUP_DOMAIN: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr_sid != 0)
		{
			sid_copy(dom_sid, &r_o.dom_sid.sid);
			valid_query = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Lookup Names
****************************************************************************/
BOOL samr_query_lookup_names(const POLICY_HND *pol, uint32 flags,
			     uint32 num_names, char **names,
			     uint32 *num_rids, uint32 **rids, uint32 **types)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_LOOKUP_NAMES q_o;
	BOOL valid_query = False;

	if (pol == NULL || flags == 0 || num_names == 0 || names == NULL ||
	    num_rids == NULL || rids == NULL || types == NULL ) return False;

	*num_rids = 0;
	*types = NULL;
	*rids  = NULL;

	/* create and send a MSRPC command with api SAMR_LOOKUP_NAMES */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Query Lookup NAMES.\n"));

	/* store the parameters */
	make_samr_q_lookup_names(&q_o, pol, flags, num_names, names);

	/* turn parameters into data stream */
	if (samr_io_q_lookup_names("", &q_o, &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_LOOKUP_NAMES, &data, &rdata))
	{
		SAMR_R_LOOKUP_NAMES r_o;
		BOOL p;

		ZERO_STRUCT(r_o);
		samr_io_r_lookup_names("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_LOOKUP_NAMES: %s\n", get_nt_error_msg(r_o.status)));
			p = r_o.status == 0x107;
		}

		if (p)
		{
			if (r_o.ptr_rids != 0 && r_o.ptr_types != 0 &&
			    r_o.num_types1 == r_o.num_rids1)
			{
				uint32 i;

				valid_query = True;
				*num_rids = r_o.num_rids1;
				*types = g_new(uint32, *num_rids);
				*rids  = g_new(uint32, *num_rids);

				for (i = 0; i < r_o.num_rids1; i++)
				{
					(*rids)[i] = r_o.rids[i];
				}
				for (i = 0; i < r_o.num_types1; i++)
				{
					(*types)[i] = r_o.types[i];
				}
			}
			else if (r_o.ptr_rids == 0 && r_o.ptr_types == 0)
			{
				valid_query = True;
				*num_rids = 0;
			}
			else
			{
				p = False;
			}
		}

		samr_free_r_lookup_names(&r_o);
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Lookup RIDS
****************************************************************************/
BOOL samr_query_lookup_rids(  const POLICY_HND *pol, uint32 flags,
				uint32 num_rids, const uint32 *rids,
				uint32 *num_names,
				char   ***names,
				uint32 **type)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_LOOKUP_RIDS q_o;
	BOOL valid_query = False;

	if (pol == NULL || flags == 0 || num_rids == 0 || rids == NULL ||
	    num_names == NULL || names == NULL || type == NULL ) return False;

	/* create and send a MSRPC command with api SAMR_LOOKUP_RIDS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	DEBUG(4,("SAMR Query Lookup RIDs.\n"));

	/* store the parameters */
	make_samr_q_lookup_rids(&q_o, pol, flags, num_rids, rids);

	/* turn parameters into data stream */
	if (samr_io_q_lookup_rids("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_LOOKUP_RIDS, &data, &rdata))
	{
		SAMR_R_LOOKUP_RIDS r_o;
		BOOL p;
		ZERO_STRUCT(r_o);

		samr_io_r_lookup_rids("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_LOOKUP_RIDS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			if (r_o.ptr_names != 0 && r_o.ptr_types != 0 &&
			    r_o.num_types1 == r_o.num_names1)
			{
				uint32 i;
				valid_query = True;

				(*num_names) = 0;
				(*names) = NULL;

				for (i = 0; i < r_o.num_names1; i++)
				{
					fstring tmp;
					unistr2_to_ascii(tmp, &r_o.uni_name[i], sizeof(tmp)-1);
					add_chars_to_array(num_names, names, tmp);
				}

				if ((*num_names) != 0)
				{
					(*type) = (uint32*)malloc((*num_names) * sizeof(**type));
				}

				for (i = 0; (*type) != NULL && i < r_o.num_types1; i++)
				{
					(*type)[i] = r_o.type[i];
				}
			}
			else if (r_o.ptr_names == 0 && r_o.ptr_types == 0)
			{
				valid_query = True;
				*num_names = 0;
				*names = NULL;
				*type = NULL;
			}
			else
			{
				p = False;
			}
		}

		samr_free_r_lookup_rids(&r_o);
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Alias Members
****************************************************************************/
BOOL samr_query_aliasmem(  const POLICY_HND *alias_pol, 
				uint32 *num_mem, DOM_SID2 *sid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_ALIASMEM q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Alias Members.\n"));

	if (alias_pol == NULL || sid == NULL || num_mem == NULL) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_ALIASMEM */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_aliasmem(&q_o, alias_pol);

	/* turn parameters into data stream */
	if (samr_io_q_query_aliasmem("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(alias_pol, SAMR_QUERY_ALIASMEM, &data, &rdata))
	{
		SAMR_R_QUERY_ALIASMEM r_o;
		BOOL p;

		/* get user info */
		r_o.sid = sid;

		samr_io_r_query_aliasmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_ALIASMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_query = True;
			*num_mem = r_o.num_sids;
		}

	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query User Aliases
****************************************************************************/
BOOL samr_query_useraliases(  const POLICY_HND *pol,
				uint32 *ptr_sid, DOM_SID2 *sid,
				uint32 *num_aliases, uint32 **rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_USERALIASES q_o;
	BOOL valid_query = False;
	ZERO_STRUCT(q_o);

	DEBUG(4,("SAMR Query User Aliases.\n"));

	if (pol == NULL || sid == NULL || rid == NULL || num_aliases == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_USERALIASES */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_useraliases(&q_o, pol, 1, ptr_sid, sid);

	/* turn parameters into data stream */
	if (samr_io_q_query_useraliases("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_QUERY_USERALIASES, &data, &rdata))
	{
		SAMR_R_QUERY_USERALIASES r_o;
		BOOL p;

		r_o.rid = NULL;

		samr_io_r_query_useraliases("", &r_o, &rdata, 0);
		*rid = r_o.rid;
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_USERALIASES: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_query = True;
			*num_aliases = r_o.num_entries;
		}

	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Group Members
****************************************************************************/
BOOL samr_query_groupmem(  POLICY_HND *group_pol, 
				uint32 *num_mem, uint32 **rid, uint32 **attr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_GROUPMEM q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Group Members.\n"));

	if (group_pol == NULL || rid == NULL || attr == NULL || num_mem == NULL) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_GROUPMEM */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_groupmem(&q_o, group_pol);

	/* turn parameters into data stream */
	if (samr_io_q_query_groupmem("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(group_pol, SAMR_QUERY_GROUPMEM, &data, &rdata))
	{
		SAMR_R_QUERY_GROUPMEM r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		samr_io_r_query_groupmem("", &r_o, &rdata, 0);
		*rid  = r_o.rid ;
		*attr = r_o.attr;
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_GROUPMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && 
		    ((r_o.ptr_rids != 0 && r_o.ptr_attrs != 0) ||
		     (r_o.ptr_rids == 0 && r_o.ptr_attrs == 0)) &&
		      r_o.num_rids == r_o.num_attrs)
		{
			valid_query = True;
			*num_mem = r_o.num_rids;
		}

	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query User Groups
****************************************************************************/
BOOL samr_query_usergroups(  POLICY_HND *pol, uint32 *num_groups,
				DOM_GID **gid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_USERGROUPS q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query User Groups.\n"));

	if (pol == NULL || gid == NULL || num_groups == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_USERGROUPS */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_usergroups(&q_o, pol);

	/* turn parameters into data stream */
	if (samr_io_q_query_usergroups("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_QUERY_USERGROUPS, &data, &rdata))
	{
		SAMR_R_QUERY_USERGROUPS r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		/* get user info */
		r_o.gid = NULL;

		samr_io_r_query_usergroups("", &r_o, &rdata, 0);
		*gid = r_o.gid;
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_USERGROUPS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr_0 != 0)
		{
			valid_query = True;
			*num_groups = r_o.num_entries;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Group Info
****************************************************************************/
BOOL samr_query_groupinfo(  POLICY_HND *pol,
				uint16 switch_value, GROUP_INFO_CTR* ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_GROUPINFO q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Group Info.  level: %d\n", switch_value));

	if (pol == NULL || ctr == NULL || switch_value == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_GROUPINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_groupinfo(&q_o, pol, switch_value);

	/* turn parameters into data stream */
	if (samr_io_q_query_groupinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_QUERY_GROUPINFO, &data, &rdata))
	{
		SAMR_R_QUERY_GROUPINFO r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		/* get group info */
		r_o.ctr = ctr;

		samr_io_r_query_groupinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_GROUPINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ctr->switch_value1 != switch_value)
		{
			DEBUG(4,("SAMR_R_QUERY_GROUPINFO: received incorrect level %d\n",
			          r_o.ctr->switch_value1));
		}

		if (p && r_o.ptr != 0)
		{
			valid_query = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Set User Info
****************************************************************************/
BOOL samr_set_userinfo2(  POLICY_HND *pol, uint16 switch_value,
				void* usr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_SET_USERINFO2 q_o;
	SAM_USERINFO_CTR ctr;
	BOOL valid_query = False;

	ctr.info.id = usr;

	DEBUG(4,("SAMR Set User Info 2.  level: %d\n", switch_value));

	if (pol == NULL || usr == NULL || switch_value == 0) return False;

	/* create and send a MSRPC command with api SAMR_SET_USERINFO2 */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_set_userinfo2(&q_o, pol, switch_value, &ctr);

	/* turn parameters into data stream */
	if (samr_io_q_set_userinfo2("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_SET_USERINFO2, &data, &rdata))
	{
		SAMR_R_SET_USERINFO2 r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		samr_io_r_set_userinfo2("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_USERINFO2: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_query = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Set User Info
****************************************************************************/
BOOL samr_set_userinfo(  POLICY_HND *pol, uint16 switch_value, void* usr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_SET_USERINFO q_o;
	SAM_USERINFO_CTR ctr;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Set User Info.  level: %d\n", switch_value));

	if (pol == NULL || usr == NULL || switch_value == 0) return False;

	/* create and send a MSRPC command with api SAMR_SET_USERINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	q_o.ctr = &ctr;

	/* store the parameters */
	make_samr_q_set_userinfo(&q_o, pol, switch_value, usr);

	/* turn parameters into data stream */
	if (samr_io_q_set_userinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_SET_USERINFO, &data, &rdata))
	{
		SAMR_R_SET_USERINFO r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		samr_io_r_set_userinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_USERINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_query = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query User Info
****************************************************************************/
BOOL samr_query_userinfo(  POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_USERINFO q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query User Info.  level: %d\n", switch_value));

	if (pol == NULL || ctr == NULL || switch_value == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_USERINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_userinfo(&q_o, pol, switch_value);

	/* turn parameters into data stream */
	if (samr_io_q_query_userinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol, SAMR_QUERY_USERINFO, &data, &rdata))
	{
		SAMR_R_QUERY_USERINFO r_o;
		BOOL p;
		ZERO_STRUCT(r_o);

		r_o.ctr = ctr;

		samr_io_r_query_userinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_USERINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr == 0)
		{
			p = False;
		}

		if (p && r_o.ctr->switch_value != switch_value)
		{
			DEBUG(4,("SAMR_R_QUERY_USERINFO: received incorrect level %d\n",
			          r_o.ctr->switch_value));
		}

		if (p && r_o.ptr != 0)
		{
			valid_query = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Close
****************************************************************************/
BOOL samr_close(  POLICY_HND *hnd)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CLOSE_HND q_c;
	BOOL valid_close = False;

	DEBUG(4,("SAMR Close\n"));

	if (hnd == NULL) return False;

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* create and send a MSRPC command with api SAMR_CLOSE_HND */

	/* store the parameters */
	make_samr_q_close_hnd(&q_c, hnd);

	/* turn parameters into data stream */
	if (samr_io_q_close_hnd("", &q_c,  &data, 0) &&
	    rpc_hnd_pipe_req(hnd, SAMR_CLOSE_HND, &data, &rdata))
	{
		SAMR_R_CLOSE_HND r_c;
		BOOL p;

		ZERO_STRUCT(r_c);

		samr_io_r_close_hnd("", &r_c, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_CLOSE_HND: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			valid_close = True;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	close_policy_hnd(get_global_hnd_cache(), hnd);

	return valid_close;
}

/****************************************************************************
do a SAMR query display info
****************************************************************************/
BOOL samr_query_dispinfo(  POLICY_HND *pol_domain, uint16 level,
				uint32 *num_entries,
				SAM_DISPINFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_DISPINFO q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Display Info.  level: %d\n", level));

	if (pol_domain == NULL || num_entries == NULL || ctr == NULL ||
	    level == 0)
	{
		return False;
	}

	/* create and send a MSRPC command with api SAMR_QUERY_DISPINFO */

	prs_init(&data , 0, 4, False);
	prs_init(&rdata, 0, 4, True );

	/* store the parameters */
	make_samr_q_query_dispinfo(&q_o, pol_domain, level, 0, 0xffffffff);

	/* turn parameters into data stream */
	if (samr_io_q_query_dispinfo("", &q_o,  &data, 0) &&
	    rpc_hnd_pipe_req(pol_domain, SAMR_QUERY_DISPINFO, &data, &rdata))
	{
		SAMR_R_QUERY_DISPINFO r_o;
		BOOL p;

		ZERO_STRUCT(r_o);

		/* get user info */
		r_o.ctr = ctr;

		samr_io_r_query_dispinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(4,("SAMR_R_QUERY_DISPINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.switch_level != level)
		{
			DEBUG(4,("SAMR_R_QUERY_DISPINFO: received incorrect level %d\n",
			          r_o.switch_level));
		}

		if (p && r_o.ptr_entries != 0)
		{
			valid_query = True;
			(*num_entries) = r_o.num_entries;
		}
	}

	prs_free_data(&data   );
	prs_free_data(&rdata  );

	return valid_query;
}
