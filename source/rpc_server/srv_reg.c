#define OLD_NTDOMAIN 1
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Hewlett-Packard Company           1999.
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


#include "includes.h"

extern int DEBUGLEVEL;

struct reg_info
{
	/* for use by \PIPE\winreg */
	fstring name; /* name of registry key */
};

static void free_reg_info(void *ptr)
{
	struct reg_info *info = (struct reg_info *)ptr;

	SAFE_FREE(info);
}

/*******************************************************************
 reg_reply_unknown_1
 ********************************************************************/
static void reg_reply_close(pipes_struct *p, REG_Q_CLOSE *q_r,
				prs_struct *rdata)
{
	REG_R_CLOSE r_u;

	/* set up the REG unknown_1 response */
	ZERO_STRUCT(r_u.pol);

	/* close the policy handle */
	if (close_policy_hnd(p, &q_r->pol))
	{
		r_u.status = 0;
	}
	else
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_INVALID;
	}

	DEBUG(5,("reg_unknown_1: %d\n", __LINE__));

	/* store the response in the SMB stream */
	reg_io_r_close("", &r_u, rdata, 0);

	DEBUG(5,("reg_unknown_1: %d\n", __LINE__));
}

/*******************************************************************
 api_reg_close
 ********************************************************************/
static BOOL api_reg_close(pipes_struct *p)
{
	REG_Q_CLOSE q_r;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	/* grab the reg unknown 1 */
	reg_io_q_close("", &q_r, data, 0);

	/* construct reply.  always indicate success */
	reg_reply_close(p, &q_r, rdata);

	return True;
}


/*******************************************************************
 reg_reply_open
 ********************************************************************/
static void reg_reply_open(pipes_struct *p, REG_Q_OPEN_HKLM *q_r,
				prs_struct *rdata)
{
	REG_R_OPEN_HKLM r_u;

	r_u.status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !create_policy_hnd(p, &r_u.pol, free_reg_info, NULL))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(5,("reg_open: %d\n", __LINE__));

	/* store the response in the SMB stream */
	reg_io_r_open_hklm("", &r_u, rdata, 0);

	DEBUG(5,("reg_open: %d\n", __LINE__));
}

/*******************************************************************
 api_reg_open
 ********************************************************************/
static BOOL api_reg_open(pipes_struct *p)
{
	REG_Q_OPEN_HKLM q_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	/* grab the reg open */
	reg_io_q_open_hklm("", &q_u, data, 0);

	/* construct reply.  always indicate success */
	reg_reply_open(p, &q_u, rdata);

	return True;
}


/*******************************************************************
 reg_reply_open_entry
 ********************************************************************/
static void reg_reply_open_entry(pipes_struct *p, REG_Q_OPEN_ENTRY *q_u,
				prs_struct *rdata)
{
	uint32 status     = 0;
	POLICY_HND pol;
	REG_R_OPEN_ENTRY r_u;
	fstring name;
	struct reg_info *info = NULL;

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		status = NT_STATUS_INVALID_HANDLE;

	fstrcpy(name, dos_unistrn2(q_u->uni_name.buffer, q_u->uni_name.uni_str_len));

	if (status == 0) {
		if ((info = (struct reg_info *)malloc(sizeof(struct reg_info))) == NULL)
			status = NT_STATUS_NO_MEMORY;

		ZERO_STRUCTP(info);
		fstrcpy(info->name, name);

		DEBUG(5,("reg_open_entry: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
		if (!strequal(name, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions")) {
			status = NT_STATUS_ACCESS_DENIED;
			SAFE_FREE(info);
		}
	}

	if (status == 0x0 && !create_policy_hnd(p, &pol, free_reg_info, (void *)info)) {
		status = NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
		SAFE_FREE(info);
	}

	init_reg_r_open_entry(&r_u, &pol, status);

	/* store the response in the SMB stream */
	reg_io_r_open_entry("", &r_u, rdata, 0);

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));
}

/*******************************************************************
 api_reg_open_entry
 ********************************************************************/
static BOOL api_reg_open_entry(pipes_struct *p)
{
	REG_Q_OPEN_ENTRY q_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	/* grab the reg open entry */
	reg_io_q_open_entry("", &q_u, data, 0);

	/* construct reply. */
	reg_reply_open_entry(p, &q_u, rdata);

	return True;
}


/*******************************************************************
 reg_reply_info
 ********************************************************************/
static void reg_reply_info(pipes_struct *p, REG_Q_INFO *q_u,
				prs_struct *rdata)
{
	uint32 status     = 0;
	char *key;
	uint32 type=0x1; /* key type: REG_SZ */

	UNISTR2 uni_key;
	BUFFER2 buf;

	REG_R_INFO r_u;

	DEBUG(5,("reg_info: %d\n", __LINE__));

	if (status == 0 && !find_policy_by_hnd(p, &q_u->pol, NULL))
	{
		status = NT_STATUS_INVALID_HANDLE;
	}

	switch (lp_server_role())
	{
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
		{
			key = "LanmanNT";
			break;
		}
		case ROLE_STANDALONE:
		{
			key = "ServerNT";
			break;
		}
		case ROLE_DOMAIN_MEMBER:
		{
			key = "WinNT";
			break;
		}
	}
	/* This makes the server look like a member server to clients */
	/* which tells clients that we have our own local user and    */
	/* group databases and helps with ACL support.                */
	init_unistr2(&uni_key, key, strlen(key)+1);
	init_buffer2(&buf, (uint8*) uni_key.buffer, uni_key.uni_str_len*2);
  
	init_reg_r_info(q_u->ptr_buf, &r_u, &buf, type, status);

	/* store the response in the SMB stream */
	reg_io_r_info("", &r_u, rdata, 0);

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));
}

/*******************************************************************
 api_reg_info
 ********************************************************************/
static BOOL api_reg_info(pipes_struct *p)
{
	REG_Q_INFO q_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	/* grab the reg unknown 0x11*/
	reg_io_q_info("", &q_u, data, 0);

	/* construct reply.  always indicate success */
	reg_reply_info(p, &q_u, rdata);

	return True;
}


/*******************************************************************
 array of \PIPE\reg operations
 ********************************************************************/
static struct api_struct api_reg_cmds[] =
{
	{ "REG_CLOSE"        , REG_CLOSE        , api_reg_close        },
	{ "REG_OPEN_ENTRY"   , REG_OPEN_ENTRY   , api_reg_open_entry   },
	{ "REG_OPEN"         , REG_OPEN_HKLM    , api_reg_open         },
	{ "REG_INFO"         , REG_INFO         , api_reg_info         },
	{ NULL,                0                , NULL                 }
};

/*******************************************************************
 receives a reg pipe and responds.
 ********************************************************************/
BOOL api_reg_rpc(pipes_struct *p)
{
	return api_rpcTNP(p, "api_reg_rpc", api_reg_cmds);
}
#undef OLD_NTDOMAIN
