
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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
#include "nterr.h"

extern int DEBUGLEVEL;


/****************************************************************************
  set reg name 
****************************************************************************/
static BOOL set_policy_reg_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev = strdup(name);
	if (dev != NULL)
	{
		if (set_policy_state(cache, hnd, NULL, (void*)dev))
		{
			DEBUG(3,("Registry setting policy name=%s\n", name));
			return True;
		}
		free(dev);
	}

	DEBUG(3,("Error setting policy name=%s\n", name));
	return False;
}

/****************************************************************************
  get reg name 
****************************************************************************/
static BOOL get_policy_reg_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev = (char*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		fstrcpy(name, dev);
		DEBUG(5,("getting policy reg name=%s\n", name));
		return True;
	}

	DEBUG(3,("Error getting policy reg name\n"));
	return False;
}

/*******************************************************************
 reg_reply_unknown_1
 ********************************************************************/
static void reg_reply_close(REG_Q_CLOSE *q_r,
				prs_struct *rdata)
{
	REG_R_CLOSE r_u;

	/* set up the REG unknown_1 response */
	bzero(r_u.pol.data, POL_HND_SIZE);

	/* close the policy handle */
	if (close_policy_hnd(get_global_hnd_cache(), &(q_r->pol)))
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
static void api_reg_close( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	REG_Q_CLOSE q_r;

	/* grab the reg unknown 1 */
	reg_io_q_close("", &q_r, data, 0);

	/* construct reply.  always indicate success */
	reg_reply_close(&q_r, rdata);
}


/*******************************************************************
 reg_reply_open
 ********************************************************************/
static void reg_reply_open(REG_Q_OPEN_HKLM *q_r,
				prs_struct *rdata)
{
	REG_R_OPEN_HKLM r_u;

	r_u.status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !open_policy_hnd(get_global_hnd_cache(), &(r_u.pol)))
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
static void api_reg_open( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	REG_Q_OPEN_HKLM q_u;

	/* grab the reg open */
	reg_io_q_open_hklm("", &q_u, data, 0);

	/* construct reply.  always indicate success */
	reg_reply_open(&q_u, rdata);
}


/*******************************************************************
 reg_reply_open_entry
 ********************************************************************/
static void reg_reply_open_entry(REG_Q_OPEN_ENTRY *q_u,
				prs_struct *rdata)
{
	uint32 status     = 0;
	POLICY_HND pol;
	REG_R_OPEN_ENTRY r_u;
	fstring name;

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));

	if (status == 0 && find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1)
	{
		status = 0xC000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0 && !open_policy_hnd(get_global_hnd_cache(), &pol))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, &q_u->uni_name, sizeof(name)-1);

	if (status == 0x0)
	{
		DEBUG(5,("reg_open_entry: %s\n", name));
		/* lkcl XXXX do a check on the name, here */
		if (!strequal(name, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions") &&
		    !strequal(name, "SYSTEM\\CurrentControlSet\\Services\\NETLOGON\\Parameters\\"))
		{
			status = 0xC000000 | NT_STATUS_ACCESS_DENIED;
		}
	}

	if (status == 0x0 && !set_policy_reg_name(get_global_hnd_cache(), &pol, name))
	{
		status = 0xC000000 | NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	make_reg_r_open_entry(&r_u, &pol, status);

	/* store the response in the SMB stream */
	reg_io_r_open_entry("", &r_u, rdata, 0);

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));
}

/*******************************************************************
 api_reg_open_entry
 ********************************************************************/
static void api_reg_open_entry( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	REG_Q_OPEN_ENTRY q_u;

	/* grab the reg open entry */
	reg_io_q_open_entry("", &q_u, data, 0);

	/* construct reply. */
	reg_reply_open_entry(&q_u, rdata);
}


/*******************************************************************
 reg_reply_info
 ********************************************************************/
static void reg_reply_info(REG_Q_INFO *q_u,
				prs_struct *rdata)
{
	uint32 status     = 0;

	REG_R_INFO r_u;
	uint32 type = 0xcafeface;
	BUFFER2 buf;
	fstring name;

	ZERO_STRUCT(buf);

	DEBUG(5,("reg_info: %d\n", __LINE__));

	if (status == 0x0 && !get_policy_reg_name(get_global_hnd_cache(), &q_u->pol, name))
	{
		status = 0xC000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0 &&
	   strequal(name, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"))
	{
		char *key = "LanmanNT";
		make_buffer2(&buf, key, strlen(key));
		type = 0x1;
	}
	else
	{
		status = 0x2; /* Win32 status code.  ick */
	}

	make_reg_r_info(&r_u, &type, &buf, status);

	/* store the response in the SMB stream */
	reg_io_r_info("", &r_u, rdata, 0);

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));
}

/*******************************************************************
 api_reg_info
 ********************************************************************/
static void api_reg_info( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	REG_Q_INFO q_u;

	/* grab the reg unknown 0x11*/
	reg_io_q_info("", &q_u, data, 0);

	/* construct reply.  always indicate success */
	reg_reply_info(&q_u, rdata);
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
BOOL api_reg_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_reg_rpc", api_reg_cmds);
}

