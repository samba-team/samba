/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Lars Kneschke                     2000. 
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
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
  set reg name 
****************************************************************************/
static BOOL set_policy_reg_name(struct policy_cache *cache, POLICY_HND * hnd,
				fstring name)
{
	char *dev = strdup(name);
	if (dev != NULL)
	{
		if (set_policy_state(cache, hnd, NULL, (void *)dev))
		{
			DEBUG(3, ("Registry setting policy name=%s\n", name));
			return True;
		}
		free(dev);
	}

	DEBUG(3, ("Error setting policy name=%s\n", name));
	return False;
}

/****************************************************************************
  get reg name 
****************************************************************************/
static BOOL get_policy_reg_name(struct policy_cache *cache, POLICY_HND * hnd,
				fstring name)
{
	char *dev = (char *)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		fstrcpy(name, dev);
		DEBUG(5, ("getting policy reg name=%s\n", name));
		return True;
	}

	DEBUG(3, ("Error getting policy reg name\n"));
	return False;
}

/*******************************************************************
 _reg_close
 ********************************************************************/
uint32 _reg_close(POLICY_HND * pol)
{
	/* close the policy handle */
	if (!close_policy_hnd(get_global_hnd_cache(), pol))
	{
		return NT_STATUS_OBJECT_NAME_INVALID;
	}
	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _reg_open
 ********************************************************************/
uint32 _reg_open(POLICY_HND * pol, uint32 access_mask)
{
	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(), get_sec_ctx(),
			     pol, access_mask))
	{
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _reg_open_entry
 ********************************************************************/
uint32 _reg_open_entry(const POLICY_HND * pol, const UNISTR2 * uni_name,
		       uint32 unknown_0, uint32 access_mask,
		       POLICY_HND * entry_pol)
{
	fstring name;

	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!open_policy_hnd_link(get_global_hnd_cache(),
				  pol, entry_pol, access_mask))
	{
		return NT_STATUS_TOO_MANY_SECRETS;	/* ha ha very droll */
	}

	unistr2_to_ascii(name, uni_name, sizeof(name) - 1);

	/* lkcl XXXX do a check on the name, here */
	if (!strequal
	    (name, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions")
	    && !strequal(name,
			 "SYSTEM\\CurrentControlSet\\Services\\NETLOGON\\Parameters\\"))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!set_policy_reg_name(get_global_hnd_cache(), entry_pol, name))
	{
		return NT_STATUS_TOO_MANY_SECRETS;	/* ha ha very droll */
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _reg_info
 ********************************************************************/
uint32 _reg_info(POLICY_HND * pol, BUFFER2 * buf, uint32 * type)
{
	fstring name;

	if (!get_policy_reg_name(get_global_hnd_cache(), pol, name))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (strequal
	    (name, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"))
	{
		char *key;
		if (lp_server_role() == ROLE_DOMAIN_PDC)
		{
			key = "LanmanNT";
		}
		else
		{
			key = "ServerNT";
		}
		make_buffer2(buf, key, strlen(key));
		*type = 0x1;
	}
	else
	{
		return 0x2;	/* Win32 status code.  ick */
	}

	return NT_STATUS_NOPROBLEMO;
}

#if 0

/*******************************************************************
 array of \PIPE\reg operations
 ********************************************************************/
static struct api_struct api_reg_cmds[] = {
	{"REG_CLOSE", REG_CLOSE, api_reg_close},
	{"REG_OPEN_ENTRY", REG_OPEN_ENTRY, api_reg_open_entry},
	{"REG_OPEN", REG_OPEN_HKLM, api_reg_open},
	{"REG_INFO", REG_INFO, api_reg_info},
	{NULL, 0, NULL}
};

/*******************************************************************
 receives a reg pipe and responds.
 ********************************************************************/
BOOL api_reg_rpc(rpcsrv_struct * p)
{
	return api_rpcTNP(p, "api_reg_rpc", api_reg_cmds);
}
#endif
