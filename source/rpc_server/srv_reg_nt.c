/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Hewlett-Packard Company           1999.
 *  Copyright (C) Jeremy Allison					2001.
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

/* Implementation of registry functions. */

#include "includes.h"

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

NTSTATUS _reg_close(pipes_struct *p, REG_Q_CLOSE *q_u, REG_R_CLOSE *r_u)
{
	/* set up the REG unknown_1 response */
	ZERO_STRUCT(r_u->pol);

	/* close the policy handle */
	if (!close_policy_hnd(p, &q_u->pol))
		return NT_STATUS_OBJECT_NAME_INVALID;

	return NT_STATUS_OK;
}

/*******************************************************************
 reg_reply_open
 ********************************************************************/

NTSTATUS _reg_open(pipes_struct *p, REG_Q_OPEN_HKLM *q_u, REG_R_OPEN_HKLM *r_u)
{
	if (!create_policy_hnd(p, &r_u->pol, free_reg_info, NULL))
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	return NT_STATUS_OK;
}

/*******************************************************************
 reg_reply_open_entry
 ********************************************************************/

NTSTATUS _reg_open_entry(pipes_struct *p, REG_Q_OPEN_ENTRY *q_u, REG_R_OPEN_ENTRY *r_u)
{
	POLICY_HND pol;
	fstring name;
	struct reg_info *info = NULL;

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	fstrcpy(name, dos_unistrn2(q_u->uni_name.buffer, q_u->uni_name.uni_str_len));

	DEBUG(5,("reg_open_entry: %s\n", name));

	/* lkcl XXXX do a check on the name, here */
	if (!strequal(name, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions") &&
	    !strequal(name, "System\\CurrentControlSet\\services\\Netlogon\\parameters\\"))
			return NT_STATUS_ACCESS_DENIED;

	if ((info = (struct reg_info *)malloc(sizeof(struct reg_info))) == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(info);
	fstrcpy(info->name, name);

	if (!create_policy_hnd(p, &pol, free_reg_info, (void *)info))
		return NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */

	init_reg_r_open_entry(r_u, &pol, NT_STATUS_OK);

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 reg_reply_info
 ********************************************************************/

NTSTATUS _reg_info(pipes_struct *p, REG_Q_INFO *q_u, REG_R_INFO *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	const char *key = NULL;
	uint32 type=0x1; /* key type: REG_SZ */

	UNISTR2 *uni_key = NULL;
	BUFFER2 *buf = NULL;
	fstring name;

	DEBUG(5,("_reg_info: %d\n", __LINE__));

	if (!find_policy_by_hnd(p, &q_u->pol, NULL))
		return NT_STATUS_INVALID_HANDLE;

	fstrcpy(name, dos_unistrn2(q_u->uni_type.buffer, q_u->uni_type.uni_str_len));

	DEBUG(5,("reg_info: checking key: %s\n", name));

	uni_key = (UNISTR2 *)talloc_zero(p->mem_ctx, sizeof(UNISTR2));
	buf = (BUFFER2 *)talloc_zero(p->mem_ctx, sizeof(BUFFER2));

	if (!uni_key || !buf)
		return NT_STATUS_NO_MEMORY;

	if ( strequal(name, "RefusePasswordChange") ) {
		type=0xF770;
		status = NT_STATUS_NO_SUCH_FILE;
		init_unistr2(uni_key, "", 0);
		init_buffer2(buf, (uint8*) uni_key->buffer, uni_key->uni_str_len*2);
		
		buf->buf_max_len=4;

		goto out;
	}

	switch (lp_server_role()) {
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
		key = "LanmanNT";
		break;
	case ROLE_STANDALONE:
		key = "ServerNT";
		break;
	case ROLE_DOMAIN_MEMBER:
		key = "WinNT";
		break;
	}

	/* This makes the server look like a member server to clients */
	/* which tells clients that we have our own local user and    */
	/* group databases and helps with ACL support.                */

	init_unistr2(uni_key, key, strlen(key)+1);
	init_buffer2(buf, (uint8*)uni_key->buffer, uni_key->uni_str_len*2);
  
 out:
	init_reg_r_info(q_u->ptr_buf, r_u, buf, type, status);

	DEBUG(5,("reg_open_entry: %d\n", __LINE__));

	return status;
}
