/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker                    2000,
 *  Copyright (C) Elrond                            2000
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
#include "sids.h"

extern int DEBUGLEVEL;


/*******************************************************************
 samr_make_usr_obj_sd
 ********************************************************************/
uint32 samr_make_usr_obj_sd(SEC_DESC_BUF *buf, DOM_SID *usr_sid)
{
	DOM_SID adm_sid;
	DOM_SID act_sid;
	DOM_SID glb_sid;

	SEC_ACL *dacl = NULL;
	SEC_ACE *dace = NULL;
	SEC_ACCESS mask;
	SEC_DESC *sec = NULL;
	int len;

	DEBUG(15, ("samr_make_usr_obj_sd: %d\n", __LINE__));

	dacl = malloc(sizeof(*dacl));
	dace = malloc(4 * sizeof(*dace));
	sec = malloc(sizeof(*sec));

	if (dacl == NULL || dace == NULL || sec == NULL)
	{
		safe_free(dacl);
		safe_free(dace);
		safe_free(sec);
		return NT_STATUS_NO_MEMORY;
	}

	sid_copy(&adm_sid, global_sid_builtin);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&act_sid, global_sid_builtin);
	sid_append_rid(&act_sid, BUILTIN_ALIAS_RID_ACCOUNT_OPS);

	sid_copy(&glb_sid, global_sid_everyone);

	mask.mask = 0x2035b;
	make_sec_ace(&dace[0], &glb_sid, 0, mask, 0);
	mask.mask = 0xf07ff;
	make_sec_ace(&dace[1], &adm_sid, 0, mask, 0);
	make_sec_ace(&dace[2], &act_sid, 0, mask, 0);
	mask.mask = 0x20044;
	make_sec_ace(&dace[3], usr_sid, 0, mask, 0);

	make_sec_acl(dacl, 2, 4, dace);

	len = make_sec_desc(sec, 1,
	              SEC_DESC_DACL_PRESENT|SEC_DESC_SELF_RELATIVE,
	              NULL, NULL, NULL, dacl);

	make_sec_desc_buf(buf, len, sec);
	buf->undoc = 0x1;

	return NT_STATUS_NOPROBLEMO;
}
