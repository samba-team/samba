/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Matthew Chapman              1999-2000,
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

BOOL synchronise_passdb(void)
{
	SAM_DELTA_HDR hdr_deltas[MAX_SAM_DELTAS];
	SAM_DELTA_CTR deltas[MAX_SAM_DELTAS];
	uint32 num;

	SAM_ACCOUNT_INFO *acc;
	struct smb_passwd pwd;
	fstring nt_name;
	unsigned char smb_passwd[16];
	unsigned char smb_nt_passwd[16];
	uchar trust_passwd[16];
	fstring trust_acct;

	char *mode;
	BOOL success;
	BOOL ret;
	int i;

	fstrcpy(trust_acct, global_myname);
	fstrcat(trust_acct, "$");

	if (!msrpc_lsa_query_trust_passwd("\\\\.", "$MACHINE.ACC",
	                                  trust_passwd))
	{
		return False;
	}

	ret = net_sam_sync(lp_passwordserver(), lp_workgroup(),
	                  global_myname, trust_acct,
	                  trust_passwd,
	                  hdr_deltas, deltas, &num);

	if (ret)
	{
		for (i = 0; i < num; i++)
		{
			/* Currently only interested in accounts */
			if (hdr_deltas[i].type != 5)
			{
				continue;
			}

			acc = &deltas[i].account_info;
			pwdb_init_smb(&pwd);

			pwd.user_rid = acc->user_rid;
			unistr2_to_ascii(nt_name, &(acc->uni_acct_name), sizeof(fstring)-1);
			pwd.nt_name = nt_name;
			pwd.acct_ctrl = acc->acb_info;
			pwd.pass_last_set_time = nt_time_to_unix(&(acc->pwd_last_set_time));
			
			sam_pwd_hash(acc->user_rid, smb_passwd, acc->pass.buf_lm_pwd, 0);
			sam_pwd_hash(acc->user_rid, smb_nt_passwd, acc->pass.buf_nt_pwd, 0);
			pwd.smb_passwd = smb_passwd;
			pwd.smb_nt_passwd = smb_nt_passwd;

			mode = "modify";
			success = mod_smbpwd_entry(&pwd, True);

			if (!success)
			{
				mode = "add";
				success = add_smbpwd_entry(&pwd);
			}

			DEBUG(0, ("Attempted to %s account for %s: %s\n", mode,
				  nt_name, success ? "OK" : "FAILED"));
		}
	}

	return ret;
}
