/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tgrpsgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Paul Ashton                  1997-1999.
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
 *  Foundation, Inc., 675 Mass Ave, Cambgrpsge, MA 02139, USA.
 */


#include "includes.h"

extern int DEBUGLEVEL;


/*******************************************************************
makes a CREDS_UNIX structure.
********************************************************************/
BOOL make_creds_unix(CREDS_UNIX *r_u, const char* user_name,
				const char* requested_name,
				const char* real_name,
				BOOL guest)
{
	if (r_u == NULL) return False;

	DEBUG(5,("make_creds_unix\n"));

	fstrcpy(r_u->user_name     , user_name);
	fstrcpy(r_u->requested_name, requested_name);
	fstrcpy(r_u->real_name     , real_name);
	r_u->guest = guest;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_unix(char *desc, CREDS_UNIX *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_unix");
	depth++;

	prs_align(ps);
	prs_string("user_name", ps, depth,   r_u->user_name, strlen(r_u->user_name), sizeof(r_u->user_name));
	prs_align(ps);
	prs_string("requested_name", ps, depth,   r_u->requested_name, strlen(r_u->requested_name), sizeof(r_u->requested_name));
	prs_align(ps);
	prs_string("real_name", ps, depth,   r_u->real_name, strlen(r_u->real_name), sizeof(r_u->real_name));
	prs_align(ps);
	prs_uint32("guest", ps, depth, &(r_u->guest));
	return True;
}


/*******************************************************************
frees a structure.
********************************************************************/
void creds_free_unix(CREDS_UNIX *r_u)
{
}

/*******************************************************************
makes a CREDS_UNIX_SEC structure.
********************************************************************/
BOOL make_creds_unix_sec(CREDS_UNIX_SEC *r_u,
		uint32 uid, uint32 gid, uint32 num_grps, gid_t *grps)
{
	int i;
	if (r_u == NULL) return False;

	DEBUG(5,("make_creds_unix_sec\n"));

	r_u->uid      = uid;
	r_u->gid      = gid;
	r_u->num_grps = num_grps;
	r_u->grps = (uint32*)Realloc(NULL, sizeof(r_u->grps[0]) *
				       r_u->num_grps);
	if (r_u->grps == NULL && num_grps != 0)
	{
		return False;
	}
	for (i = 0; i < num_grps; i++)
	{
		r_u->grps[i] = (gid_t)grps[i];
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_unix_sec(char *desc, CREDS_UNIX_SEC *r_u, prs_struct *ps, int depth)
{
	uint32 i;

	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_unix_sec");
	depth++;

	prs_align(ps);

	prs_uint32("uid", ps, depth, &(r_u->uid));
	prs_uint32("gid", ps, depth, &(r_u->gid));
	prs_uint32("num_grps", ps, depth, &(r_u->num_grps));
	if (r_u->num_grps != 0)
	{
		r_u->grps = (uint32*)Realloc(r_u->grps,
				       sizeof(r_u->grps[0]) *
				       r_u->num_grps);
		if (r_u->grps == NULL)
		{
			creds_free_unix_sec(r_u);
			return False;
		}
	}
	for (i = 0; i < r_u->num_grps; i++)
	{
		prs_uint32("", ps, depth, &(r_u->grps[i]));
	}
	return True;
}


/*******************************************************************
frees a structure.
********************************************************************/
void creds_free_unix_sec(CREDS_UNIX_SEC *r_u)
{
	if (r_u->grps != NULL)
	{
		free(r_u->grps);
		r_u->grps = NULL;
	}
}

/*******************************************************************
makes a CREDS_NT_SEC structure.
********************************************************************/
BOOL make_creds_nt_sec(CREDS_NT_SEC *r_u,
		DOM_SID *sid, uint32 num_grps, uint32 *grps)
{
	int i;
	if (r_u == NULL) return False;

	DEBUG(5,("make_creds_unix_sec\n"));

	sid_copy(&r_u->sid, sid);
	r_u->num_grps = num_grps;
	r_u->grp_rids = (uint32*)Realloc(NULL, sizeof(r_u->grp_rids[0]) *
				       r_u->num_grps);

	if (r_u->grp_rids == NULL && num_grps != 0)
	{
		return False;
	}
	for (i = 0; i < num_grps; i++)
	{
		r_u->grp_rids[i] = grps[i];
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_nt_sec(char *desc, CREDS_NT_SEC *r_u, prs_struct *ps, int depth)
{
	int i;
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_nt");
	depth++;

	prs_align(ps);

	smb_io_dom_sid ("sid", &r_u->sid, ps, depth);
	prs_align(ps);

	prs_uint32("num_grps", ps, depth, &(r_u->num_grps));
	if (r_u->num_grps != 0)
	{
		r_u->grp_rids = (uint32*)Realloc(r_u->grp_rids,
				       sizeof(r_u->grp_rids[0]) *
				       r_u->num_grps);
		if (r_u->grp_rids == NULL)
		{
			creds_free_nt_sec(r_u);
			return False;
		}
	}
	for (i = 0; i < r_u->num_grps; i++)
	{
		prs_uint32("", ps, depth, &(r_u->grp_rids[i]));
	}

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void creds_free_nt_sec(CREDS_NT_SEC *r_u)
{
	if (r_u->grp_rids != NULL)
	{
		free(r_u->grp_rids);
		r_u->grp_rids = NULL;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_pwd_info(char *desc, struct pwd_info *pwd, prs_struct *ps, int depth)
{
	if (pwd == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_pwd_info");
	depth++;

	prs_align(ps);

	prs_uint32("nullpwd", ps, depth, &(pwd->null_pwd));
	if (pwd->null_pwd)
	{
		return True;
	}
	
	prs_uint32("cleartext", ps, depth, &(pwd->cleartext));
	if (pwd->cleartext)
	{
		prs_string("password", ps, depth,   pwd->password, strlen(pwd->password), sizeof(pwd->password));
		prs_align(ps);
		return True;
	}
	prs_uint32("crypted", ps, depth, &(pwd->crypted));
		
	prs_uint8s(False, "smb_lm_pwd", ps, depth, (char*)&pwd->smb_lm_pwd, sizeof(pwd->smb_lm_pwd));
	prs_align(ps);
	prs_uint8s(False, "smb_nt_pwd", ps, depth, (char*)&pwd->smb_nt_pwd, sizeof(pwd->smb_nt_pwd));
	prs_align(ps);

	prs_uint8s(False, "smb_lm_owf", ps, depth, (char*)&pwd->smb_lm_owf, sizeof(pwd->smb_lm_owf));
	prs_align(ps);
	prs_uint32("nt_owf_len", ps, depth, &(pwd->nt_owf_len));
	if (pwd->nt_owf_len > sizeof(pwd->smb_nt_owf))
	{
		return False;
	}
	prs_uint8s(False, "smb_nt_owf", ps, depth, (char*)&pwd->smb_nt_owf, pwd->nt_owf_len);
	prs_align(ps);

	prs_uint8s(False, "lm_cli_chal", ps, depth, (char*)&pwd->lm_cli_chal, sizeof(pwd->lm_cli_chal));
	prs_align(ps);
	prs_uint32("nt_cli_chal_len", ps, depth, &(pwd->nt_cli_chal_len));

	if (pwd->nt_cli_chal_len > sizeof(pwd->nt_cli_chal))
	{
		return False;
	}
	prs_uint8s(False, "nt_cli_chal", ps, depth, (char*)&pwd->nt_cli_chal, pwd->nt_cli_chal_len);
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_nt(char *desc, CREDS_NT *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_nt");
	depth++;

	prs_align(ps);

	/* lkclXXXX CHEAT!!!!!!!! */
	prs_string("user_name", ps, depth,   r_u->user_name, strlen(r_u->user_name), sizeof(r_u->user_name));
	prs_align(ps);
	prs_string("domain", ps, depth,   r_u->domain, strlen(r_u->domain), sizeof(r_u->domain));
	prs_align(ps);

	creds_io_pwd_info("pwd", &r_u->pwd, ps, depth);
	prs_align(ps);

	prs_uint32("ntlmssp", ps, depth, &(r_u->ntlmssp_flags));

	return True;
}

/*******************************************************************
frees a structure.
********************************************************************/
void creds_free_nt(CREDS_NT *r_u)
{
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_hybrid(char *desc, CREDS_HYBRID *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_hybrid");
	depth++;

	prs_align(ps);

	prs_uint32("reuse", ps, depth, &(r_u->reuse));
	prs_uint32("ptr_ntc", ps, depth, &(r_u->ptr_ntc));
	prs_uint32("ptr_uxc", ps, depth, &(r_u->ptr_uxc));
	prs_uint32("ptr_nts", ps, depth, &(r_u->ptr_nts));
	prs_uint32("ptr_uxs", ps, depth, &(r_u->ptr_uxs));
	if (r_u->ptr_ntc != 0)
	{
		if (!creds_io_nt  ("ntc", &r_u->ntc, ps, depth)) return False;
	}
	if (r_u->ptr_uxc != 0)
	{
		if (!creds_io_unix("uxc", &r_u->uxc, ps, depth)) return False;
	}
	if (r_u->ptr_nts != 0)
	{
		if (!creds_io_nt_sec  ("nts", &r_u->nts, ps, depth)) return False;
	}
	if (r_u->ptr_uxs != 0)
	{
		if (!creds_io_unix_sec("uxs", &r_u->uxs, ps, depth)) return False;
	}
	return True;
}

void copy_unix_creds(CREDS_UNIX *to, const CREDS_UNIX *from)
{
	if (from == NULL)
	{
		to->user_name[0] = 0;
		return;
	}
	fstrcpy(to->user_name, from->user_name);
};

void copy_nt_sec_creds(CREDS_NT_SEC *to, const CREDS_NT_SEC *from)
{
	if (from == NULL)
	{
		ZERO_STRUCTP(to);
		return;
	}
	sid_copy(&to->sid, &from->sid);
	to->num_grps = 0;
	to->grp_rids = NULL;

	if (from->num_grps != 0)
	{
		size_t size = from->num_grps * sizeof(from->grp_rids[0]);
		to->grp_rids = (uint32*)malloc(size);
		if (to->grp_rids == NULL)
		{
			return;
		}
		to->num_grps = from->num_grps;
		memcpy(to->grp_rids, from->grp_rids, size);
	}
};

void copy_unix_sec_creds(CREDS_UNIX_SEC *to, const CREDS_UNIX_SEC *from)
{
	if (from == NULL)
	{
		to->uid = -1;
		to->gid = -1;
		to->num_grps = 0;
		to->grps = NULL;
		return;
	}
	to->uid = from->uid;
	to->gid = from->gid;
	to->num_grps = 0;
	to->grps = NULL;

	if (from->num_grps != 0)
	{
		size_t size = from->num_grps * sizeof(from->grps[0]);
		to->grps = (uint32*)malloc(size);
		if (to->grps == NULL)
		{
			return;
		}
		to->num_grps = from->num_grps;
		memcpy(to->grps, from->grps, size);
	}
};

void copy_nt_creds(struct ntuser_creds *to,
				const struct ntuser_creds *from)
{
	if (from == NULL)
	{
		DEBUG(10,("copy_nt_creds: null creds\n"));
		to->domain[0] = 0;
		to->user_name[0] = 0;
		pwd_set_nullpwd(&to->pwd);
		to->ntlmssp_flags = 0;

		return;
	}
	safe_strcpy(to->domain   , from->domain   , sizeof(from->domain   )-1);
	safe_strcpy(to->user_name, from->user_name, sizeof(from->user_name)-1);
	memcpy(&to->pwd, &from->pwd, sizeof(from->pwd));
	to->ntlmssp_flags = from->ntlmssp_flags;
};

void copy_user_creds(struct user_creds *to,
				const struct user_creds *from)
{
	ZERO_STRUCTP(to);
	if (from == NULL)
	{
		to->ptr_ntc = 0;
		to->ptr_uxc = 0;
		to->ptr_nts = 0;
		to->ptr_uxs = 0;
		copy_nt_creds(&to->ntc, NULL);
		copy_unix_creds(&to->uxc, NULL);
		copy_nt_sec_creds(&to->nts, NULL);
		copy_unix_sec_creds(&to->uxs, NULL);
		to->reuse = False;
		return;
	}
	to->ptr_nts = from->ptr_nts;
	to->ptr_uxs = from->ptr_uxs;
	to->ptr_ntc = from->ptr_ntc;
	to->ptr_uxc = from->ptr_uxc;
	if (to->ptr_ntc != 0)
	{
		copy_nt_creds(&to->ntc, &from->ntc);
	}
	if (to->ptr_uxc != 0)
	{
		copy_unix_creds(&to->uxc, &from->uxc);
	}
	if (to->ptr_nts != 0)
	{
		copy_nt_sec_creds(&to->nts, &from->nts);
	}
	if (to->ptr_uxs != 0)
	{
		copy_unix_sec_creds(&to->uxs, &from->uxs);
	}
	to->reuse = from->reuse;
};

void free_user_creds(struct user_creds *creds)
{
	creds_free_unix(&creds->uxc);
	creds_free_nt  (&creds->ntc);
	creds_free_unix_sec(&creds->uxs);
	creds_free_nt_sec  (&creds->nts);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL creds_io_cmd(char *desc, CREDS_CMD *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "creds_io_cmd");
	depth++;

	prs_align(ps);

	prs_uint16("version", ps, depth, &(r_u->version));
	prs_uint16("command", ps, depth, &(r_u->command));

	prs_string("name   ", ps, depth,   r_u->name, strlen(r_u->name), sizeof(r_u->name));
	prs_align(ps);
	
	prs_uint32("ptr_creds", ps, depth, &(r_u->ptr_creds));
	if (r_u->ptr_creds != 0)
	{
		if (!creds_io_hybrid("creds", r_u->cred, ps, depth))
		{
			return False;
		}
	}


	return True;
}


BOOL create_ntuser_creds( prs_struct *ps,
				const char* name, 
				uint16 version, uint16 command,
				const struct ntuser_creds *ntu,
				BOOL reuse)
{
	CREDS_CMD cmd;
	struct user_creds usr;

	ZERO_STRUCT(cmd);
	ZERO_STRUCT(usr);

	DEBUG(10,("create_user_creds: %s %d %d\n",
		name, version, command));

	usr.reuse = reuse;

	fstrcpy(cmd.name, name);
	cmd.version = version;
	cmd.command = command;
	cmd.ptr_creds = ntu != NULL ? 1 : 0;
	cmd.cred = &usr;

	if (ntu != NULL)
	{
		copy_nt_creds(&usr.ntc, ntu);
		usr.ptr_ntc = 1;
	}
	else
	{
		usr.ptr_ntc = 0;
	}
		
	prs_init(ps, 1024, 4, False);

	ps->data_offset = 4;
	return creds_io_cmd("creds", &cmd, ps, 0);
}

BOOL create_user_creds( prs_struct *ps,
				const char* name, 
				uint16 version, uint16 command,
				const struct user_creds *usr)
{
	CREDS_CMD cmd;

	ZERO_STRUCT(cmd);

	DEBUG(10,("create_user_creds: %s %d %d\n",
		name, version, command));

	fstrcpy(cmd.name, name);
	cmd.version = version;
	cmd.command = command;
	cmd.ptr_creds = usr != NULL ? 1 : 0;
	cmd.cred = usr;

	prs_init(ps, 1024, 4, False);

	ps->data_offset = 4;
	return creds_io_cmd("creds", &cmd, ps, 0);
}
