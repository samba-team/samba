/*
 * Unix SMB/CIFS implementation. 
 * tdbsam2 genstruct enabled header file
 * Copyright (C) Simo Sorce 2002
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

/* ALL strings assumes UTF8 as encoding */

#ifndef TDBSAM2_H
#define TDBSAM2_H

/* IMPORTANT: these structures must follow closely the GUMS_OBJECTs
 * structures as they will be casted over !!
 * the GUMS_OBJECT union is unrolled here into four tdbsam2
 * objects cause genstruct is not able to follow arbitrary unions */

GENSTRUCT struct domain_sub_structure
{
	uint32 next_rid;		/* The Next free RID */
};

GENSTRUCT struct tdbsam2_domain_data
{
	TALLOC_CTX *mem_ctx;

	uint32 type;
	uint32 version;
	uint32 xcounter;		/* counter to be updated at any change */

	SEC_DESC *sec_desc;		/* Security Descriptor */
	
	DOM_SID *dom_sid;		/* The Domain SID */
	char *name; _NULLTERM		/* NT Domain Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	struct domain_sub_structure *dss;
};

GENSTRUCT struct user_sub_structure
{
	DOM_SID *group_sid;		/* The Primary Group SID */

	NTTIME logon_time;
	NTTIME logoff_time;
	NTTIME kickoff_time;
	NTTIME pass_last_set_time;
	NTTIME pass_can_change_time;
	NTTIME pass_must_change_time;
	
	char *full_name; _NULLTERM	/* The Full Name */
	char *home_dir; _NULLTERM	/* Home Directory */
	char *dir_drive; _NULLTERM	/* Drive Letter the home should be mapped to */
	char *logon_script; _NULLTERM	/* Logon script path */
	char *profile_path; _NULLTERM	/* Profile is stored here */
	char *workstations; _NULLTERM	/* List of Workstation names the user is allowed to LogIn */
	char *unknown_str; _NULLTERM	/* Guess ... Unknown */
	char *munged_dial; _NULLTERM	/* Callback Number */

	DATA_BLOB lm_pw;		/* .data is Null if no password */
	DATA_BLOB nt_pw;		/* .data is Null if no password */

	uint16 acct_ctrl;		/* account flags */
	uint16 logon_divs;		/* 168 - num of hours in a week */
	uint32 hours_len;		/* normally 21 */
	uint8 *hours; _LEN(hours_len)	/* normally 21 bytes (depends on hours_len) */

	uint16 bad_password_count;	/* 0 */
	uint16 logon_count;		/* 0 */
	uint32 unknown_3;		/* 0x00ff ffff */
	uint32 unknown_6;		/* 0x0000 04ec */
};

GENSTRUCT struct tdbsam2_user_data
{
	TALLOC_CTX *mem_ctx;

	uint32 type;
	uint32 version;
	uint32 xcounter;		/* counter to be updated at any change */

	SEC_DESC *sec_desc;		/* Security Descriptor */

	DOM_SID *user_sid;		/* The User SID */
	char *name; _NULLTERM		/* NT User Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	struct user_sub_structure *uss;
};

GENSTRUCT struct group_sub_structure
{
	uint32 count;			/* number of sids */
	DOM_SID *members; _LEN(count)	/* SID array */
};

GENSTRUCT struct tdbsam2_group_data
{
	TALLOC_CTX *mem_ctx;

	uint32 type;
	uint32 version;
	uint32 xcounter;		/* counter to be updated at any change */

	SEC_DESC *sec_desc;		/* Security Descriptor */

	DOM_SID *group_sid;		/* The Group SID */
	char *name; _NULLTERM		/* NT Group Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	struct group_sub_structure *gss;
};

GENSTRUCT struct priv_sub_structure
{
	LUID_ATTR *privilege;		/* Privilege */

	uint32 count;			/* number of sids */
	DOM_SID *members; _LEN(count)	/* SID array */
};

GENSTRUCT struct tdbsam2_priv_data
{
	TALLOC_CTX *mem_ctx;

	uint32 type;
	uint32 version;
	uint32 xcounter;		/* counter to be updated at any change */

	DOM_SID *null_sid;
	char *name; _NULLTERM		/* Privilege Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	struct priv_sub_structure *pss;
};

#endif /* TDBSAM2_H */
