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

GENSTRUCT struct tdbsam2_domain_data {
	uint32 xcounter;		/* counter to be updated at any change */

	SEC_DESC *sec_desc;		/* Security Descriptor */
	DOM_SID *user_sid;		/* The User SID */
	char *name; _NULLTERM		/* NT User Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */
};

GENSTRUCT struct tdbsam2_user_data {
	uint32 xcounter;		/* counter to be updated at any change */

	SEC_DESC *sec_desc;		/* Security Descriptor */
	DOM_SID *user_sid;		/* The User SID */
	char *name; _NULLTERM		/* NT User Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	DOM_SID *group_sid;		/* The Primary Group SID */

	NTTIME *logon_time;
	NTTIME *logoff_time;
	NTTIME *kickoff_time;
	NTTIME *pass_last_set_time;
	NTTIME *pass_can_change_time;
	NTTIME *pass_must_change_time;
	
	char *full_name; _NULLTERM	/* The Full Name */
	char *home_dir; _NULLTERM	/* Home Directory */
	char *dir_drive; _NULLTERM	/* Drive Letter the home should be mapped to */
	char *logon_script; _NULLTERM	/* Logon script path */
	char *profile_path; _NULLTERM	/* Profile is stored here */
	char *workstations; _NULLTERM	/* List of Workstation names the user is allowed to LogIn */
	char *unknown_str; _NULLTERM	/* Guess ... Unknown */
	char *munged_dial; _NULLTERM	/* Callback Number */

	/* passwords are 16 byte leght, pointer is null if no password */
	uint8 *lm_pw_ptr; _LEN(16)	/* Lanman hashed password */
	uint8 *nt_pw_ptr; _LEN(16)	/* NT hashed password */

	uint16 logon_divs;		/* 168 - num of hours in a week */
	uint32 hours_len;		/* normally 21 */
	uint8 *hours; _LEN(hours_len)	/* normally 21 bytes (depends on hours_len) */

	uint32 unknown_3;		/* 0x00ff ffff */
	uint32 unknown_5;		/* 0x0002 0000 */
	uint32 unknown_6;		/* 0x0000 04ec */
};	

GENSTRUCT struct tdbsam2_group_data {
	uint32 xcounter;		/* counter to be updated at any change */

	SEC_DESC *sec_desc;		/* Security Descriptor */
	DOM_SID *group_sid;		/* The Group SID */
	char *name; _NULLTERM		/* NT User Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	uint32 count;			/* number of sids */
	DOM_SID **members; _LEN(count)	/* SID array */
};

GENSTRUCT struct tdbsam2_privilege_data {
	uint32 xcounter;		/* counter to be updated at any change */

	LUID_ATTR *privilege;		/* Privilege */
	char *name; _NULLTERM		/* NT User Name */
	char *description; _NULLTERM	/* Descritpion (Gecos) */

	uint32 count;			/* number of sids */
	DOM_SID **members; _LEN(count)	/* SID array */
};

