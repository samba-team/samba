/* 
   Unix SMB/CIFS implementation.
   GUMS structures
   Copyright (C) Simo Sorce 2002
   
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

#ifndef _GUMS_H
#define _GUMS_H

#define GUMS_VERSION_MAJOR	0
#define GUMS_VERSION_MINOR	1
#define GUMS_OBJECT_VERSION	1
#define GUMS_PRIVILEGE_VERSION	1
#define GUMS_INTERFACE_VERSION	1

#define GUMS_OBJ_DOMAIN			0x10
#define GUMS_OBJ_NORMAL_USER		0x20
#define GUMS_OBJ_GROUP			0x30
#define GUMS_OBJ_ALIAS			0x31

/* define value types */
#define GUMS_SET_PRIMARY_GROUP		0x1
#define GUMS_SET_SEC_DESC		0x2

#define GUMS_SET_NAME			0x10
#define GUMS_SET_DESCRIPTION		0x11
#define GUMS_SET_FULL_NAME		0x12

/* user specific type values */
#define GUMS_SET_LOGON_TIME		0x20
#define GUMS_SET_LOGOFF_TIME		0x21
#define GUMS_SET_KICKOFF_TIME		0x23
#define GUMS_SET_PASS_LAST_SET_TIME	0x24
#define GUMS_SET_PASS_CAN_CHANGE_TIME	0x25
#define GUMS_SET_PASS_MUST_CHANGE_TIME	0x26


#define GUMS_SET_HOME_DIRECTORY		0x31
#define GUMS_SET_DRIVE			0x32
#define GUMS_SET_LOGON_SCRIPT		0x33
#define GUMS_SET_PROFILE_PATH		0x34
#define GUMS_SET_WORKSTATIONS		0x35
#define GUMS_SET_UNKNOWN_STRING		0x36
#define GUMS_SET_MUNGED_DIAL		0x37

#define GUMS_SET_LM_PASSWORD		0x40
#define GUMS_SET_NT_PASSWORD		0x41
#define GUMS_SET_PLAINTEXT_PASSWORD	0x42
#define GUMS_SET_UNKNOWN_3		0x43
#define GUMS_SET_LOGON_DIVS		0x44
#define GUMS_SET_HOURS_LEN		0x45
#define GUMS_SET_HOURS			0x46
#define GUMS_SET_BAD_PASSWORD_COUNT	0x47
#define GUMS_SET_LOGON_COUNT		0x48
#define GUMS_SET_UNKNOWN_6		0x49

#define GUMS_SET_MUST_CHANGE_PASS	0x50
#define GUMS_SET_CANNOT_CHANGE_PASS	0x51
#define GUMS_SET_PASS_NEVER_EXPIRE	0x52
#define GUMS_SET_ACCOUNT_DISABLED	0x53
#define GUMS_SET_ACCOUNT_LOCKOUT	0x54

/*group specific type values */
#define GUMS_ADD_SID_LIST		0x60
#define GUMS_DEL_SID_LIST		0x61
#define GUMS_SET_SID_LIST		0x62

GENSTRUCT struct gums_user
{
	DOM_SID *group_sid;		/* Primary Group SID */

	NTTIME logon_time;		/* logon time */
	NTTIME logoff_time;		/* logoff time */
	NTTIME kickoff_time;		/* kickoff time */
	NTTIME pass_last_set_time;	/* password last set time */
	NTTIME pass_can_change_time;	/* password can change time */
	NTTIME pass_must_change_time;	/* password must change time */

	char *full_name; _NULLTERM	/* user's full name string */
	char *home_dir; _NULLTERM	/* home directory string */
	char *dir_drive; _NULLTERM	/* home directory drive string */
	char *logon_script; _NULLTERM	/* logon script string */
	char *profile_path; _NULLTERM	/* profile path string */
	char *workstations; _NULLTERM	/* login from workstations string */
	char *unknown_str; _NULLTERM	/* don't know what this is, yet. */
	char *munged_dial; _NULLTERM	/* munged path name and dial-back tel number */

	DATA_BLOB lm_pw; 		/* .data is Null if no password */
	DATA_BLOB nt_pw; 		/* .data is Null if no password */

	uint16 acct_ctrl;		/* account type & status flags */
	uint16 logon_divs;		/* 168 - number of hours in a week */
	uint32 hours_len;		/* normally 21 bytes */
	uint8 *hours; _LEN(hours_len)	/* normally 21 bytes (depends on hours_len) */

	uint16 bad_password_count;	/* 0 */
	uint16 logon_count;		/* 0 */
	uint32 unknown_3;		/* 0x00ff ffff */
	uint32 unknown_6;		/* 0x0000 04ec */

};

GENSTRUCT struct gums_group
{
	uint32 count;			/* Number of SIDs */
	DOM_SID *members; _LEN(count)	/* SID array */

};

GENSTRUCT struct gums_domain
{
	uint32 next_rid;

};

GENSTRUCT struct gums_object
{
	TALLOC_CTX *mem_ctx;

	uint32 type;			/* Object Type */
	uint32 version;			/* Object Version */
	uint32 seq_num;			/* Object Sequence Number */

	SEC_DESC *sec_desc;		/* Security Descriptor */

	DOM_SID *sid;			/* Object Sid */
	char *name; _NULLTERM		/* Object Name - it should be in DOMAIN\NAME format */
	char *description; _NULLTERM	/* Object Description */

	struct gums_user *user;
	struct gums_group *group;
	struct gums_domain *domain;

};

GENSTRUCT struct gums_privilege
{
	TALLOC_CTX *mem_ctx;

	uint32 version;			/* Object Version */
	uint32 seq_num;			/* Object Sequence Number */

	char *name; _NULLTERM		/* Object Name */
	char *description; _NULLTERM	/* Object Description */

	LUID_ATTR *privilege;		/* Privilege Type */

	uint32 count;
	DOM_SID *members; _LEN(count)

};

typedef struct gums_user GUMS_USER;
typedef struct gums_group GUMS_GROUP;
typedef struct gums_domain GUMS_DOMAIN;
typedef struct gums_object GUMS_OBJECT;
typedef struct gums_privilege GUMS_PRIVILEGE;

typedef struct gums_data_set
{
	int type; /* GUMS_SET_xxx */
	void *data;

} GUMS_DATA_SET;

typedef struct gums_commit_set
{
	TALLOC_CTX *mem_ctx;

	uint32 type;			/* Object type */
	DOM_SID sid;			/* Object Sid */
	uint32 count;			/* number of changes */
	GUMS_DATA_SET *data;

} GUMS_COMMIT_SET;

typedef struct gums_priv_commit_set
{
	TALLOC_CTX *mem_ctx;

	uint32 type;			/* Object type */
	char *name;			/* Object Sid */
	uint32 count;			/* number of changes */
	GUMS_DATA_SET *data;

} GUMS_PRIV_COMMIT_SET;


typedef struct gums_functions
{
	/* module data */
	TALLOC_CTX *mem_ctx;
	char *name;
	void *private_data;
	void (*free_private_data)(void **);

	/* Generic object functions */

	NTSTATUS (*get_domain_sid) (DOM_SID *sid, const char* name);
	NTSTATUS (*set_domain_sid) (const DOM_SID *sid);

	NTSTATUS (*get_sequence_number) (void);

	NTSTATUS (*new_object) (DOM_SID *sid, const char *name, const int obj_type);
	NTSTATUS (*delete_object) (const DOM_SID *sid);

	NTSTATUS (*get_object_from_sid) (GUMS_OBJECT **object, const DOM_SID *sid, const int obj_type);
	NTSTATUS (*get_object_from_name) (GUMS_OBJECT **object, const char *domain, const char *name, const int obj_type);
	/* This function is used to get the list of all objects changed since b_time, it is
	   used to support PDC<->BDC synchronization */
	NTSTATUS (*get_updated_objects) (GUMS_OBJECT **objects, const NTTIME base_time);

	NTSTATUS (*enumerate_objects_start) (void **handle, const DOM_SID *sid, const int obj_type);
	NTSTATUS (*enumerate_objects_get_next) (GUMS_OBJECT **object, void *handle);
	NTSTATUS (*enumerate_objects_stop) (void *handle);

	/* This function MUST be used ONLY by PDC<->BDC replication code or recovery tools.
	   Never use this function to update an object in the database, use set_object_values() */
	NTSTATUS (*set_object) (GUMS_OBJECT *object);

	/* set object values function */
	NTSTATUS (*set_object_values) (DOM_SID *sid, uint32 count, GUMS_DATA_SET *data_set);

	/* Group related functions */
	NTSTATUS (*add_members_to_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*delete_members_from_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*enumerate_group_members) (DOM_SID **members, const DOM_SID *sid, const int type);

	NTSTATUS (*get_sid_groups) (DOM_SID **groups, const DOM_SID *sid);

	NTSTATUS (*lock_sid) (const DOM_SID *sid);
	NTSTATUS (*unlock_sid) (const DOM_SID *sid);

	/* privileges related functions */

	NTSTATUS (*get_privilege) (GUMS_OBJECT **object, const char *name);
	NTSTATUS (*add_members_to_privilege) (const char *name, const DOM_SID **members);
	NTSTATUS (*delete_members_from_privilege) (const char *name, const DOM_SID **members);
	NTSTATUS (*enumerate_privilege_members) (const char *name, DOM_SID **members);
	NTSTATUS (*get_sid_privileges) (const DOM_SID *sid, const char **privs);

	/* warning!: set_privilege will overwrite a prior existing privilege if such exist */
	NTSTATUS (*set_privilege) (GUMS_PRIVILEGE *priv);

} GUMS_FUNCTIONS;

typedef NTSTATUS (*gums_init_function)(
			struct gums_functions *,
			const char *);

struct gums_init_function_entry {

	const char *name;
	gums_init_function init_fn;
	struct gums_init_function_entry *prev, *next;
};

#endif /* _GUMS_H */
