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

#define GUMS_VERSION_MAJOR 0
#define GUMS_VERSION_MINOR 1
#define GUMS_OBJECT_VERSION	1

#define GUMS_OBJ_DOMAIN			1
#define GUMS_OBJ_NORMAL_USER		2
#define GUMS_OBJ_GROUP			3
#define GUMS_OBJ_ALIAS			4
#define GUMS_OBJ_WORKSTATION_TRUST	5
#define GUMS_OBJ_SERVER_TRUST		6
#define GUMS_OBJ_DOMAIN_TRUST		7

typedef struct gums_user
{
	DOM_SID *group_sid;		/* Primary Group SID */

	NTTIME logon_time;		/* logon time */
	NTTIME logoff_time;		/* logoff time */
	NTTIME kickoff_time;		/* kickoff time */
	NTTIME pass_last_set_time;	/* password last set time */
	NTTIME pass_can_change_time;	/* password can change time */
	NTTIME pass_must_change_time;	/* password must change time */

	char *full_name;		/* user's full name string */
	char *home_dir;			/* home directory string */
	char *dir_drive;		/* home directory drive string */
	char *logon_script;		/* logon script string */
	char *profile_path;		/* profile path string */
	char *workstations;		/* login from workstations string */
	char *unknown_str;		/* don't know what this is, yet. */
	char *munged_dial;		/* munged path name and dial-back tel number */
		
	DATA_BLOB lm_pw; 		/* .data is Null if no password */
	DATA_BLOB nt_pw; 		/* .data is Null if no password */
		
	uint32 unknown_3;		/* 0x00ff ffff */
		
	uint16 logon_divs;		/* 168 - number of hours in a week */
	uint32 hours_len;		/* normally 21 bytes */
	uint8 *hours;
		
	uint32 unknown_5;		/* 0x0002 0000 */
	uint32 unknown_6;		/* 0x0000 04ec */

} GUMS_USER;

typedef struct gums_group
{
	uint32 count;			/* Number of SIDs */
	DOM_SID **members;		/* SID array */

} GUMS_GROUP;

union gums_obj_p {
	gums_user *user;
	gums_group *group;
}

typedef struct gums_object
{
	TALLOC_CTX *mem_ctx;

	uint32 type;			/* Object Type */
	uint32 version;			/* Object Version */
	uint32 seq_num;			/* Object Sequence Number */

	SEC_DESC *sec_desc;		/* Security Descriptor */

	DOM_SID *sid;			/* Object Sid */
	char *name;			/* Object Name */
	char *description;		/* Object Description */

	union gums_obj_p data;		/* Object Specific data */

} GUMS_OBJECT;

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
	GUMS_DATA_SET **data;
} GUMS_COMMIT_SET;

typedef struct gums_privilege
{
	TALLOC_CTX *mem_ctx;

	uint32 type;			/* Object Type */
	uint32 version;			/* Object Version */
	uint32 seq_num;			/* Object Sequence Number */

	LUID_ATTR *privilege;		/* Privilege Type */
	char *name;			/* Object Name */
	char *description;		/* Object Description */

	uint32 count;
	DOM_SID **members;

} GUMS_PRIVILEGE;


typedef struct gums_functions
{
	/* Generic object functions */

	NTSTATUS (*get_domain_sid) (DOM_SID **sid, const char* name);
	NTSTATUS (*set_domain_sid) (const DOM_SID *sid);

	NTSTATUS (*get_sequence_number) (void);

	NTSTATUS (*new_object) (DOM_SID **sid, const char *name, const int obj_type);
	NTSTATUS (*delete_object) (const DOM_SID *sid);

	NTSTATUS (*get_object_from_sid) (GUMS_OBJECT **object, const DOM_SID *sid, const int obj_type);
	NTSTATUS (*get_sid_from_name) (GUMS_OBJECT **object, const char *name);
	/* This function is used to get the list of all objects changed since b_time, it is
	   used to support PDC<->BDC synchronization */
	NTSTATUS (*get_updated_objects) (GUMS_OBJECT **objects, const NTTIME base_time);

	NTSTATUS (*enumerate_objects_start) (void *handle, const DOM_SID *sid, const int obj_type);
	NTSTATUS (*enumerate_objects_get_next) (GUMS_OBJECT **object, void *handle);
	NTSTATUS (*enumerate_objects_stop) (void *handle);

	/* This function MUST be used ONLY by PDC<->BDC replication code or recovery tools.
	   Never use this function to update an object in the database, use set_object_values() */
	NTSTATUS (*set_object) (const GUMS_OBJECT *object);

	/* set object values function */
	NTSTATUS (*set_object_values) (DOM_SID *sid, uint32 count, GUMS_DATA_SET *data_set);

	/* Group related functions */
	NTSTATUS (*add_memberss_to_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*delete_members_from_group) (const DOM_SID *group, const DOM_SID **members);
	NTSTATUS (*enumerate_group_members) (DOM_SID **members, const DOM_SID *sid, const int type);

	NTSTATUS (*get_sid_groups) (DOM_SID **groups, const DOM_SID *sid);

	NTSTATUS (*lock_sid) (const DOM_SID *sid);
	NTSTATUS (*unlock_sid) (const DOM_SID *sid);

	/* privileges related functions */

	NTSTATUS (*add_members_to_privilege) (const LUID_ATTR *priv, const DOM_SID **members);
	NTSTATUS (*delete_members_from_privilege) (const LUID_ATTR *priv, const DOM_SID **members);
	NTSTATUS (*enumerate_privilege_members) (DOM_SID **members, const LUID_ATTR *priv);
	NTSTATUS (*get_sid_privileges) (DOM_SID **privs, const DOM_SID *sid);
	/* warning!: set_privilege will overwrite a prior existing privilege if such exist */
	NTSTATUS (*set_privilege) (GUMS_PRIVILEGE *priv);

} GUMS_FUNCTIONS;

/* define value types */

#define GUMS_SET_PRIMARY_GROUP		1
#define GUMS_SET_SEC_DESC		2

/* user specific type values */
#define GUMS_SET_LOGON_TIME		10  /* keep NTTIME consecutive */
#define GUMS_SET_LOGOFF_TIME		11 /* too ease checking */
#define GUMS_SET_KICKOFF_TIME		13
#define GUMS_SET_PASS_LAST_SET_TIME	14
#define GUMS_SET_PASS_CAN_CHANGE_TIME	15
#define GUMS_SET_PASS_MUST_CHANGE_TIME	16 /* NTTIME end */

#define GUMS_SET_NAME			20 /* keep strings consecutive */
#define GUMS_SET_DESCRIPTION		21 /* too ease checking */
#define GUMS_SET_FULL_NAME		22
#define GUMS_SET_HOME_DIRECTORY		23
#define GUMS_SET_DRIVE			24
#define GUMS_SET_LOGON_SCRIPT		25
#define GUMS_SET_PROFILE_PATH		26
#define GUMS_SET_WORKSTATIONS		27
#define GUMS_SET_UNKNOWN_STRING		28
#define GUMS_SET_MUNGED_DIAL		29 /* strings end */

#define GUMS_SET_LM_PASSWORD		40
#define GUMS_SET_NT_PASSWORD		41
#define GUMS_SET_PLAINTEXT_PASSWORD	42
#define GUMS_SET_UNKNOWN_3		43
#define GUMS_SET_LOGON_DIVS		44
#define GUMS_SET_HOURS_LEN		45
#define GUMS_SET_HOURS			46
#define GUMS_SET_UNKNOWN_5		47
#define GUMS_SET_UNKNOWN_6		48

#define GUMS_SET_MUST_CHANGE_PASS	50
#define GUMS_SET_CANNOT_CHANGE_PASS	51
#define GUMS_SET_PASS_NEVER_EXPIRE	52
#define GUMS_SET_ACCOUNT_DISABLED	53
#define GUMS_SET_ACCOUNT_LOCKOUT	54

/*group specific type values */
#define GUMS_ADD_SID_LIST		60
#define GUMS_DEL_SID_LIST		61
#define GUMS_SET_SID_LIST		62

#endif /* _GUMS_H */
