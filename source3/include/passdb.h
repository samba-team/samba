/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   passdb structures and parameters
   Copyright (C) Gerald Carter 2001
   Copyright (C) Luke Kenneth Casson Leighton 1998 - 2000
   
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

#ifndef _PASSDB_H
#define _PASSDB_H

/*
 * This next constant specifies the version number of the VFS interface
 * this smbd will load. Increment this if *ANY* changes are made to the
 * passdb_ops below.
 */

#define SMB_PASSDB_MAJOR_VERSION 1
#define SMB_PASSDB_MINOR_VERSION 0

/* passdb operations structure */
struct passdb_ops {

	/* Iteration  Functions*/
	BOOL (*setsampwent) (BOOL update);
	void (*endsampwent) (void);
	SAM_ACCOUNT* (*getsampwent) (void);

	/* Lookup Functions */
	SAM_ACCOUNT* (*getsampwuid) (uid_t uid);
	SAM_ACCOUNT* (*getsampwrid) (uint32 rid);
	SAM_ACOCUNT* (*getsampwnam) (char* username);

	/* Modify the SAM database */
	BOOL (*update_sam_account) (SAM_ACCOUNT* sampass, BOOL override);
	BOOL (*delete_sam_account) (char* username);
	BOOL (*add_sam_account) (SAM_ACCOUNT* sampass);

	/* authenticate a user */
	SAM_ACCOUNT* (*logon_user) (char* username, char* domain, char* lm_pw,
		int lm_pw_len, char* nt_pw, int nt_pw_len, char* clear_pass);
};



#define SMB_UIDMAP_MAJOR_VERSION 1
#define SMB_UIDMAP_MINOR_VERSION 0

typedef enum sid_type {SID_USER_TYPE, SID_GROUP_TYPE} SMB_SID_T

/* uid mapping structure */
struct uidmap_ops {

	/* From NT to UNIX */
	int (*sid_to_id) (DOM_SID* sid, SMB_SID_T type);

	/* From UNIX to NT */
	DOM_SID* (*id_to_sid) (int id, SMB_SID_T type);

};


#endif /* _PASSDB_H */
