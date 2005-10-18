/* 
   Unix SMB/CIFS implementation.

   Unixinfo definitions.

   Copyright (C) Volker Lendecke 2005

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

#ifndef _RPC_UNIXINFO_H
#define _RPC_UNIXINFO_H

#define UNIXINFO_SID_TO_UID	0x00
#define UNIXINFO_UID_TO_SID	0x01
#define UNIXINFO_SID_TO_GID	0x02
#define UNIXINFO_GID_TO_SID	0x03
#define UNIXINFO_GETPWUID		0x04

typedef struct unixinfo_q_sid_to_uid {
	DOM_SID sid;
} UNIXINFO_Q_SID_TO_UID;

typedef struct unixinfo_r_sid_to_uid {
	UINT64_S uid;
	NTSTATUS status;
} UNIXINFO_R_SID_TO_UID;

typedef struct unixinfo_q_uid_to_sid {
	UINT64_S uid;
} UNIXINFO_Q_UID_TO_SID;

typedef struct unixinfo_r_uid_to_sid {
	uint32 sidptr;
	DOM_SID sid;
	NTSTATUS status;
} UNIXINFO_R_UID_TO_SID;

typedef struct unixinfo_q_sid_to_gid {
	DOM_SID sid;
} UNIXINFO_Q_SID_TO_GID;

typedef struct unixinfo_r_sid_to_gid {
	UINT64_S gid;
	NTSTATUS status;
} UNIXINFO_R_SID_TO_GID;

typedef struct unixinfo_q_gid_to_sid {
	UINT64_S gid;
} UNIXINFO_Q_GID_TO_SID;

typedef struct unixinfo_r_gid_to_sid {
	uint32 sidptr;
	DOM_SID sid;
	NTSTATUS status;
} UNIXINFO_R_GID_TO_SID;

typedef struct unixinfo_q_getpwuid {
	uint32 count;
	UINT64_S *uid;
} UNIXINFO_Q_GETPWUID;

struct unixinfo_getpwuid {
	/* name, gid and gecos explicitly excluded, these values can be
	   retrieved via other means */
	NTSTATUS status;
	const char *homedir;
	const char *shell;
};

typedef struct unixinfo_r_getpwuid {
	uint32 count;
	struct unixinfo_getpwuid *info;
	NTSTATUS status;
} UNIXINFO_R_GETPWUID;

#endif  
/* 
   Unix SMB/CIFS implementation.

   Unixinfo definitions.

   Copyright (C) Volker Lendecke 2005

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

#ifndef _RPC_UNIXINFO_H
#define _RPC_UNIXINFO_H

#define UNIXINFO_SID_TO_UID	0x00
#define UNIXINFO_UID_TO_SID	0x01
#define UNIXINFO_SID_TO_GID	0x02
#define UNIXINFO_GID_TO_SID	0x03
#define UNIXINFO_GETPWUID		0x04

typedef struct unixinfo_q_sid_to_uid {
	DOM_SID sid;
} UNIXINFO_Q_SID_TO_UID;

typedef struct unixinfo_r_sid_to_uid {
	UINT64_S uid;
	NTSTATUS status;
} UNIXINFO_R_SID_TO_UID;

typedef struct unixinfo_q_uid_to_sid {
	UINT64_S uid;
} UNIXINFO_Q_UID_TO_SID;

typedef struct unixinfo_r_uid_to_sid {
	uint32 sidptr;
	DOM_SID sid;
	NTSTATUS status;
} UNIXINFO_R_UID_TO_SID;

typedef struct unixinfo_q_sid_to_gid {
	DOM_SID sid;
} UNIXINFO_Q_SID_TO_GID;

typedef struct unixinfo_r_sid_to_gid {
	UINT64_S gid;
	NTSTATUS status;
} UNIXINFO_R_SID_TO_GID;

typedef struct unixinfo_q_gid_to_sid {
	UINT64_S gid;
} UNIXINFO_Q_GID_TO_SID;

typedef struct unixinfo_r_gid_to_sid {
	uint32 sidptr;
	DOM_SID sid;
	NTSTATUS status;
} UNIXINFO_R_GID_TO_SID;

typedef struct unixinfo_q_getpwuid {
	UINT64_S uid;
} UNIXINFO_Q_GETPWUID;

typedef struct unixinfo_r_getpwuid {
	/* name and gid explicitly excluded, these values can be retrieved via
	   other means */
	const char *gecos;
	const char *homedir;
	const char *shell;
	NTSTATUS status;
} UNIXINFO_R_GETPWUID;

#endif  
