/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-1997,
   Copyright (C) Gerald (Jerry) Carter        2004
   
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

#ifndef _RPC_SVCCTL_H /* _RPC_SVCCTL_H */
#define _RPC_SVCCTL_H 


/* svcctl pipe */

#define SVCCTL_CLOSE_SERVICE		0x00
#define SVCCTL_OPEN_SCMANAGER		0x0f
#define SVCCTL_OPEN_SERVICE		0x10
#define SVCCTL_START_SERVICE		0x13
#define SVCCTL_GET_DISPLAY_NAME		0x14


/* rpc structures */

typedef struct _svcctl_q_close_svc {
	POLICY_HND handle;
} SVCCTL_Q_CLOSE_SERVICE;

typedef struct _svcctl_r_close_svc {
	NTSTATUS status;
} SVCCTL_R_CLOSE_SERVICE;

typedef struct _svcctl_q_open_scmanager {
	uint32 ptr_srv;
	UNISTR2 servername;
	uint32 ptr_db;
	UNISTR2 database; 
	uint32 access_mask;
} SVCCTL_Q_OPEN_SCMANAGER;

typedef struct _svcctl_r_open_scmanager {
	POLICY_HND handle;
	NTSTATUS status;
} SVCCTL_R_OPEN_SCMANAGER;

typedef struct _svcctl_q_get_display_name {
	POLICY_HND handle;
	UNISTR2 servicename;
	uint32  display_name_len;
} SVCCTL_Q_GET_DISPLAY_NAME;

typedef struct _svcctl_r_get_display_name {
	UNISTR2 displayname;
	uint32 display_name_len;
	NTSTATUS status;
} SVCCTL_R_GET_DISPLAY_NAME;

typedef struct _svcctl_q_open_service {
	POLICY_HND handle;
	UNISTR2 servicename;
	uint32 access_mask;
} SVCCTL_Q_OPEN_SERVICE;

typedef struct _svcctl_r_open_service {
	POLICY_HND handle;
	NTSTATUS status;
} SVCCTL_R_OPEN_SERVICE;


#endif /* _RPC_SVCCTL_H */

