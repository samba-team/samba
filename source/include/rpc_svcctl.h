/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-1997,
   Copyright (C) Gerald (Jerry) Carter        2005
   
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
#define SVCCTL_QUERY_STATUS		0x06
#define SVCCTL_ENUM_SERVICES_STATUS	0x0e
#define SVCCTL_OPEN_SCMANAGER		0x0f
#define SVCCTL_OPEN_SERVICE		0x10
#define SVCCTL_QUERY_SERVICE_CONFIG	0x11
#define SVCCTL_START_SERVICE		0x13
#define SVCCTL_GET_DISPLAY_NAME		0x14


/* rpc structures */

typedef struct {
	POLICY_HND handle;
} SVCCTL_Q_CLOSE_SERVICE;

typedef struct {
	WERROR status;
} SVCCTL_R_CLOSE_SERVICE;

typedef struct {
	uint32 ptr_srv;
	UNISTR2 servername;
	uint32 ptr_db;
	UNISTR2 database; 
	uint32 access_mask;
} SVCCTL_Q_OPEN_SCMANAGER;

typedef struct {
	POLICY_HND handle;
	WERROR status;
} SVCCTL_R_OPEN_SCMANAGER;

typedef struct {
	POLICY_HND handle;
	UNISTR2 servicename;
	uint32  display_name_len;
} SVCCTL_Q_GET_DISPLAY_NAME;

typedef struct {
	UNISTR2 displayname;
	uint32 display_name_len;
	WERROR status;
} SVCCTL_R_GET_DISPLAY_NAME;

typedef struct {
	POLICY_HND handle;
	UNISTR2 servicename;
	uint32 access_mask;
} SVCCTL_Q_OPEN_SERVICE;

typedef struct {
	POLICY_HND handle;
	WERROR status;
} SVCCTL_R_OPEN_SERVICE;

typedef struct {
	POLICY_HND handle;
	uint32 parmcount;
	UNISTR2_ARRAY parameters;
} SVCCTL_Q_START_SERVICE;

typedef struct {
	WERROR status;
} SVCCTL_R_START_SERVICE;

typedef struct {
	uint32 type;
	uint32 state;
	uint32 controls_accepted;
	uint32 win32_exit_code;
	uint32 service_exit_code;
	uint32 check_point;
	uint32 wait_hint;
} SERVICE_STATUS;

typedef struct {
	POLICY_HND handle;
} SVCCTL_Q_QUERY_STATUS;

typedef struct {
	SERVICE_STATUS svc_status;
	WERROR status;
} SVCCTL_R_QUERY_STATUS;

typedef struct {
	POLICY_HND handle;
	uint32 type;
	uint32 state;
	uint32 buffer_size;
	uint32 resume_ptr;
	uint32 resume;
} SVCCTL_Q_ENUM_SERVICES_STATUS;

typedef struct {
	uint32 buffer_size;
	uint8 *buffer;
	uint32 needed;
	uint32 returned;
	uint32 resume_ptr;
	uint32 resume;
	WERROR status;
} SVCCTL_R_ENUM_SERVICES_STATUS;

#endif /* _RPC_SVCCTL_H */

