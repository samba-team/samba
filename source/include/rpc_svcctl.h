/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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
#define SVC_OPEN_SC_MAN      0x0f
#define SVC_ENUM_SVCS_STATUS 0x0e
#define SVC_CLOSE            0x00


/* SVC_Q_OPEN_SC_MAN */
typedef struct q_svc_open_sc_man_info
{
	uint32 ptr_srv_name;         /* pointer (to server name?) */
	UNISTR2 uni_srv_name;        /* unicode server name starting with '\\' */

	uint32 ptr_db_name;         /* pointer (to database name?) */
	UNISTR2 uni_db_name;        /* unicode database name */

	uint32 des_access;            /* 0x80000004 - SC_MANAGER_xxxx */

} SVC_Q_OPEN_SC_MAN;

/* SVC_R_OPEN_SC_MAN */
typedef struct r_svc_open_sc_man_info
{
	POLICY_HND pol;
	uint32 status;             /* return status */

} SVC_R_OPEN_SC_MAN;

/* SVC_STATUS */
typedef struct svc_status_info
{
	uint32 svc_type;
	uint32 current_state;
	uint32 controls_accepted;
	uint32 win32_exit_code;
	uint32 svc_specific_exit_code;
	uint32 check_point;
	uint32 wait_hint;

} SVC_STATUS;

/* ENUM_SVC_STATUS */
typedef struct enum_svc_status_info
{
	UNISTR uni_srvc_name;
	UNISTR uni_disp_name;
	SVC_STATUS status;

} ENUM_SVC_STATUS;

/* SVC_Q_ENUM_SVCS_STATUS */
typedef struct q_svc_enum_svcs_status_info
{
	POLICY_HND pol;
	uint32 service_type; /* 0x00000030 - win32 | 0x0000000b - driver */
	uint32 service_state; /* 0x00000003 - state_all */
	uint32 buf_size; /* max service buffer size */
	ENUM_HND resume_hnd; /* resume handle */

} SVC_Q_ENUM_SVCS_STATUS;

/* SVC_R_ENUM_SVCS_STATUS */
typedef struct r_svc_enum_svcs_status_info
{
	uint32 buf_size; /* service buffer size */
	ENUM_SVC_STATUS *svcs;
	uint32 status;             /* return status */

} SVC_R_ENUM_SVCS_STATUS;


/* SVC_Q_CLOSE */
typedef struct q_svc_close_info
{
	POLICY_HND pol;

} SVC_Q_CLOSE;



/* SVC_R_CLOSE */
typedef struct r_svc_close_info
{
	POLICY_HND pol;
	uint32 status;             /* return status */

} SVC_R_CLOSE;


#endif /* _RPC_SVCCTL_H */

