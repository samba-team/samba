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
#define SVC_OPEN_SC_MAN       0x0f
#define SVC_ENUM_SVCS_STATUS  0x0e
#define SVC_QUERY_SVC_CONFIG  0x11
#define SVC_QUERY_DISP_NAME   0x14
#define SVC_CHANGE_SVC_CONFIG 0x0b
#define SVC_OPEN_SERVICE      0x10
#define SVC_START_SERVICE     0x13
#define SVC_STOP_SERVICE      0x01
#define SVC_CLOSE             0x00

/* SVC_Q_START_SERVICE */
#define MAX_SVC_ARGS 		10
/* SVC_Q_ENUM_SVCS_STATUS */
#define MAX_SERVICES		50

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

/* SVC_Q_OPEN_SERVICE */
typedef struct q_svc_open_service_info
{
	POLICY_HND scman_pol;
	UNISTR2 uni_svc_name;        /* unicode service name */
	uint32 des_access;            /* 0x8000 0001 */

} SVC_Q_OPEN_SERVICE;

/* SVC_R_OPEN_SERVICE */
typedef struct r_svc_open_service_info
{
	POLICY_HND pol;
	uint32 status;             /* return status */

} SVC_R_OPEN_SERVICE;

/* SVC_Q_STOP_SERVICE */
typedef struct q_svc_stop_service_info
{
	POLICY_HND pol;

	uint32 unknown;

} SVC_Q_STOP_SERVICE;

/* SVC_R_STOP_SERVICE */
typedef struct r_svc_stop_service_info
{
	uint32 unknown0; /* 0x00000020 */
	uint32 unknown1; /* 0x00000001 */
	uint32 unknown2; /* 0x00000001 */
	uint32 unknown3; /* 0x00000000 */
	uint32 unknown4; /* 0x00000000 */
	uint32 unknown5; /* 0x00000000 */
	uint32 unknown6; /* 0x00000000 */
	uint32 status;

} SVC_R_STOP_SERVICE;

/* SVC_Q_START_SERVICE */
typedef struct q_svc_start_service_info
{
	POLICY_HND pol;

	uint32 argc;
	uint32 ptr_args;
	uint32 argc2;
	uint32 ptr_argv[MAX_SVC_ARGS];
	UNISTR2 argv[MAX_SVC_ARGS];

} SVC_Q_START_SERVICE;

/* SVC_R_START_SERVICE */
typedef struct r_svc_start_service_info
{
	uint32 status;

} SVC_R_START_SERVICE;


/* QUERY_SERVICE_CONFIG */
typedef struct query_service_config_info
{
	uint32 service_type;
	uint32 start_type;
	uint32 error_control;
	uint32 ptr_bin_path_name; 
	uint32 ptr_load_order_grp; 
	uint32 tag_id;
	uint32 ptr_dependencies;
	uint32 ptr_service_start_name;
	uint32 ptr_display_name;

	UNISTR2 uni_bin_path_name;
	UNISTR2 uni_load_order_grp;
	UNISTR2 uni_dependencies;
	UNISTR2 uni_service_start_name;
	UNISTR2 uni_display_name;

} QUERY_SERVICE_CONFIG;

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

/* ENUM_SRVC_STATUS */
typedef struct enum_svc_status_info
{
	UNISTR uni_srvc_name;
	UNISTR uni_disp_name;
	SVC_STATUS status;

} ENUM_SRVC_STATUS;

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
	ENUM_SRVC_STATUS *svcs;
	uint32 more_buf_size;
	uint32 num_svcs;
	ENUM_HND resume_hnd; /* resume handle */
	uint32 dos_status; /* return status, DOS error code (wow!) */

} SVC_R_ENUM_SVCS_STATUS;


/* SVC_Q_QUERY_SVC_CONFIG */
typedef struct q_svc_query_svc_cfg_info
{
	POLICY_HND pol;
	uint32 buf_size;

} SVC_Q_QUERY_SVC_CONFIG;


/* SVC_R_QUERY_SVC_CONFIG */
typedef struct r_svc_query_svc_cfg_info
{
	QUERY_SERVICE_CONFIG *cfg;
	uint32 buf_size;
	uint32 status;             /* return status */

} SVC_R_QUERY_SVC_CONFIG;


/* SVC_Q_QUERY_DISP_NAME */
typedef struct q_svc_query_disp_name_info
{
	POLICY_HND scman_pol;
	UNISTR2 uni_svc_name;
	uint32 buf_size;

} SVC_Q_QUERY_DISP_NAME;


/* SVC_R_QUERY_DISP_NAME */
typedef struct r_svc_query_disp_name_info
{
	UNISTR2 uni_disp_name;
	uint32 buf_size;
	uint32 status;

} SVC_R_QUERY_DISP_NAME;


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

/* SVC_Q_CHANGE_SVC_CONFIG */
typedef struct q_svc_change_svc_cfg_info
{
	POLICY_HND pol;
	uint32 service_type;
	uint32 start_type;
	uint32 unknown_0;
	uint32 error_control;

	uint32 ptr_bin_path_name; 
	UNISTR2 uni_bin_path_name;

	uint32 ptr_load_order_grp; 
	UNISTR2 uni_load_order_grp;

	uint32 tag_id;

	uint32 ptr_dependencies;
	UNISTR2 uni_dependencies;

	uint32 ptr_service_start_name;
	UNISTR2 uni_service_start_name;

	uint32 ptr_password;
	STRING2 str_password;

	uint32 ptr_display_name;
	UNISTR2 uni_display_name;

} SVC_Q_CHANGE_SVC_CONFIG;

/* SVC_R_CHANGE_SVC_CONFIG */
typedef struct r_svc_change_svc_cfg_info
{
	uint32 unknown_0;             /* */
	uint32 status;             /* return status */

} SVC_R_CHANGE_SVC_CONFIG;


#endif /* _RPC_SVCCTL_H */

