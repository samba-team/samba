/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Nigel Williams 2001
   Copyright (C) Gerald (Jerry) Carter 2006.

   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _RPC_SRVSVC_H /* _RPC_SRVSVC_H */
#define _RPC_SRVSVC_H 

/* srvsvc pipe */
#define SRV_NET_CONN_ENUM          0x08
#define SRV_NET_FILE_ENUM          0x09
#define SRV_NET_FILE_CLOSE         0x0b
#define SRV_NET_SESS_ENUM          0x0c
#define SRV_NET_SESS_DEL           0x0d
#define SRV_NET_SHARE_ADD          0x0e
#define SRV_NET_SHARE_ENUM_ALL     0x0f
#define SRV_NET_SHARE_GET_INFO     0x10
#define SRV_NET_SHARE_SET_INFO     0x11
#define SRV_NET_SHARE_DEL          0x12
#define SRV_NET_SHARE_DEL_STICKY   0x13
#define SRV_NET_SRV_GET_INFO       0x15
#define SRV_NET_SRV_SET_INFO       0x16
#define SRV_NET_DISK_ENUM          0x17
#define SRV_NET_REMOTE_TOD         0x1c
#define SRV_NET_NAME_VALIDATE      0x21
#define SRV_NET_SHARE_ENUM         0x24
#define SRV_NET_FILE_QUERY_SECDESC 0x27
#define SRV_NET_FILE_SET_SECDESC   0x28

#define MAX_SERVER_DISK_ENTRIES 15

/***************************/

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */

#define MAX_SESS_ENTRIES 32

typedef struct {
	UNISTR2 *sharename;
} SESS_INFO_0;

typedef struct {
	uint32 num_entries_read;
	uint32 ptr_sess_info;
	uint32 num_entries_read2;
	SESS_INFO_0 info_0[MAX_SESS_ENTRIES];
} SRV_SESS_INFO_0;

typedef struct {
	UNISTR2 *sharename;
	UNISTR2 *username;
	uint32 num_opens;
	uint32 open_time;
	uint32 idle_time;
	uint32 user_flags;
} SESS_INFO_1;

typedef struct {
	uint32 num_entries_read;
	uint32 ptr_sess_info;
	uint32 num_entries_read2;
	SESS_INFO_1 info_1[MAX_SESS_ENTRIES];
} SRV_SESS_INFO_1;

typedef struct {
	uint32 switch_value;
	uint32 ptr_sess_ctr;
	union {
		SRV_SESS_INFO_0 info0; 
		SRV_SESS_INFO_1 info1; 
	} sess;

} SRV_SESS_INFO_CTR;

typedef struct {
	UNISTR2 *servername;
	UNISTR2 *qualifier;
	UNISTR2 *username;
	uint32 sess_level;
	SRV_SESS_INFO_CTR *ctr;
	uint32 preferred_len;
	ENUM_HND enum_hnd;
} SRV_Q_NET_SESS_ENUM;

typedef struct {
	uint32 sess_level; 
	SRV_SESS_INFO_CTR *ctr;
	uint32 total_entries;
	ENUM_HND enum_hnd;
	WERROR status;
} SRV_R_NET_SESS_ENUM;

/***************************/

/* CONN_INFO_0 (pointers to level 0 connection info strings) */
typedef struct ptr_conn_info0
{
	uint32 id; /* connection id. */

} CONN_INFO_0;

/* oops - this is going to take up a *massive* amount of stack. */
/* the UNISTR2s already have 1024 uint16 chars in them... */
#define MAX_CONN_ENTRIES 32

/* SRV_CONN_INFO_0 */
typedef struct srv_conn_info_0_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_conn_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	CONN_INFO_0     info_0    [MAX_CONN_ENTRIES]; /* connection entry pointers */

} SRV_CONN_INFO_0;

/* CONN_INFO_1 (pointers to level 1 connection info strings) */
typedef struct ptr_conn_info1
{
	uint32 id;   /* connection id */
	uint32 type; /* 0x3 */
	uint32 num_opens;
	uint32 num_users;
	uint32 open_time;

	uint32 ptr_usr_name; /* pointer to user name. */
	uint32 ptr_net_name; /* pointer to network name (e.g IPC$). */

} CONN_INFO_1;

/* CONN_INFO_1_STR (level 1 connection info strings) */
typedef struct str_conn_info1
{
	UNISTR2 uni_usr_name; /* unicode string of user */
	UNISTR2 uni_net_name; /* unicode string of name */

} CONN_INFO_1_STR;

/* SRV_CONN_INFO_1 */
typedef struct srv_conn_info_1_info
{
	uint32 num_entries_read;                     /* EntriesRead */
	uint32 ptr_conn_info;                       /* Buffer */
	uint32 num_entries_read2;                    /* EntriesRead */

	CONN_INFO_1     info_1    [MAX_CONN_ENTRIES]; /* connection entry pointers */
	CONN_INFO_1_STR info_1_str[MAX_CONN_ENTRIES]; /* connection entry strings */

} SRV_CONN_INFO_1;

/* SRV_CONN_INFO_CTR */
typedef struct srv_conn_info_ctr_info
{
	uint32 switch_value;         /* switch value */
	uint32 ptr_conn_ctr;       /* pointer to conn info union */
	union
    {
		SRV_CONN_INFO_0 info0; /* connection info level 0 */
		SRV_CONN_INFO_1 info1; /* connection info level 1 */

    } conn;

} SRV_CONN_INFO_CTR;


/* SRV_Q_NET_CONN_ENUM */
typedef struct q_net_conn_enum_info
{
	uint32 ptr_srv_name;         /* pointer (to server name) */
	UNISTR2 uni_srv_name;        /* server name "\\server" */

	uint32 ptr_qual_name;         /* pointer (to qualifier name) */
	UNISTR2 uni_qual_name;        /* qualifier name "\\qualifier" */

	uint32 conn_level;          /* connection level */

	SRV_CONN_INFO_CTR *ctr;

	uint32 preferred_len;        /* preferred maximum length (0xffff ffff) */
	ENUM_HND enum_hnd;

} SRV_Q_NET_CONN_ENUM;

/* SRV_R_NET_CONN_ENUM */
typedef struct r_net_conn_enum_info
{
	uint32 conn_level;          /* share level */

	SRV_CONN_INFO_CTR *ctr;

	uint32 total_entries;                    /* total number of entries */
	ENUM_HND enum_hnd;

	WERROR status;               /* return status */

} SRV_R_NET_CONN_ENUM;

/***************************/

typedef struct {
	uint32 id;            /* file index */
	uint32 perms;         /* file permissions. don't know what format */
	uint32 num_locks;     /* file locks */
	UNISTR2 *path;        /* file name */
	UNISTR2 *user;        /* file owner */
} FILE_INFO_3;

typedef struct {
	uint32 level;                /* switch value */
	uint32 ptr_file_info;        /* pointer to file info union */

	uint32 num_entries;
	uint32 ptr_entries;
	uint32 num_entries2;
	union {
		FILE_INFO_3 *info3;
	} file;

} SRV_FILE_INFO_CTR;

typedef struct {
	UNISTR2 *servername;
	UNISTR2 *qualifier;
	UNISTR2 *username;
	uint32 level;
	SRV_FILE_INFO_CTR ctr;
	uint32 preferred_len;     /* preferred maximum length (0xffff ffff) */
	ENUM_HND enum_hnd;
} SRV_Q_NET_FILE_ENUM;

typedef struct {
	uint32 level;   
	SRV_FILE_INFO_CTR ctr;
	uint32 total_entries;
	ENUM_HND enum_hnd;
	WERROR status;      
} SRV_R_NET_FILE_ENUM;

#endif /* _RPC_SRVSVC_H */
