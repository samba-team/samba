/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Simo Sorce 2003
   
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

#ifndef PRIVILEGES_H
#define PRIVILEGES_H

#define PRIV_ALL_INDEX		30

#define SE_NONE				0
#define SE_ASSIGN_PRIMARY_TOKEN		1
#define SE_CREATE_TOKEN			2
#define SE_LOCK_MEMORY			3
#define SE_INCREASE_QUOTA		4
#define SE_UNSOLICITED_INPUT		5
#define SE_MACHINE_ACCOUNT		6
#define SE_TCB				7
#define SE_SECURITY			8
#define SE_TAKE_OWNERSHIP		9
#define SE_LOAD_DRIVER			10
#define SE_SYSTEM_PROFILE		11
#define SE_SYSTEM_TIME			12
#define SE_PROF_SINGLE_PROCESS		13
#define SE_INC_BASE_PRIORITY		14
#define SE_CREATE_PAGEFILE		15
#define SE_CREATE_PERMANENT		16
#define SE_BACKUP			17
#define SE_RESTORE			18
#define SE_SHUTDOWN			19
#define SE_DEBUG			20
#define SE_AUDIT			21
#define SE_SYSTEM_ENVIRONMENT		22
#define SE_CHANGE_NOTIFY		23
#define SE_REMOTE_SHUTDOWN		24
#define SE_UNDOCK			25
#define SE_SYNC_AGENT			26
#define SE_ENABLE_DELEGATION		27
#define SE_PRINT_OPERATOR		28
#define SE_ADD_USERS			29
#define SE_ALL_PRIVS			0xffff

#define PR_NONE                0x0000
#define PR_LOG_ON_LOCALLY      0x0001
#define PR_ACCESS_FROM_NETWORK 0x0002
#define PR_LOG_ON_BATCH_JOB    0x0004
#define PR_LOG_ON_SERVICE      0x0010

#ifndef _BOOL
typedef int BOOL;
#define _BOOL       /* So we don't typedef BOOL again in vfs.h */
#endif

typedef struct LUID
{
	uint32 low;
	uint32 high;
} LUID;

typedef struct LUID_ATTR
{
	LUID luid;
	uint32 attr;
} LUID_ATTR;

typedef struct privilege_set
{
	TALLOC_CTX *mem_ctx;
	BOOL ext_ctx;
	uint32 count;
	uint32 control;
	LUID_ATTR *set;
} PRIVILEGE_SET;

typedef struct _PRIVS {
	uint32 se_priv;
	const char *priv;
	const char *description;
} PRIVS;


#endif /* PRIVILEGES_H */
