/* 
   Unix SMB/CIFS implementation.
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

#ifndef PRIVILEGES_H
#define PRIVILEGES_H

#define PRIV_ALL_INDEX		5

#define SE_PRIV_NONE		0x0000
#define SE_PRIV_ADD_MACHINES	0x0006
#define SE_PRIV_SEC_PRIV	0x0008
#define SE_PRIV_TAKE_OWNER	0x0009
#define SE_PRIV_ADD_USERS	0xff01
#define SE_PRIV_PRINT_OPERATOR	0xff03
#define SE_PRIV_ALL		0xffff

#define PR_NONE                0x0000
#define PR_LOG_ON_LOCALLY      0x0001
#define PR_ACCESS_FROM_NETWORK 0x0002
#define PR_LOG_ON_BATCH_JOB    0x0004
#define PR_LOG_ON_SERVICE      0x0010

typedef struct LUID
{
	uint32 low;
	uint32 high;
} LUID;

typedef struct LUID_ATTR
{
	LUID luid;
	uint32 attr;
} LUID_ATTR ;

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
