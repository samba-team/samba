/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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

#ifndef _RPC_CREDS_H /* _RPC_CREDS_H */
#define _RPC_CREDS_H 

typedef struct ntuser_creds
{
	fstring user_name;
	fstring domain;
	struct pwd_info pwd;

	uint32 ntlmssp_flags;

} CREDS_NT;

typedef struct unixuser_creds
{
	fstring user_name;
	fstring requested_name;
	fstring real_name;
	uint32 guest;

} CREDS_UNIX;

typedef struct unixsec_creds
{
	uint32 uid;
	uint32 gid;
	uint32 num_grps;
	uint32 *grps;

} CREDS_UNIX_SEC;

typedef struct user_creds
{
	BOOL reuse;

	uint32 ptr_ntc;
	uint32 ptr_uxc;
	uint32 ptr_nts;
	uint32 ptr_uxs;

	CREDS_NT   ntc;
	CREDS_UNIX uxc;

	NET_USER_INFO_3 nts;
	CREDS_UNIX_SEC uxs;

} CREDS_HYBRID;

typedef struct smbd_creds
{
	CREDS_HYBRID cred;
	CREDS_SUBST smbd;

} CREDS_SMBD;

typedef struct cred_command
{
	uint16 version;
	uint16 command;

	vuser_key key;

	fstring name;

	uint32 ptr_creds;
	CREDS_HYBRID *cred;

} CREDS_CMD;
	
#endif /* _RPC_CREDS_H */

