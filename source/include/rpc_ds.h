/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Gerald Carter			2002
      
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

#ifndef _RPC_DS_H /* _RPC_LSA_H */
#define _RPC_DS_H 

#include "rpc_misc.h"


/* Opcodes available on PIPE_LSARPC_DS */

#define DS_GETPRIMDOMINFO      0x00


/* macros for RPC's */

#define DSROLE_PRIMARY_DS_RUNNING           0x00000001
#define DSROLE_PRIMARY_DS_MIXED_MODE        0x00000002
#define DSROLE_UPGRADE_IN_PROGRESS          0x00000004
#define DSROLE_PRIMARY_DOMAIN_GUID_PRESENT  0x01000000

typedef struct
{
	uint16		machine_role;
	uint16		unknown;		/* 0x6173 -- maybe just alignment? */
	
	uint32		flags;
	
	uint32		netbios_ptr;
	uint32		dnsname_ptr;
	uint32		forestname_ptr;
	
	GUID		domain_guid;
	
	UNISTR2	netbios_domain;
	/* these 2 might be reversed in order.  I can't tell from 
	   my tests as both values are the same --jerry */
	UNISTR2	dns_domain;
	UNISTR2	forest_domain;
} DSROLE_PRIMARY_DOMAIN_INFO_BASIC;

typedef struct
{
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC	*basic;
} DS_DOMINFO_CTR;

/* info levels for ds_getprimdominfo() */

#define DsRolePrimaryDomainInfoBasic		1


/* DS_Q_GETPRIMDOMINFO - DsGetPrimaryDomainInformation() request */
typedef struct 
{
	uint16	level;
} DS_Q_GETPRIMDOMINFO;

/* DS_R_GETPRIMDOMINFO - DsGetPrimaryDomainInformation() response */
typedef struct 
{
	uint32		ptr;
		
	uint16		level;
	uint16		unknown0;	/* 0x455c -- maybe just alignment? */

	DS_DOMINFO_CTR	info;
	
	NTSTATUS status;
} DS_R_GETPRIMDOMINFO;




#endif /* _RPC_DS_H */
