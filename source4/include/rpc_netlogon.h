/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Jean François Micouleau 2002
   
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

#ifndef _RPC_NETLOGON_H /* _RPC_NETLOGON_H */
#define _RPC_NETLOGON_H 


/* NETLOGON pipe */
#define NET_SAMLOGON		0x02
#define NET_SAMLOGOFF		0x03
#define NET_REQCHAL		0x04
#define NET_AUTH		0x05
#define NET_SRVPWSET		0x06
#define NET_SAM_DELTAS		0x07
#define NET_LOGON_CTRL		0x0c
#define NET_AUTH2		0x0f
#define NET_LOGON_CTRL2		0x0e
#define NET_SAM_SYNC		0x10
#define NET_TRUST_DOM_LIST	0x13
#define NET_AUTH3		0x1a

/* Secure Channel types.  used in NetrServerAuthenticate negotiation */
#define SEC_CHAN_WKSTA   2
#define SEC_CHAN_DOMAIN  4
#define SEC_CHAN_BDC     6

/* Returned delta types */
#define SAM_DELTA_DOMAIN_INFO    0x01
#define SAM_DELTA_GROUP_INFO     0x02
#define SAM_DELTA_RENAME_GROUP   0x04
#define SAM_DELTA_ACCOUNT_INFO   0x05
#define SAM_DELTA_RENAME_USER    0x07
#define SAM_DELTA_GROUP_MEM      0x08
#define SAM_DELTA_ALIAS_INFO     0x09
#define SAM_DELTA_RENAME_ALIAS   0x0b
#define SAM_DELTA_ALIAS_MEM      0x0c
#define SAM_DELTA_POLICY_INFO    0x0d
#define SAM_DELTA_TRUST_DOMS     0x0e
#define SAM_DELTA_PRIVS_INFO     0x10 /* DT_DELTA_ACCOUNTS */
#define SAM_DELTA_SECRET_INFO    0x12
#define SAM_DELTA_DELETE_GROUP   0x14
#define SAM_DELTA_DELETE_USER    0x15
#define SAM_DELTA_MODIFIED_COUNT 0x16

/* SAM database types */
#define SAM_DATABASE_DOMAIN    0x00 /* Domain users and groups */
#define SAM_DATABASE_BUILTIN   0x01 /* BUILTIN users and groups */
#define SAM_DATABASE_PRIVS     0x02 /* Privileges */



#endif /* _RPC_NETLOGON_H */
