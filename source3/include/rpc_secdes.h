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

#ifndef _RPC_SECDES_H /* _RPC_SECDES_H */
#define _RPC_SECDES_H 

#define SEC_RIGHTS_QUERY_VALUE    0x00000001
#define SEC_RIGHTS_SET_VALUE      0x00000002
#define SEC_RIGHTS_CREATE_SUBKEY  0x00000004
#define SEC_RIGHTS_ENUM_SUBKEYS   0x00000008
#define SEC_RIGHTS_NOTIFY         0x00000010
#define SEC_RIGHTS_CREATE_LINK    0x00000020
#define SEC_RIGHTS_DELETE         0x00010000
#define SEC_RIGHTS_READ_CONTROL   0x00020000
#define SEC_RIGHTS_WRITE_DAC      0x00040000
#define SEC_RIGHTS_WRITE_OWNER    0x00080000

#define SEC_RIGHTS_READ           0x00020019
#define SEC_RIGHTS_FULL_CONTROL   0x000f003f

/* SEC_INFO */
typedef struct security_info_info
{
	uint32 perms;

} SEC_INFO;

/* SEC_ACE */
typedef struct security_ace_info
{
	uint16 unknown_1; /* 0x2000 */
	uint16 ace_size;

	SEC_INFO info;
	DOM_SID sid;

} SEC_ACE;


#define MAX_SEC_ACES 16

/* SEC_ACL */
typedef struct security_acl_info
{
	uint16 unknown_1; /* 0x0002 */
	uint16 acl_size; /* size in bytes of the entire ACL structure */
	uint32 num_aces; /* number of Access Control Entries */

	SEC_ACE ace[MAX_SEC_ACES];

} SEC_ACL;

/* SEC_DESC */
typedef struct security_descriptor_info
{
	uint16 unknown_1; /* 0x0001 */
	uint16 unknown_2; /* 0x8004 */

	uint32 off_owner_sid; /* offset to owner sid */
	uint32 off_pnt_sid  ; /* offset to parent? sid */
	uint32 off_unknown  ; /* 0x0000 0000 */
	uint32 off_acl      ; /* offset to list of permissions */

	SEC_ACL acl;
	DOM_SID owner_sid;
	DOM_SID parent_sid;

} SEC_DESC;

/* SEC_DESC_BUF */
typedef struct sec_desc_buf_info
{
	uint32 max_len;
	uint32 undoc;
	uint32 len;

	SEC_DESC sec;

} SEC_DESC_BUF;

#endif /* _RPC_SECDES_H */

