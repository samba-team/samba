/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

#define SEC_RIGHTS_READ           0x00020019
#define SEC_RIGHTS_FULL_CONTROL   0x000f003f
#define SEC_RIGHTS_MAXIMUM_ALLOWED 0x02000000

#define SEC_ACE_TYPE_ACCESS_ALLOWED	0x0
#define SEC_ACE_TYPE_ACCESS_DENIED	0x1
#define SEC_ACE_TYPE_SYSTEM_AUDIT	0x2
#define SEC_ACE_TYPE_SYSTEM_ALARM	0x3

#define SEC_ACE_FLAG_OBJECT_INHERIT	0x1
#define SEC_ACE_FLAG_CONTAINER_INHERIT	0x2
#define SEC_ACE_FLAG_NO_PROPAGATE_INHERIT	0x4
#define SEC_ACE_FLAG_INHERIT_ONLY	0x8
#define SEC_ACE_FLAG_INHERITED_ACE	0x10 /* New for Windows 2000 */
#define SEC_ACE_FLAG_VALID_INHERIT	0xf
#define SEC_ACE_FLAG_SUCCESSFUL_ACCESS	0x40
#define SEC_ACE_FLAG_FAILED_ACCESS	0x80

#define SEC_DESC_OWNER_DEFAULTED	0x0001
#define SEC_DESC_GROUP_DEFAULTED	0x0002
#define SEC_DESC_DACL_PRESENT		0x0004
#define SEC_DESC_DACL_DEFAULTED		0x0008
#define SEC_DESC_SACL_PRESENT		0x0010
#define SEC_DESC_SACL_DEFAULTED		0x0020
/*
 * New Windows 2000 bits.
 */
#define SE_DESC_DACL_AUTO_INHERIT_REQ 0x0100
#define SE_DESC_SACL_AUTO_INHERIT_REQ 0x0200
#define SE_DESC_DACL_AUTO_INHERITED 0x0400
#define SE_DESC_SACL_AUTO_INHERITED 0x0800
#define SE_DESC_DACL_PROTECTED		0x1000
#define SE_DESC_SACL_PROTECTED		0x2000

#define SEC_DESC_SELF_RELATIVE		0x8000

/* security information */

#define OWNER_SECURITY_INFORMATION 0x00000001
#define GROUP_SECURITY_INFORMATION 0x00000002
#define DACL_SECURITY_INFORMATION  0x00000004
#define SACL_SECURITY_INFORMATION  0x00000008

#define ALL_SECURITY_INFORMATION (OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|\
									DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)

#ifndef _SEC_ACCESS
/* SEC_ACCESS */
typedef struct security_info_info
{
	uint32 mask;

} SEC_ACCESS;
#define _SEC_ACCESS
#endif

#ifndef _SEC_ACE
/* SEC_ACE */
typedef struct security_ace_info
{
	uint8 type;  /* xxxx_xxxx_ACE_TYPE - e.g allowed / denied etc */
	uint8 flags; /* xxxx_INHERIT_xxxx - e.g OBJECT_INHERIT_ACE */
	uint16 size;

	SEC_ACCESS info;
	DOM_SID trustee;

} SEC_ACE;
#define _SEC_ACE
#endif

#ifndef ACL_REVISION
#define ACL_REVISION 0x3
#endif

#ifndef NT4_ACL_REVISION
#define NT4_ACL_REVISION 0x2
#endif

#ifndef _SEC_ACL
/* SEC_ACL */
typedef struct security_acl_info
{
	uint16 revision; /* 0x0003 */
	uint16 size; /* size in bytes of the entire ACL structure */
	uint32 num_aces; /* number of Access Control Entries */

	SEC_ACE *ace;

} SEC_ACL;
#define _SEC_ACL
#endif

#ifndef SEC_DESC_REVISION
#define SEC_DESC_REVISION 0x1
#endif

#ifndef _SEC_DESC
/* SEC_DESC */
typedef struct security_descriptor_info
{
	uint16 revision; /* 0x0001 */
	uint16 type;     /* SEC_DESC_xxxx flags */

	uint32 off_owner_sid; /* offset to owner sid */
	uint32 off_grp_sid  ; /* offset to group sid */
	uint32 off_sacl     ; /* offset to system list of permissions */
	uint32 off_dacl     ; /* offset to list of permissions */

	SEC_ACL *dacl; /* user ACL */
	SEC_ACL *sacl; /* system ACL */
	DOM_SID *owner_sid; 
	DOM_SID *grp_sid;

} SEC_DESC;
#define _SEC_DESC
#endif

#ifndef _SEC_DESC_BUF
/* SEC_DESC_BUF */
typedef struct sec_desc_buf_info
{
	uint32 max_len;
	uint32 ptr;
	uint32 len;

	SEC_DESC *sec;

} SEC_DESC_BUF;
#define _SEC_DESC_BUF
#endif

/* A type to describe the mapping of generic access rights to object
   specific access rights. */

typedef struct generic_mapping {
	uint32 generic_read;
	uint32 generic_write;
	uint32 generic_execute;
	uint32 generic_all;
} GENERIC_MAPPING;

typedef struct standard_mapping {
	uint32 std_read;
	uint32 std_write;
	uint32 std_execute;
	uint32 std_all;
} STANDARD_MAPPING;

#endif /* _RPC_SECDES_H */
