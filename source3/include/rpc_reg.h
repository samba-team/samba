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

#ifndef _RPC_REG_H /* _RPC_REG_H */
#define _RPC_REG_H 


/* winreg pipe defines */
#define REG_OPEN_POLICY     0x02
#define REG_OPEN_ENTRY      0x0f
#define REG_INFO            0x11
#define REG_CLOSE           0x05

/* REG_Q_OPEN_POLICY */
typedef struct q_reg_open_policy_info
{
	uint32 ptr;
	uint16 unknown_0; /* 0x5da0      - 16 bit unknown */
	uint32 level;     /* 0x0000 0001 - 32 bit unknown */
	uint16 unknown_1; /* 0x0200      - 16 bit unknown */

} REG_Q_OPEN_POLICY;

/* REG_R_OPEN_POLICY */
typedef struct r_reg_open_policy_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} REG_R_OPEN_POLICY;


/* REG_Q_CLOSE */
typedef struct reg_q_close_info
{
	POLICY_HND pol; /* policy handle */

} REG_Q_CLOSE;

/* REG_R_CLOSE */
typedef struct reg_r_close_info
{
	POLICY_HND pol; /* policy handle.  should be all zeros. */

	uint32 status; /* return code */

} REG_R_CLOSE;


/* REG_Q_INFO */
typedef struct q_reg_info_info
{
    POLICY_HND pol;        /* policy handle */

	UNIHDR  hdr_type;       /* unicode product type header */
	UNISTR2 uni_type;       /* unicode product type - "ProductType" */

	uint32 ptr1;            /* pointer */
	NTTIME time;            /* current time? */
	uint8  major_version1;  /* 0x4 - os major version? */
	uint8  minor_version1;  /* 0x1 - os minor version? */
	uint8  pad1[10];        /* padding - zeros */

	uint32 ptr2;            /* pointer */
	uint8  major_version2;  /* 0x4 - os major version? */
	uint8  minor_version2;  /* 0x1 - os minor version? */
	uint8  pad2[2];         /* padding - zeros */

	uint32 ptr3;            /* pointer */
	uint32 unknown;         /* 0x0000 0000 */

} REG_Q_INFO;

/* REG_R_INFO */
typedef struct r_reg_info_info
{ 
	uint32 ptr1;            /* buffer pointer */
	uint32 level;          /* 0x1 - info level? */

	uint32     ptr_type;       /* pointer to o/s type */
	UNINOTSTR2 uni_type;      /* unicode string o/s type - "LanmanNT" */

	uint32 ptr2;           /* pointer to unknown_0 */
	uint32 unknown_0;      /* 0x12 */

	uint32 ptr3;           /* pointer to unknown_1 */
	uint32 unknown_1;      /* 0x12 */

	uint32 status;         /* return status */

} REG_R_INFO;


/* REG_Q_OPEN_ENTRY */
typedef struct q_reg_open_entry_info
{
    POLICY_HND pol;        /* policy handle */

	UNIHDR  hdr_name;       /* unicode registry string header */
	UNISTR2 uni_name;       /* unicode registry string name */

	uint32 unknown_0;       /* 32 bit unknown - 0x0000 0000 */
	uint16 unknown_1;       /* 16 bit unknown - 0x0000 */
	uint16 unknown_2;       /* 16 bit unknown - 0x0200 */

} REG_Q_OPEN_ENTRY;



/* REG_R_OPEN_ENTRY */
typedef struct r_reg_open_entry_info
{
    POLICY_HND pol;       /* policy handle */
	uint32 status;         /* return status */

} REG_R_OPEN_ENTRY;



#endif /* _RPC_REG_H */

