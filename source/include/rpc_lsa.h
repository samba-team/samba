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

#error SAMBA4 clean up
#error this file should be (re)moved 
#error and all unused stuff should go

#ifndef _RPC_LSA_H /* _RPC_LSA_H */
#define _RPC_LSA_H 

#include "rpc_misc.h"

typedef struct seq_qos_info
{
	uint32 len; /* 12 */
	uint16 sec_imp_level; /* 0x02 - impersonation level */
	uint8  sec_ctxt_mode; /* 0x01 - context tracking mode */
	uint8  effective_only; /* 0x00 - effective only */

} LSA_SEC_QOS;

typedef struct obj_attr_info
{
	uint32 len;          /* 0x18 - length (in bytes) inc. the length field. */
	uint32 ptr_root_dir; /* 0 - root directory (pointer) */
	uint32 ptr_obj_name; /* 0 - object name (pointer) */
	uint32 attributes;   /* 0 - attributes (undocumented) */
	uint32 ptr_sec_desc; /* 0 - security descriptior (pointer) */
	uint32 ptr_sec_qos;  /* security quality of service */
	LSA_SEC_QOS *sec_qos;

} LSA_OBJ_ATTR;

/* LSA_Q_OPEN_POL - LSA Query Open Policy */
typedef struct lsa_q_open_pol_info
{
	uint32 ptr;         /* undocumented buffer pointer */
	uint16 system_name; /* 0x5c - system name */
	LSA_OBJ_ATTR attr ; /* object attributes */

	uint32 des_access; /* desired access attributes */

} LSA_Q_OPEN_POL;

#define POLICY_VIEW_LOCAL_INFORMATION    0x00000001
#define POLICY_VIEW_AUDIT_INFORMATION    0x00000002
#define POLICY_GET_PRIVATE_INFORMATION   0x00000004
#define POLICY_TRUST_ADMIN               0x00000008
#define POLICY_CREATE_ACCOUNT            0x00000010
#define POLICY_CREATE_SECRET             0x00000020
#define POLICY_CREATE_PRIVILEGE          0x00000040
#define POLICY_SET_DEFAULT_QUOTA_LIMITS  0x00000080
#define POLICY_SET_AUDIT_REQUIREMENTS    0x00000100
#define POLICY_AUDIT_LOG_ADMIN           0x00000200
#define POLICY_SERVER_ADMIN              0x00000400
#define POLICY_LOOKUP_NAMES              0x00000800

#define POLICY_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED_ACCESS  |\
                            POLICY_VIEW_LOCAL_INFORMATION    |\
                            POLICY_VIEW_AUDIT_INFORMATION    |\
                            POLICY_GET_PRIVATE_INFORMATION   |\
                            POLICY_TRUST_ADMIN               |\
                            POLICY_CREATE_ACCOUNT            |\
                            POLICY_CREATE_SECRET             |\
                            POLICY_CREATE_PRIVILEGE          |\
                            POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            POLICY_SET_AUDIT_REQUIREMENTS    |\
                            POLICY_AUDIT_LOG_ADMIN           |\
                            POLICY_SERVER_ADMIN              |\
                            POLICY_LOOKUP_NAMES )


#define POLICY_READ       ( STANDARD_RIGHTS_READ_ACCESS      |\
                            POLICY_VIEW_AUDIT_INFORMATION    |\
                            POLICY_GET_PRIVATE_INFORMATION)

#define POLICY_WRITE      ( STANDARD_RIGHTS_WRITE_ACCESS     |\
                            POLICY_TRUST_ADMIN               |\
                            POLICY_CREATE_ACCOUNT            |\
                            POLICY_CREATE_SECRET             |\
                            POLICY_CREATE_PRIVILEGE          |\
                            POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            POLICY_SET_AUDIT_REQUIREMENTS    |\
                            POLICY_AUDIT_LOG_ADMIN           |\
                            POLICY_SERVER_ADMIN)

#define POLICY_EXECUTE    ( STANDARD_RIGHTS_EXECUTE_ACCESS   |\
                            POLICY_VIEW_LOCAL_INFORMATION    |\
                            POLICY_LOOKUP_NAMES )

#endif /* _RPC_LSA_H */


