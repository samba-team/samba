/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell               1992-1997
   Copyright (C) Luke Kenneth Casson Leighton  1996-1997
   Copyright (C) Paul Ashton                   1997
   Copyright (C) Gerald (Jerry) Carter         2005
   
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

#ifndef _RPC_LSA_H /* _RPC_LSA_H */
#define _RPC_LSA_H 

#define LSA_AUDIT_NUM_CATEGORIES_NT4	7
#define LSA_AUDIT_NUM_CATEGORIES_WIN2K	9
#define LSA_AUDIT_NUM_CATEGORIES LSA_AUDIT_NUM_CATEGORIES_NT4

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

#define POLICY_WRITE      ( STD_RIGHT_READ_CONTROL_ACCESS     |\
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

/*******************************************************/
#define MAX_REF_DOMAINS 32

/* This number is based on Win2k and later maximum response allowed */
#define MAX_LOOKUP_SIDS 20480	/* 0x5000 */

#endif /* _RPC_LSA_H */
