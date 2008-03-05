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

#define LSA_POLICY_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED_ACCESS  |\
                            LSA_POLICY_VIEW_LOCAL_INFORMATION    |\
                            LSA_POLICY_VIEW_AUDIT_INFORMATION    |\
                            LSA_POLICY_GET_PRIVATE_INFORMATION   |\
                            LSA_POLICY_TRUST_ADMIN               |\
                            LSA_POLICY_CREATE_ACCOUNT            |\
                            LSA_POLICY_CREATE_SECRET             |\
                            LSA_POLICY_CREATE_PRIVILEGE          |\
                            LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            LSA_POLICY_SET_AUDIT_REQUIREMENTS    |\
                            LSA_POLICY_AUDIT_LOG_ADMIN           |\
                            LSA_POLICY_SERVER_ADMIN              |\
                            LSA_POLICY_LOOKUP_NAMES )


#define LSA_POLICY_READ       ( STANDARD_RIGHTS_READ_ACCESS      |\
                            LSA_POLICY_VIEW_AUDIT_INFORMATION    |\
                            LSA_POLICY_GET_PRIVATE_INFORMATION)

#define LSA_POLICY_WRITE      ( STD_RIGHT_READ_CONTROL_ACCESS     |\
                            LSA_POLICY_TRUST_ADMIN               |\
                            LSA_POLICY_CREATE_ACCOUNT            |\
                            LSA_POLICY_CREATE_SECRET             |\
                            LSA_POLICY_CREATE_PRIVILEGE          |\
                            LSA_POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                            LSA_POLICY_SET_AUDIT_REQUIREMENTS    |\
                            LSA_POLICY_AUDIT_LOG_ADMIN           |\
                            LSA_POLICY_SERVER_ADMIN)

#define LSA_POLICY_EXECUTE    ( STANDARD_RIGHTS_EXECUTE_ACCESS   |\
                            LSA_POLICY_VIEW_LOCAL_INFORMATION    |\
                            LSA_POLICY_LOOKUP_NAMES )

#endif /* _RPC_LSA_H */
