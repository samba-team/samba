/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   LDAP and NTDS prototypes &c

   Copyright (C) Luke Howard 2000

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

/* groupType */

typedef enum
{
  NTDS_GROUP_TYPE_BUILTIN_GROUP       = 0x00000001, /* ??? */
  NTDS_GROUP_TYPE_GLOBAL_GROUP        = 0x00000002,
  NTDS_GROUP_TYPE_DOMAIN_LOCAL_GROUP  = 0x00000004,
  NTDS_GROUP_TYPE_UNIVERSAL_GROUP     = 0x00000008,
  NTDS_GROUP_TYPE_SECURITY_ENABLED    = 0x80000000
} NTDS_GROUP_TYPE_ENUM;

/* userAccountFlags */

typedef enum
{
  NTDS_UF_SCRIPT                           =  0x00000001,
  NTDS_UF_ACCOUNTDISABLE                   =  0x00000002,
  NTDS_UF_HOMEDIR_REQUIRED                 =  0x00000003,
  NTDS_UF_LOCKOUT                          =  0x00000010,
  NTDS_UF_PASSWD_NOTREQD                   =  0x00000020,
  NTDS_UF_PASSWD_CANT_CHANGE               =  0x00000040,
  NTDS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED  =  0x00000080,
  NTDS_UF_TEMP_DUPLICATE_ACCOUNT           =  0x00000100,
  NTDS_UF_NORMAL_ACCOUNT                   =  0x00000200,
  NTDS_UF_INTERDOMAIN_TRUST_ACCOUNT        =  0x00000800,
  NTDS_UF_WORKSTATION_TRUST_ACCOUNT        =  0x00001000,
  NTDS_UF_SERVER_TRUST_ACCOUNT             =  0x00002000,
  NTDS_UF_DONT_EXPIRE_PASSWD               =  0x00010000,
  NTDS_UF_MNS_LOGON_ACCOUNT                =  0x00020000,
  NTDS_UF_SMARTCARD_REQUIRED               =  0x00040000,
  NTDS_UF_TRUSTED_FOR_DELEGATION           =  0x00080000,
  NTDS_UF_NOT_DELEGATED                    =  0x00100000,
  NTDS_UF_USE_DES_KEY_ONLY                 =  0x00200000,
  NTDS_UF_DONT_REQUIRE_PREAUTH             =  0x00400000
} NTDS_USER_FLAG_ENUM;

