/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Gerald Carter                        2002.
   Copyright (C) Jelmer Vernooij					  2003-2004.
   
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

#ifndef _REGISTRY_H /* _REGISTRY_H */
#define _REGISTRY_H 

#define HKEY_CLASSES_ROOT	0x80000000
#define HKEY_CURRENT_USER	0x80000001
#define HKEY_LOCAL_MACHINE 	0x80000002
#define HKEY_USERS         	0x80000003

/* Registry data types */

#define	REG_DELETE									-1
#define	REG_NONE									0
#define	REG_SZ										1
#define	REG_EXPAND_SZ								2
#define	REG_BINARY									3
#define	REG_DWORD									4
#define	REG_DWORD_LE								4 /* DWORD, little endian*/
#define	REG_DWORD_BE								5 /* DWORD, big endian */
#define	REG_LINK									6
#define	REG_MULTI_SZ								7
#define	REG_RESOURCE_LIST							8
#define	REG_FULL_RESOURCE_DESCRIPTOR				9
#define	REG_RESOURCE_REQUIREMENTS_LIST				10

typedef struct reg_handle_s REG_HANDLE;
typedef struct reg_key_s REG_KEY;
typedef struct reg_val_s REG_VAL;
typedef struct reg_ops_s REG_OPS;

#if 0
/* FIXME */
typedef struct ace_struct_s {
  uint8_t type, flags;
  uint_t perms;   /* Perhaps a better def is in order */
  DOM_SID *trustee;
} ACE;
#endif

#endif /* _REGISTRY_H */
