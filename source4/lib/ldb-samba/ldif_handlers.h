#ifndef __LIB_LDB_SAMBA_LDIF_HANDLERS_H__
#define __LIB_LDB_SAMBA_LDIF_HANDLERS_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

#define LDB_SYNTAX_SAMBA_SID			"LDB_SYNTAX_SAMBA_SID"
#define LDB_SYNTAX_SAMBA_SECURITY_DESCRIPTOR	"1.2.840.113556.1.4.907"
#define LDB_SYNTAX_SAMBA_GUID			"LDB_SYNTAX_SAMBA_GUID"
#define LDB_SYNTAX_SAMBA_OBJECT_CATEGORY	"LDB_SYNTAX_SAMBA_OBJECT_CATEGORY"
#define LDB_SYNTAX_SAMBA_SCHEMAINFO		"LDB_SYNTAX_SAMBA_SCHEMAINFO"
#define LDB_SYNTAX_SAMBA_PREFIX_MAP		"LDB_SYNTAX_SAMBA_PREFIX_MAP"
#define LDB_SYNTAX_SAMBA_INT32			"LDB_SYNTAX_SAMBA_INT32"
#define LDB_SYNTAX_SAMBA_REPSFROMTO		"LDB_SYNTAX_SAMBA_REPSFROMTO"
#define LDB_SYNTAX_SAMBA_REPLPROPERTYMETADATA   "LDB_SYNTAX_SAMBA_REPLPROPERTYMETADATA"
#define LDB_SYNTAX_SAMBA_REPLUPTODATEVECTOR     "LDB_SYNTAX_SAMBA_REPLUPTODATEVECTOR"
#define LDB_SYNTAX_SAMBA_RANGE64		"LDB_SYNTAX_SAMBA_RANGE64"
#define LDB_SYNTAX_SAMBA_DNSRECORD		"LDB_SYNTAX_SAMBA_DNSRECORD"
#define LDB_SYNTAX_SAMBA_SUPPLEMENTALCREDENTIALS "LDB_SYNTAX_SAMBA_SUPPLEMENTALCREDENTIALS"
#include "lib/ldb-samba/ldif_handlers_proto.h"

#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2)

#endif /* __LIB_LDB_SAMBA_LDIF_HANDLERS_H__ */

