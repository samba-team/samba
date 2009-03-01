/*
   Samba CIFS implementation
   ADS convenience functions for GPO

   Copyright (C) 2008 Jelmer Vernooij, jelmer@samba.org
   Copyright (C) 2008 Wilco Baan Hofman, wilco@baanhofman.nl

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

#ifndef __ADS_CONVENIENCE_H__
#define __ADS_CONVENIENCE_H__

#define ADS_ERR_OK(status) ((status.error_type == ENUM_ADS_ERROR_NT) ? NT_STATUS_IS_OK(status.err.nt_status):(status.err.rc == 0))
#define ADS_ERROR(rc) ads_build_ldap_error(rc)
#define ADS_ERROR_NT(rc) ads_build_nt_error(rc)
#define ADS_ERROR_HAVE_NO_MEMORY(x) do { \
        if (!(x)) {\
                return ADS_ERROR_NT(NT_STATUS_NO_MEMORY);\
        }\
} while (0)

#define LDAP_SCOPE_BASE		LDB_SCOPE_BASE
#define LDAP_SCOPE_SUBTREE	LDB_SCOPE_SUBTREE
#define LDAP_SCOPE_ONELEVEL	LDB_SCOPE_ONELEVEL




typedef struct {
	struct libnet_context *netctx;
	struct ldb_context *ldbctx;
} ADS_STRUCT;

typedef struct ldb_result LDAPMessage;
typedef struct void ** ADS_MODLIST;

/* there are 3 possible types of errors the ads subsystem can produce */
enum ads_error_type { ENUM_ADS_ERROR_LDAP, ENUM_ADS_ERROR_SYSTEM, ENUM_ADS_ERROR_NT};

typedef struct {
	enum ads_error_type error_type;
	union err_state{
		int rc;
		NTSTATUS nt_status;
	} err;
	int minor_status;
} ADS_STATUS;

#endif
