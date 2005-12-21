/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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

#include "librpc/gen_ndr/ndr_netlogon.h"

/* struct and enum for doing a remote domain vampire dump */
struct libnet_SamSync {
	NTSTATUS (*delta_fn)(TALLOC_CTX *mem_ctx, 		
			     void *private, 			
			     struct creds_CredentialState *creds,
			     enum netr_SamDatabaseID database,
			     struct netr_DELTA_ENUM *delta,
			     char **error_string);
	void *fn_ctx;
	char *error_string;
	struct cli_credentials *machine_account;
};

enum libnet_SamDump_level {
	LIBNET_SAMDUMP_GENERIC,
	LIBNET_SAMDUMP_NETLOGON,
};

struct libnet_SamDump {
	enum libnet_SamDump_level level;
	char *error_string;
};

struct libnet_SamDump_keytab {
	enum libnet_SamDump_level level;
	char *keytab_name;
	char *error_string;
};

enum libnet_samsync_ldb_level {
	LIBNET_SAMSYNC_LDB_GENERIC,
	LIBNET_SAMSYNC_LDB_NETLOGON,
};

struct libnet_samsync_ldb {
	enum libnet_samsync_ldb_level level;
	char *error_string;
};

