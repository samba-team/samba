/*
   Unix SMB/CIFS implementation.

   Copyright (C) Brad Henry	2005

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

#include "includes.h"
#include "libnet/libnet.h"
#include "libcli/cldap/cldap.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "librpc/rpc/dcerpc.h"

/*
 * 1. Setup a CLDAP socket.
 * 2. Lookup the default Site-Name.
 */
NTSTATUS libnet_FindSite(TALLOC_CTX *ctx, struct libnet_JoinSite *r)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	char *site_name_str;
	char *config_dn_str;
	char *server_dn_str;

	struct cldap_socket *cldap = NULL;
	struct cldap_netlogon search;

	tmp_ctx = talloc_named(ctx, 0, "libnet_FindSite temp context");
	if (!tmp_ctx) {
		r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	/* Resolve the site name. */
	ZERO_STRUCT(search);
	search.in.dest_address = r->in.dest_address;
	search.in.acct_control = -1;
	search.in.version = 6;

	cldap = cldap_socket_init(tmp_ctx, NULL);
	status = cldap_netlogon(cldap, tmp_ctx, &search);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		  If cldap_netlogon() returns in error,
		  default to using Default-First-Site-Name.
		*/
		site_name_str = talloc_asprintf(tmp_ctx, "%s",
						"Default-First-Site-Name");
		if (!site_name_str) {
			r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		site_name_str = talloc_asprintf(tmp_ctx, "%s",
					search.out.netlogon.logon5.client_site);
		if (!site_name_str) {
			r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* Generate the CN=Configuration,... DN. */
	config_dn_str = talloc_asprintf(tmp_ctx, "CN=Configuration,%s", r->in.domain_dn_str);
	if (!config_dn_str) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* Generate the CN=Servers,... DN. */
	server_dn_str = talloc_asprintf(tmp_ctx, "CN=%s,CN=Servers,CN=%s,CN=Sites,%s",
						 r->in.netbios_name, site_name_str, config_dn_str);
	if (!server_dn_str) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	r->out.site_name_str = site_name_str;
	talloc_steal(r, site_name_str);

	r->out.config_dn_str = config_dn_str;
	talloc_steal(r, config_dn_str);

	r->out.server_dn_str = server_dn_str;
	talloc_steal(r, server_dn_str);

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 * find out Site specific stuff:
 * 1. Lookup the Site name.
 * 2. Add entry CN=<netbios name>,CN=Servers,CN=<site name>,CN=Sites,CN=Configuration,<domain dn>.
 * TODO: 3.) use DsAddEntry() to create CN=NTDS Settings,CN=<netbios name>,CN=Servers,CN=<site name>,...
 */
NTSTATUS libnet_JoinSite(struct ldb_context *remote_ldb,
			 struct libnet_JoinDomain *libnet_r)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	struct libnet_JoinSite *r;

	struct ldb_dn *server_dn;
	struct ldb_message *msg;
	int rtn;

	const char *server_dn_str;
	const char *config_dn_str;

	tmp_ctx = talloc_named(libnet_r, 0, "libnet_JoinSite temp context");
	if (!tmp_ctx) {
		libnet_r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	r = talloc(tmp_ctx, struct libnet_JoinSite);
	if (!r) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* Resolve the site name and AD DN's. */
	r->in.dest_address = libnet_r->out.samr_binding->host;
	r->in.netbios_name = libnet_r->in.netbios_name;
	r->in.domain_dn_str = libnet_r->out.domain_dn_str;

	status = libnet_FindSite(tmp_ctx, r);
	if (!NT_STATUS_IS_OK(status)) {
		libnet_r->out.error_string =
			talloc_steal(libnet_r, r->out.error_string);
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	config_dn_str = r->out.config_dn_str;
	server_dn_str = r->out.server_dn_str;

	/*
	 Add entry CN=<netbios name>,CN=Servers,CN=<site name>,CN=Sites,CN=Configuration,<domain dn>.
	*/
	msg = ldb_msg_new(tmp_ctx);
	if (!msg) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	rtn = ldb_msg_add_string(msg, "objectClass", "server");
	if (rtn != 0) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	rtn = ldb_msg_add_string(msg, "systemFlags", "50000000");
	if (rtn != 0) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	rtn = ldb_msg_add_string(msg, "serverReference", libnet_r->out.account_dn_str);
	if (rtn != 0) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	server_dn = ldb_dn_explode(tmp_ctx, server_dn_str);
	if (server_dn == NULL) {
		libnet_r->out.error_string = talloc_asprintf(libnet_r,
					"Invalid server dn: %s",
					server_dn_str);
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	msg->dn = server_dn;

	rtn = ldb_add(remote_ldb, msg);
	if (rtn == LDB_ERR_ENTRY_ALREADY_EXISTS) {
		int i;

		/* make a 'modify' msg, and only for serverReference */
		msg = ldb_msg_new(tmp_ctx);
		if (!msg) {
			libnet_r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		msg->dn = server_dn;

		rtn = ldb_msg_add_string(msg, "serverReference",libnet_r->out.account_dn_str);
		if (rtn != 0) {
			libnet_r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		/* mark all the message elements (should be just one)
		   as LDB_FLAG_MOD_REPLACE */
		for (i=0;i<msg->num_elements;i++) {
			msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
		}

		rtn = ldb_modify(remote_ldb, msg);
		if (rtn != 0) {
			libnet_r->out.error_string
				= talloc_asprintf(libnet_r,
						  "Failed to modify server entry %s: %s: %d",
						  server_dn_str,
						  ldb_errstring(remote_ldb), rtn);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else if (rtn != 0) {
		libnet_r->out.error_string
			= talloc_asprintf(libnet_r,
				"Failed to add server entry %s: %s: %d",
				server_dn_str, ldb_errstring(remote_ldb),
				rtn);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	DEBUG(0, ("We still need to perform a DsAddEntry() so that we can create the CN=NTDS Settings container.\n"));

	/* Store the server DN in libnet_r */
	libnet_r->out.server_dn_str = server_dn_str;
	talloc_steal(libnet_r, server_dn_str);

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}
