/*
   Unix SMB/CIFS implementation.

   debug print helpers

   Copyright (C) Guenther Deschner 2008

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

#include "includes.h"
#include "ads.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../librpc/ndr/libndr.h"
#include "lib/param/loadparm.h"

static void ndr_print_ads_auth_flags(struct ndr_print *ndr, const char *name, uint32_t r)
{
	ndr_print_uint32(ndr, name, r);
	ndr->depth++;
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_DISABLE_KERBEROS", ADS_AUTH_DISABLE_KERBEROS, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_NO_BIND", ADS_AUTH_NO_BIND, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_ANON_BIND", ADS_AUTH_ANON_BIND, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_SIMPLE_BIND", ADS_AUTH_SIMPLE_BIND, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_ALLOW_NTLMSSP", ADS_AUTH_ALLOW_NTLMSSP, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_SASL_SIGN", ADS_AUTH_SASL_SIGN, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_SASL_SEAL", ADS_AUTH_SASL_SEAL, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_SASL_FORCE", ADS_AUTH_SASL_FORCE, r);
	ndr_print_bitmap_flag(ndr, sizeof(uint32_t), "ADS_AUTH_USER_CREDS", ADS_AUTH_USER_CREDS, r);
	ndr->depth--;
}

void ndr_print_ads_struct(struct ndr_print *ndr, const char *name, const struct ads_struct *r)
{
	ndr_print_struct(ndr, name, "ads_struct");
	ndr->depth++;
	ndr_print_bool(ndr, "is_mine", r->is_mine);
	ndr_print_struct(ndr, name, "server");
	ndr->depth++;
	ndr_print_string(ndr, "realm", r->server.realm);
	ndr_print_string(ndr, "workgroup", r->server.workgroup);
	ndr_print_string(ndr, "ldap_server", r->server.ldap_server);
	ndr->depth--;
	ndr_print_struct(ndr, name, "auth");
	ndr->depth++;
	ndr_print_string(ndr, "realm", r->auth.realm);
#ifdef DEBUG_PASSWORD
	ndr_print_string(ndr, "password", r->auth.password);
#else
	ndr_print_string(ndr, "password", "(PASSWORD omitted)");
#endif
	ndr_print_string(ndr, "user_name", r->auth.user_name);
	ndr_print_string(ndr, "kdc_server", r->auth.kdc_server);
	ndr_print_ads_auth_flags(ndr, "flags", r->auth.flags);
	ndr_print_uint32(ndr, "time_offset", r->auth.time_offset);
	ndr_print_time_t(ndr, "tgt_expire", r->auth.tgt_expire);
	ndr_print_time_t(ndr, "tgs_expire", r->auth.tgs_expire);
	ndr_print_time_t(ndr, "renewable", r->auth.renewable);
	ndr->depth--;
	ndr_print_struct(ndr, name, "config");
	ndr->depth++;
	ndr_print_netr_DsR_DcFlags(ndr, "flags", r->config.flags);
	ndr_print_string(ndr, "realm", r->config.realm);
	ndr_print_string(ndr, "bind_path", r->config.bind_path);
	ndr_print_string(ndr, "ldap_server_name", r->config.ldap_server_name);
	ndr_print_string(ndr, "server_site_name", r->config.server_site_name);
	ndr_print_string(ndr, "client_site_name", r->config.client_site_name);
	ndr_print_time_t(ndr, "current_time", r->config.current_time);
	ndr_print_string(ndr, "schema_path", r->config.schema_path);
	ndr_print_string(ndr, "config_path", r->config.config_path);
	ndr->depth--;
#ifdef HAVE_LDAP
	ndr_print_struct(ndr, name, "ldap");
	ndr->depth++;
	ndr_print_ptr(ndr, "ld", r->ldap.ld);
	ndr_print_sockaddr_storage(ndr, "ss", &r->ldap.ss);
	ndr_print_time_t(ndr, "last_attempt", r->ldap.last_attempt);
	ndr_print_uint32(ndr, "port", r->ldap.port);
	ndr_print_ads_saslwrap_struct(ndr, "saslwrap", &(r->ldap_wrap_data));
	ndr->depth--;
	ndr->depth--;
#endif /* HAVE_LDAP */
	ndr->depth--;
}
