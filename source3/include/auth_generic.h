/*
   NLTMSSP wrappers

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2011

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

#ifndef _AUTH_GENERIC_
#define _AUTH_GENERIC_

struct gensec_security;

struct auth_generic_state {
	/* used only by the client implementation */
	struct cli_credentials *credentials;

	/* used by both */
	struct gensec_security *gensec_security;
};

NTSTATUS auth_generic_set_username(struct auth_generic_state *ans,
				   const char *user);
NTSTATUS auth_generic_set_domain(struct auth_generic_state *ans,
				 const char *domain);
NTSTATUS auth_generic_set_password(struct auth_generic_state *ans,
				   const char *password);
NTSTATUS auth_generic_set_creds(struct auth_generic_state *ans,
				struct cli_credentials *creds);
NTSTATUS auth_generic_client_prepare(TALLOC_CTX *mem_ctx,
				     struct auth_generic_state **_ans);
NTSTATUS auth_generic_client_start(struct auth_generic_state *ans, const char *oid);
NTSTATUS auth_generic_client_start_by_name(struct auth_generic_state *ans,
					   const char *name);
NTSTATUS auth_generic_client_start_by_authtype(struct auth_generic_state *ans,
					       uint8_t auth_type,
					       uint8_t auth_level);
NTSTATUS auth_generic_client_start_by_sasl(struct auth_generic_state *ans,
					   const char **sasl_list);

#endif /* _AUTH_GENERIC_ */
