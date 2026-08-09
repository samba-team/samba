/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WSP_GSS_H
#define WSP_GSS_H

struct wsp_gss_state;
struct wsp_client_data;
struct memcache;

struct wspd_client_state {
	struct wsp_abstract_state *wsp_abstract_state;
	struct wsp_client_data *client_data;
	struct memcache *id_cache;
	struct GUID sessionid;
};

bool wsp_gss_init(struct wsp_gss_state *state);
struct tevent_req *wsp_request_send(TALLOC_CTX *ctx,
				    struct tevent_context *ev,
				    struct wspd_client_state *client_state,
				    DATA_BLOB *in_blob);
NTSTATUS wsp_request_recv(struct tevent_req *req,
			  TALLOC_CTX *ctx,
			  DATA_BLOB *out_blob);
struct auth_session_info *get_session_info(
	struct wspd_client_state *client_state);
uint32_t get_handle(struct wspd_client_state *client_state);
struct wsp_gss_state *wsp_gss_state_create(struct tevent_context *event_ctx);
struct wspd_client_state *wsp_gss_client_state_create(
	struct auth_session_info *session_info,
	struct wsp_gss_state *wsp_gss_state);

void wsp_gss_client_state_destroy(struct wspd_client_state *client_state,
				  struct tevent_context *ev);

#endif /* WSP_GSS_H */
