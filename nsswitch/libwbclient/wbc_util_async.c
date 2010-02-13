/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) 2009,2010 Kai Blin  <kai@samba.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "replace.h"
#include "libwbclient.h"
#include "wbc_async.h"

struct wbc_ping_state {
	struct winbindd_request req;
};

static void wbcPing_done(struct tevent_req *subreq);

/** @brief Ping winbind to see if the service is up and running
 *
 * @param mem_ctx	talloc context to allocate the request from
 * @param ev		event context to use for async operation
 * @param wb_ctx	winbind context to use
 *
 * @return Async request on successful dispatch of the request, NULL on error
 */

struct tevent_req *wbcPing_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct wb_context *wb_ctx)
{
	struct tevent_req *req, *subreq;
	struct wbc_ping_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_ping_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);

	state->req.cmd = WINBINDD_PING;
	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcPing_done, req);
	return req;
}

static void wbcPing_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_ping_state *state = tevent_req_data(
			req, struct wbc_ping_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/** @brief Receive ping response from winbind
 *
 * @param req		async request sent in #wbcPing_send
 *
 * @return NT_STATUS_OK on success, an error status on error.
 */

wbcErr wbcPing_recv(struct tevent_req *req)
{
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}


struct wbc_interface_version_state {
	struct winbindd_request req;
	uint32_t version;
};

static void wbcInterfaceVersion_done(struct tevent_req *subreq);

/**
 * @brief Request the interface version from winbind
 *
 * @param mem_ctx	talloc context to allocate memory from
 * @param ev		tevent context to use for async requests
 * @param wb_ctx	winbind context
 *
 * @return tevevt_req on success, NULL on failure
 */

struct tevent_req *wbcInterfaceVersion_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct wb_context *wb_ctx)
{
	struct tevent_req *req, *subreq;
	struct wbc_interface_version_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_interface_version_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);
	state->req.cmd = WINBINDD_INTERFACE_VERSION;

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcInterfaceVersion_done, req);

	return req;
}

static void wbcInterfaceVersion_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_interface_version_state *state = tevent_req_data(
			req, struct wbc_interface_version_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->version = resp->data.interface_version;
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive the winbind interface version
 *
 * @param req			tevent_req containing the request
 * @param interface_version	pointer to uint32_t to hold the interface
 * 				version
 *
 * @return #wbcErr
 */

wbcErr wbcInterfaceVersion_recv(struct tevent_req *req,
			        uint32_t *interface_version)
{
	struct wbc_interface_version_state *state = tevent_req_data(
			req, struct wbc_interface_version_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*interface_version = state->version;

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

struct wbc_info_state {
	struct winbindd_request req;
	char separator;
	char *version_string;
};

static void wbcInfo_done(struct tevent_req *subreq);

/**
 * @brief Request information about the winbind service
 *
 * @param mem_ctx	talloc context to allocate memory from
 * @param ev		tevent context to use for async requests
 * @param wb_ctx	winbind context
 *
 * @return tevent_req on success, NULL on failure
 */

struct tevent_req *wbcInfo_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct wb_context *wb_ctx)
{
	struct tevent_req *req, *subreq;
	struct wbc_info_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_info_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);
	state->req.cmd = WINBINDD_INFO;

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcInfo_done, req);
	return req;
}

static void wbcInfo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_info_state *state = tevent_req_data(
			req, struct wbc_info_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->version_string = talloc_strdup(state,
					resp->data.info.samba_version);
	if (tevent_req_nomem(state->version_string, subreq)) {
		return;
	}
	state->separator = resp->data.info.winbind_separator;
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive information about the running winbind service
 *
 * @param req			tevent_req containing the request
 * @param mem_ctx		talloc context to allocate memory from
 * @param winbind_separator	pointer to a char to hold the separator
 * @param version_string	pointer to a string to hold the version string
 *
 * @return #wbcErr
 */

wbcErr wbcInfo_recv(struct tevent_req *req,
		    TALLOC_CTX *mem_ctx,
		    char *winbind_separator,
		    char **version_string)
{
	struct wbc_info_state *state = tevent_req_data(
			req, struct wbc_info_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*winbind_separator = state->separator;
	*version_string = talloc_steal(mem_ctx, state->version_string);

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

struct wbc_netbios_name_state {
	struct winbindd_request req;
	char *netbios_name;
};

static void wbcNetbiosName_done(struct tevent_req *subreq);

/**
 * @brief Request the machine's netbios name
 *
 * @param mem_ctx	talloc context to allocate memory from
 * @param ev		tevent context to use for async requests
 * @param wb_ctx	winbind context
 *
 * @return tevent_req on success, NULL on failure
 */

struct tevent_req *wbcNetbiosName_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct wb_context *wb_ctx)
{
	struct tevent_req *req, *subreq;
	struct wbc_netbios_name_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_netbios_name_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);
	state->req.cmd = WINBINDD_NETBIOS_NAME;

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcNetbiosName_done, req);
	return req;
}

static void wbcNetbiosName_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_netbios_name_state *state = tevent_req_data(
			req, struct wbc_netbios_name_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->netbios_name = talloc_strdup(state,
					resp->data.info.samba_version);
	if (tevent_req_nomem(state->netbios_name, subreq)) {
		return;
	}
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive the machine's netbios name
 *
 * @param req		tevent_req containing the request
 * @param mem_ctx	talloc context to allocate memory from
 * @param netbios_name	pointer to a string to hold the netbios name
 *
 * @return #wbcErr
 */

wbcErr wbcNetbiosName_recv(struct tevent_req *req,
			   TALLOC_CTX *mem_ctx,
			   char **netbios_name)
{
	struct wbc_netbios_name_state *state = tevent_req_data(
			req, struct wbc_netbios_name_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*netbios_name = talloc_steal(mem_ctx, state->netbios_name);

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

struct wbc_domain_name_state {
	struct winbindd_request req;
	char *domain_name;
};

static void wbcDomainName_done(struct tevent_req *subreq);

/**
 * @brief Request the machine's domain name
 *
 * @param mem_ctx	talloc context to allocate memory from
 * @param ev		tevent context to use for async requests
 * @param wb_ctx	winbind context
 *
 * @return tevent_req on success, NULL on failure
 */

struct tevent_req *wbcDomainName_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct wb_context *wb_ctx)
{
	struct tevent_req *req, *subreq;
	struct wbc_domain_name_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_domain_name_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);
	state->req.cmd = WINBINDD_DOMAIN_NAME;

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcDomainName_done, req);
	return req;
}

static void wbcDomainName_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_domain_name_state *state = tevent_req_data(
			req, struct wbc_domain_name_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->domain_name = talloc_strdup(state, resp->data.domain_name);
	if (tevent_req_nomem(state->domain_name, subreq)) {
		return;
	}
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive the machine's domain name
 *
 * @param req		tevent_req containing the request
 * @param mem_ctx	talloc context to allocate memory from
 * @param domain_name	pointer to a string to hold the domain name
 *
 * @return #wbcErr
 */

wbcErr wbcDomainName_recv(struct tevent_req *req,
			  TALLOC_CTX *mem_ctx,
			  char **domain_name)
{
	struct wbc_domain_name_state *state = tevent_req_data(
			req, struct wbc_domain_name_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*domain_name = talloc_steal(mem_ctx, state->domain_name);

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

struct wbc_interface_details_state {
	struct tevent_context *ev;
	struct wb_context *wb_ctx;
	struct wbcDomainInfo *dinfo;
	struct wbcInterfaceDetails *details;
};

static void wbcInterfaceDetails_version(struct tevent_req *subreq);
static void wbcInterfaceDetails_info(struct tevent_req *subreq);
static void wbcInterfaceDetails_netbios_name(struct tevent_req *subreq);
static void wbcInterfaceDetails_domain_name(struct tevent_req *subreq);
static void wbcInterfaceDetails_domain_info(struct tevent_req *subreq);

/**
 * @brief Request some useful details about the winbind service
 *
 * @param mem_ctx	talloc context to allocate memory from
 * @param ev		tevent context to use for async requests
 * @param wb_ctx	winbind context
 *
 * @return tevent_req on success, NULL on failure
 */

struct tevent_req *wbcInterfaceDetails_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct wb_context *wb_ctx)
{
	struct tevent_req *req, *subreq;
	struct wbc_interface_details_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wbc_interface_details_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->wb_ctx = wb_ctx;
	state->details = talloc(state, struct wbcInterfaceDetails);
	if (tevent_req_nomem(state->details, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = wbcInterfaceVersion_send(state, ev, wb_ctx);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcInterfaceDetails_version, req);
	return req;
}

static void wbcInterfaceDetails_version(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_interface_details_state *state = tevent_req_data(
			req, struct wbc_interface_details_state);
	wbcErr wbc_status;


	wbc_status  = wbcInterfaceVersion_recv(subreq,
					&state->details->interface_version);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	subreq = wbcInfo_send(state, state->ev, state->wb_ctx);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wbcInterfaceDetails_info, req);
}

static void wbcInterfaceDetails_info(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_interface_details_state *state = tevent_req_data(
			req, struct wbc_interface_details_state);
	wbcErr wbc_status;

	wbc_status  = wbcInfo_recv(subreq, state->details,
				   &state->details->winbind_separator,
				   &state->details->winbind_version);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	subreq = wbcNetbiosName_send(state, state->ev, state->wb_ctx);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wbcInterfaceDetails_netbios_name, req);
}

static void wbcInterfaceDetails_netbios_name(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_interface_details_state *state = tevent_req_data(
			req, struct wbc_interface_details_state);
	wbcErr wbc_status;

	wbc_status  = wbcNetbiosName_recv(subreq, state->details,
					  &state->details->netbios_name);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	subreq = wbcDomainName_send(state, state->ev, state->wb_ctx);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wbcInterfaceDetails_domain_name, req);
}

static void wbcInterfaceDetails_domain_name(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_interface_details_state *state = tevent_req_data(
			req, struct wbc_interface_details_state);
	wbcErr wbc_status;

	wbc_status  = wbcDomainName_recv(subreq, state->details,
					 &state->details->netbios_domain);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	subreq = wbcDomainInfo_send(state, state->ev, state->wb_ctx,
				    state->details->netbios_domain);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wbcInterfaceDetails_domain_info, req);
}

static void wbcInterfaceDetails_domain_info(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_interface_details_state *state = tevent_req_data(
			req, struct wbc_interface_details_state);
	struct wbcDomainInfo *domain;
	wbcErr wbc_status;

	wbc_status = wbcDomainInfo_recv(subreq, state, &domain);
	TALLOC_FREE(subreq);
	if (wbc_status == WBC_ERR_DOMAIN_NOT_FOUND) {
		tevent_req_done(req);
		return;
	}

	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->details->dns_domain = talloc_strdup(state->details,
						   domain->dns_name);
	if (tevent_req_nomem(state->details->dns_domain, req)) {
		return;
	}

	TALLOC_FREE(domain);
	tevent_req_done(req);
}

/**
 * @brief Receive useful information about the winbind service
 *
 * @param req		tevent_req containing the request
 * @param mem_ctx	talloc context to allocate memory from
 * @param *details	pointer to hold the struct wbcInterfaceDetails
 *
 * @return #wbcErr
 */

wbcErr wbcInterfaceDetails_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				struct wbcInterfaceDetails **details)
{
	struct wbc_interface_details_state *state = tevent_req_data(
			req, struct wbc_interface_details_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*details = talloc_steal(mem_ctx, state->details);

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

struct wbc_domain_info_state {
	struct winbindd_request req;
	struct wbcDomainInfo *info;
};

static void wbcDomainInfo_done(struct tevent_req *subreq);

/**
 * @brief Request status of a given trusted domain
 *
 * @param mem_ctx	talloc context to allocate memory from
 * @param ev		tevent context to use for async requests
 * @param wb_ctx	winbind context
 * @param domain	domain to request status from
 *
 * @return tevent_req on success, NULL on failure
 */

struct tevent_req *wbcDomainInfo_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct wb_context *wb_ctx,
				      const char *domain)
{
	struct tevent_req *req, *subreq;
	struct wbc_domain_info_state *state;

	if (!domain) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct wbc_domain_info_state);
	if (req == NULL) {
		return NULL;
	}

	state->info = talloc(state, struct wbcDomainInfo);
	if (tevent_req_nomem(state->info, req)) {
		return tevent_req_post(req, ev);
	}

	ZERO_STRUCT(state->req);

	strncpy(state->req.domain_name, domain,
		sizeof(state->req.domain_name)-1);

	state->req.cmd = WINBINDD_DOMAIN_INFO;

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcDomainInfo_done, req);
	return req;
}

static void wbcDomainInfo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_domain_info_state *state = tevent_req_data(
			req, struct wbc_domain_info_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	state->info->short_name = talloc_strdup(state->info,
			resp->data.domain_info.name);
	if (tevent_req_nomem(state->info->short_name, req)) {
		return;
	}

	state->info->dns_name = talloc_strdup(state->info,
			resp->data.domain_info.alt_name);
	if (tevent_req_nomem(state->info->dns_name, req)) {
		return;
	}

	wbc_status = wbcStringToSid(resp->data.domain_info.sid,
				    &state->info->sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	if (resp->data.domain_info.native_mode) {
		state->info->domain_flags |= WBC_DOMINFO_DOMAIN_NATIVE;
	}
	if (resp->data.domain_info.active_directory) {
		state->info->domain_flags |= WBC_DOMINFO_DOMAIN_AD;
	}
	if (resp->data.domain_info.primary) {
		state->info->domain_flags |= WBC_DOMINFO_DOMAIN_PRIMARY;
	}

	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive information about a trusted domain
 *
 * @param req		tevent_req containing the request
 * @param mem_ctx	talloc context to allocate memory from
 * @param *dinfo	pointer to returned struct wbcDomainInfo
 *
 * @return #wbcErr
 */

wbcErr wbcDomainInfo_recv(struct tevent_req *req,
			  TALLOC_CTX *mem_ctx,
			  struct wbcDomainInfo **dinfo)
{
	struct wbc_domain_info_state *state = tevent_req_data(
			req, struct wbc_domain_info_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	if (dinfo == NULL) {
		tevent_req_received(req);
		return WBC_ERR_INVALID_PARAM;
	}

	*dinfo = talloc_steal(mem_ctx, state->info);

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}
