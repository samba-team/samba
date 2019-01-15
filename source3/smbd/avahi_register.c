/*
 * Unix SMB/CIFS implementation.
 * Register _smb._tcp with avahi
 *
 * Copyright (C) Volker Lendecke 2009
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/strlst.h>

struct avahi_state_struct {
	struct AvahiPoll *poll;
	AvahiClient *client;
	AvahiEntryGroup *entry_group;
	uint16_t port;
};

static void *avahi_allocator_ctx = NULL;

static void * avahi_allocator_malloc(size_t size)
{
	return talloc_size(avahi_allocator_ctx, size);
}

static void avahi_allocator_free(void *p)
{
	TALLOC_FREE(p);
}

static void * avahi_allocator_realloc(void *p, size_t size)
{
	return talloc_realloc_size(avahi_allocator_ctx, p, size);
}

static void * avahi_allocator_calloc(size_t count, size_t size)
{
	void *p = talloc_array_size(avahi_allocator_ctx, size, count);
	if (p) {
		memset(p, 0, size * count);
	}
	return p;
}

static const struct AvahiAllocator avahi_talloc_allocator = {
	&avahi_allocator_malloc,
	&avahi_allocator_free,
	&avahi_allocator_realloc,
	&avahi_allocator_calloc
};

static void avahi_entry_group_callback(AvahiEntryGroup *g,
				       AvahiEntryGroupState status,
				       void *userdata)
{
	struct avahi_state_struct *state = talloc_get_type_abort(
		userdata, struct avahi_state_struct);
	int error;

	switch (status) {
	case AVAHI_ENTRY_GROUP_ESTABLISHED:
		DBG_DEBUG("AVAHI_ENTRY_GROUP_ESTABLISHED\n");
		break;
	case AVAHI_ENTRY_GROUP_FAILURE:
		error = avahi_client_errno(state->client);

		DBG_DEBUG("AVAHI_ENTRY_GROUP_FAILURE: %s\n",
			  avahi_strerror(error));
		break;
	case AVAHI_ENTRY_GROUP_COLLISION:
		DBG_DEBUG("AVAHI_ENTRY_GROUP_COLLISION\n");
		break;
	case AVAHI_ENTRY_GROUP_UNCOMMITED:
		DBG_DEBUG("AVAHI_ENTRY_GROUP_UNCOMMITED\n");
		break;
	case AVAHI_ENTRY_GROUP_REGISTERING:
		DBG_DEBUG("AVAHI_ENTRY_GROUP_REGISTERING\n");
		break;
	}
}

static void avahi_client_callback(AvahiClient *c, AvahiClientState status,
				  void *userdata)
{
	struct avahi_state_struct *state = talloc_get_type_abort(
		userdata, struct avahi_state_struct);
	int error;

	switch (status) {
	case AVAHI_CLIENT_S_RUNNING: {
		int snum;
		int num_services = lp_numservices();
		size_t dk = 0;
		AvahiStringList *adisk = NULL;
		AvahiStringList *adisk2 = NULL;
		AvahiStringList *dinfo = NULL;
		const char *hostname = NULL;
		enum mdns_name_values mdns_name = lp_mdns_name();
		const char *model = NULL;

		DBG_DEBUG("AVAHI_CLIENT_S_RUNNING\n");

		switch (mdns_name) {
		case MDNS_NAME_MDNS:
			hostname = avahi_client_get_host_name(c);
			break;
		case MDNS_NAME_NETBIOS:
			hostname = lp_netbios_name();
			break;
		default:
			DBG_ERR("Unhandled mdns_name %d\n", mdns_name);
			return;
		}

		state->entry_group = avahi_entry_group_new(
			c, avahi_entry_group_callback, state);
		if (state->entry_group == NULL) {
			error = avahi_client_errno(c);
			DBG_DEBUG("avahi_entry_group_new failed: %s\n",
				  avahi_strerror(error));
			break;
		}

		error = avahi_entry_group_add_service(
			    state->entry_group, AVAHI_IF_UNSPEC,
			    AVAHI_PROTO_UNSPEC, 0, hostname,
			    "_smb._tcp", NULL, NULL, state->port, NULL);
		if (error != AVAHI_OK) {
			DBG_DEBUG("avahi_entry_group_add_service failed: %s\n",
				  avahi_strerror(error));
			avahi_entry_group_free(state->entry_group);
			state->entry_group = NULL;
			break;
		}

		for (snum = 0; snum < num_services; snum++) {
			if (lp_snum_ok(snum) &&
			    lp_parm_bool(snum, "fruit", "time machine", false))
			{
				adisk2 = avahi_string_list_add_printf(
					    adisk, "dk%zu=adVN=%s,adVF=0x82",
					    dk++, lp_const_servicename(snum));
				if (adisk2 == NULL) {
					DBG_DEBUG("avahi_string_list_add_printf"
						  "failed: returned NULL\n");
					avahi_string_list_free(adisk);
					avahi_entry_group_free(state->entry_group);
					state->entry_group = NULL;
					break;
				}
				adisk = adisk2;
				adisk2 = NULL;
			}
		}
		if (dk > 0) {
			adisk2 = avahi_string_list_add(adisk, "sys=adVF=0x100");
			if (adisk2 == NULL) {
				DBG_DEBUG("avahi_string_list_add failed: "
					  "returned NULL\n");
				avahi_string_list_free(adisk);
				avahi_entry_group_free(state->entry_group);
				state->entry_group = NULL;
				break;
			}
			adisk = adisk2;
			adisk2 = NULL;

			error = avahi_entry_group_add_service_strlst(
				    state->entry_group, AVAHI_IF_UNSPEC,
				    AVAHI_PROTO_UNSPEC, 0, hostname,
				    "_adisk._tcp", NULL, NULL, 0, adisk);
			avahi_string_list_free(adisk);
			adisk = NULL;
			if (error != AVAHI_OK) {
				DBG_DEBUG("avahi_entry_group_add_service_strlst "
					  "failed: %s\n", avahi_strerror(error));
				avahi_entry_group_free(state->entry_group);
				state->entry_group = NULL;
				break;
			}
		}

		model = lp_parm_const_string(-1, "fruit", "model", "MacSamba");

		dinfo = avahi_string_list_add_printf(NULL, "model=%s", model);
		if (dinfo == NULL) {
			DBG_DEBUG("avahi_string_list_add_printf"
				  "failed: returned NULL\n");
			avahi_entry_group_free(state->entry_group);
			state->entry_group = NULL;
			break;
		}

		error = avahi_entry_group_add_service_strlst(
			    state->entry_group, AVAHI_IF_UNSPEC,
			    AVAHI_PROTO_UNSPEC, 0, hostname,
			    "_device-info._tcp", NULL, NULL, 0,
			    dinfo);
		avahi_string_list_free(dinfo);
		if (error != AVAHI_OK) {
			DBG_DEBUG("avahi_entry_group_add_service failed: %s\n",
				  avahi_strerror(error));
			avahi_entry_group_free(state->entry_group);
			state->entry_group = NULL;
			break;
		}

		error = avahi_entry_group_commit(state->entry_group);
		if (error != AVAHI_OK) {
			DBG_DEBUG("avahi_entry_group_commit failed: %s\n",
				  avahi_strerror(error));
			avahi_entry_group_free(state->entry_group);
			state->entry_group = NULL;
			break;
		}
		break;
	}
	case AVAHI_CLIENT_FAILURE:
		error = avahi_client_errno(c);

		DBG_DEBUG("AVAHI_CLIENT_FAILURE: %s\n", avahi_strerror(error));

		if (error != AVAHI_ERR_DISCONNECTED) {
			break;
		}
		avahi_client_free(c);
		state->client = avahi_client_new(state->poll, AVAHI_CLIENT_NO_FAIL,
						 avahi_client_callback, state,
						 &error);
		if (state->client == NULL) {
			DBG_DEBUG("avahi_client_new failed: %s\n",
				  avahi_strerror(error));
			break;
		}
		break;
	case AVAHI_CLIENT_S_COLLISION:
		DBG_DEBUG("AVAHI_CLIENT_S_COLLISION\n");
		break;
	case AVAHI_CLIENT_S_REGISTERING:
		DBG_DEBUG("AVAHI_CLIENT_S_REGISTERING\n");
		break;
	case AVAHI_CLIENT_CONNECTING:
		DBG_DEBUG("AVAHI_CLIENT_CONNECTING\n");
		break;
	}
}

void *avahi_start_register(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			   uint16_t port)
{
	struct avahi_state_struct *state;
	int error;

	avahi_allocator_ctx = talloc_new(mem_ctx);
	if (avahi_allocator_ctx == NULL) {
		return NULL;
	}
	avahi_set_allocator(&avahi_talloc_allocator);

	state = talloc(mem_ctx, struct avahi_state_struct);
	if (state == NULL) {
		return state;
	}
	state->port = port;
	state->poll = tevent_avahi_poll(state, ev);
	if (state->poll == NULL) {
		goto fail;
	}
	state->client = avahi_client_new(state->poll, AVAHI_CLIENT_NO_FAIL,
					 avahi_client_callback, state,
					 &error);
	if (state->client == NULL) {
		DBG_DEBUG("avahi_client_new failed: %s\n",
			  avahi_strerror(error));
		goto fail;
	}
	return state;

 fail:
	TALLOC_FREE(state);
	return NULL;
}
