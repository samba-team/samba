/*
 * Unix SMB/CIFS implementation.
 * Samba internal messaging functions
 * Copyright (C) 2014 by Volker Lendecke
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <talloc.h>
#include "messages_dgm.h"
#include "messages_dgm_ref.h"
#include "lib/util/debug.h"
#include "lib/util/dlinklist.h"

struct msg_dgm_ref {
	struct msg_dgm_ref *prev, *next;
	struct messaging_dgm_fde *fde;
	void (*recv_cb)(struct tevent_context *ev,
			const uint8_t *msg, size_t msg_len,
			int *fds, size_t num_fds, void *private_data);
	void *recv_cb_private_data;
};

static pid_t dgm_pid = 0;
static struct msg_dgm_ref *refs = NULL;
static struct msg_dgm_ref *next_ref = NULL;

static int msg_dgm_ref_destructor(struct msg_dgm_ref *r);
static void msg_dgm_ref_recv(struct tevent_context *ev,
			     const uint8_t *msg, size_t msg_len,
			     int *fds, size_t num_fds, void *private_data);

void *messaging_dgm_ref(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			uint64_t *unique,
			const char *socket_dir,
			const char *lockfile_dir,
			void (*recv_cb)(struct tevent_context *ev,
					const uint8_t *msg, size_t msg_len,
					int *fds, size_t num_fds,
					void *private_data),
			void *recv_cb_private_data,
			int *err)
{
	struct msg_dgm_ref *result, *tmp_refs;

	result = talloc(mem_ctx, struct msg_dgm_ref);
	if (result == NULL) {
		*err = ENOMEM;
		return NULL;
	}
	result->fde = NULL;

	tmp_refs = refs;

	if ((refs != NULL) && (dgm_pid != getpid())) {
		/*
		 * Have to reinit after fork
		 */
		messaging_dgm_destroy();
		refs = NULL;
	}

	if (refs == NULL) {
		int ret;

		ret = messaging_dgm_init(ev, unique, socket_dir, lockfile_dir,
					 msg_dgm_ref_recv, NULL);
		DBG_DEBUG("messaging_dgm_init returned %s\n", strerror(ret));
		if (ret != 0) {
			DEBUG(10, ("messaging_dgm_init failed: %s\n",
				   strerror(ret)));
			TALLOC_FREE(result);
			*err = ret;
			return NULL;
		}
		dgm_pid = getpid();
	} else {
		int ret;
		ret = messaging_dgm_get_unique(getpid(), unique);
		DBG_DEBUG("messaging_dgm_get_unique returned %s\n",
			  strerror(ret));
		if (ret != 0) {
			TALLOC_FREE(result);
			*err = ret;
			return NULL;
		}

	}

	result->fde = messaging_dgm_register_tevent_context(result, ev);
	if (result->fde == NULL) {
		TALLOC_FREE(result);
		*err = ENOMEM;
		return NULL;
	}

	DBG_DEBUG("unique = %"PRIu64"\n", *unique);

	refs = tmp_refs;

	result->recv_cb = recv_cb;
	result->recv_cb_private_data = recv_cb_private_data;
	DLIST_ADD(refs, result);
	talloc_set_destructor(result, msg_dgm_ref_destructor);

	return result;
}

static void msg_dgm_ref_recv(struct tevent_context *ev,
			     const uint8_t *msg, size_t msg_len,
			     int *fds, size_t num_fds, void *private_data)
{
	struct msg_dgm_ref *r;

	/*
	 * We have to broadcast incoming messages to all refs. The first ref
	 * that grabs the fd's will get them.
	 */
	for (r = refs; r != NULL; r = next_ref) {
		bool active;

		next_ref = r->next;

		active = messaging_dgm_fde_active(r->fde);
		if (!active) {
			/*
			 * r's tevent_context has died.
			 */
			continue;
		}

		r->recv_cb(ev, msg, msg_len, fds, num_fds,
			   r->recv_cb_private_data);
	}
}

static int msg_dgm_ref_destructor(struct msg_dgm_ref *r)
{
	if (refs == NULL) {
		abort();
	}

	if (r == next_ref) {
		next_ref = r->next;
	}

	DLIST_REMOVE(refs, r);

	TALLOC_FREE(r->fde);

	DBG_DEBUG("refs=%p\n", refs);

	if (refs == NULL) {
		messaging_dgm_destroy();
	}
	return 0;
}
