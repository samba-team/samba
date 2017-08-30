/*
   Message handler database based on srvid

   Copyright (C) Amitay Isaacs  2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"

#include <tdb.h>

#include "lib/util/dlinklist.h"
#include "common/db_hash.h"
#include "common/srvid.h"

struct srvid_handler_list;

struct srvid_context {
	struct db_hash_context *dh;
	struct srvid_handler_list *list;
};

struct srvid_handler {
	struct srvid_handler *prev, *next;
	struct srvid_handler_list *list;
	srvid_handler_fn handler;
	void *private_data;
};

struct srvid_handler_list {
	struct srvid_handler_list *prev, *next;
	struct srvid_context *srv;
	uint64_t srvid;
	struct srvid_handler *h;
};


/*
 * Initialise message srvid context and database
 */
int srvid_init(TALLOC_CTX *mem_ctx, struct srvid_context **result)
{
	struct srvid_context *srv;
	int ret;

	srv = talloc_zero(mem_ctx, struct srvid_context);
	if (srv == NULL) {
		return ENOMEM;
	}

	ret = db_hash_init(srv, "messagedb", 8192, DB_HASH_SIMPLE, &srv->dh);
	if (ret != 0) {
		talloc_free(srv);
		return ret;
	}

	*result = srv;
	return 0;
}

/*
 * Wrapper functions to insert/delete/fetch srvid_hander_list
 */

static int srvid_insert(struct srvid_context *srv, uint64_t srvid,
			struct srvid_handler_list *list)
{
	return db_hash_insert(srv->dh, (uint8_t *)&srvid, sizeof(uint64_t),
			      (uint8_t *)&list, sizeof(list));
}

static int srvid_delete(struct srvid_context *srv, uint64_t srvid)
{
	return db_hash_delete(srv->dh, (uint8_t *)&srvid, sizeof(uint64_t));
}

static int srvid_fetch_parser(uint8_t *keybuf, size_t keylen,
			      uint8_t *databuf, size_t datalen,
			      void *private_data)
{
	struct srvid_handler_list **list =
		(struct srvid_handler_list **)private_data;

	if (datalen != sizeof(*list)) {
		return EIO;
	}

	*list = *(struct srvid_handler_list **)databuf;
	return 0;
}

static int srvid_fetch(struct srvid_context *srv, uint64_t srvid,
		       struct srvid_handler_list **list)
{
	return db_hash_fetch(srv->dh, (uint8_t *)&srvid, sizeof(uint64_t),
			     srvid_fetch_parser, list);
}

/*
 * When a handler is freed, remove it from the list
 */
static int srvid_handler_destructor(struct srvid_handler *h)
{
	struct srvid_handler_list *list = h->list;

	DLIST_REMOVE(list->h, h);
	if (list->h == NULL) {
		talloc_free(list);
	}
	return 0;
}

/*
 * When a list is freed, remove all handlers and remove db entry
 */
static int srvid_handler_list_destructor(struct srvid_handler_list *list)
{
	struct srvid_handler *h;

	while (list->h != NULL) {
		h = list->h;
		DLIST_REMOVE(list->h, h);
		TALLOC_FREE(h);
	}

	srvid_delete(list->srv, list->srvid);
	DLIST_REMOVE(list->srv->list, list);
	return 0;
}

/*
 * Register a message handler
 */
int srvid_register(struct srvid_context *srv, TALLOC_CTX *mem_ctx,
		   uint64_t srvid, srvid_handler_fn handler,
		   void *private_data)
{
	struct srvid_handler_list *list;
	struct srvid_handler *h;
	int ret;

	if (srv == NULL) {
		return EINVAL;
	}

	h = talloc_zero(mem_ctx, struct srvid_handler);
	if (h == NULL) {
		return ENOMEM;
	}

	h->handler = handler;
	h->private_data = private_data;

	ret = srvid_fetch(srv, srvid, &list);
	if (ret != 0) {
		/* srvid not yet registered */
		list = talloc_zero(srv, struct srvid_handler_list);
		if (list == NULL) {
			talloc_free(h);
			return ENOMEM;
		}

		list->srv = srv;
		list->srvid = srvid;

		ret = srvid_insert(srv, srvid, list);
		if (ret != 0) {
			talloc_free(h);
			talloc_free(list);
			return ret;
		}

		DLIST_ADD(srv->list, list);
		talloc_set_destructor(list, srvid_handler_list_destructor);
	}

	h->list = list;
	DLIST_ADD(list->h, h);
	talloc_set_destructor(h, srvid_handler_destructor);
	return 0;
}

/*
 * Deregister a message handler
 */
int srvid_deregister(struct srvid_context *srv, uint64_t srvid,
		     void *private_data)
{
	struct srvid_handler_list *list;
	struct srvid_handler *h;
	int ret;

	ret = srvid_fetch(srv, srvid, &list);
	if (ret != 0) {
		return ret;
	}

	for (h = list->h; h != NULL; h = h->next) {
		if (h->private_data == private_data) {
			talloc_free(h);
			return 0;
		}
	}

	return ENOENT;
}

/*
 * Check if a message handler exists
 */
int srvid_exists(struct srvid_context *srv, uint64_t srvid, void *private_data)
{
	struct srvid_handler_list *list;
	struct srvid_handler *h;
	int ret;

	ret = srvid_fetch(srv, srvid, &list);
	if (ret != 0) {
		return ret;
	}
	if (list->h == NULL) {
		return ENOENT;
	}

	if (private_data != NULL) {
		for (h = list->h; h != NULL; h = h->next) {
			if (h->private_data == private_data) {
				return 0;
			}
		}

		return ENOENT;
	}

	return 0;
}

/*
 * Send a message to registered srvid and srvid_all
 */
int srvid_dispatch(struct srvid_context *srv, uint64_t srvid,
		    uint64_t srvid_all, TDB_DATA data)
{
	struct srvid_handler_list *list;
	struct srvid_handler *h;
	int ret;

	ret = srvid_fetch(srv, srvid, &list);
	if (ret == 0) {
		for (h = list->h; h != NULL; h = h->next) {
			h->handler(srvid, data, h->private_data);
		}
	}

	if (srvid_all == 0) {
		return ret;
	}

	ret = srvid_fetch(srv, srvid_all, &list);
	if (ret == 0) {
		for (h = list->h; h != NULL; h = h->next) {
			h->handler(srvid, data, h->private_data);
		}
	}

	return ret;
}
