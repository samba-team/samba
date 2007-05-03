/* 
   efficient async ctdb traverse

   Copyright (C) Andrew Tridgell  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "../include/ctdb_private.h"

typedef void (*ctdb_traverse_fn_t)(void *private_data, TDB_DATA key, TDB_DATA data);

/*
  structure used to pass the data between the child and parent
 */
struct ctdb_traverse_data {
	uint32_t length;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};
				   
/*
  handle returned to caller - freeing this handler will kill the child and 
  terminate the traverse
 */
struct ctdb_traverse_handle {
	struct ctdb_db_context *ctdb_db;
	int fd[2];
	pid_t child;
	void *private_data;
	ctdb_traverse_fn_t callback;
	struct timeval start_time;
	struct ctdb_queue *queue;
};

/*
  called when data is available from the child
 */
static void ctdb_traverse_handler(uint8_t *rawdata, size_t length, void *private_data)
{
	struct ctdb_traverse_handle *h = talloc_get_type(private_data, 
						    struct ctdb_traverse_handle);
	TDB_DATA key, data;
	ctdb_traverse_fn_t callback = h->callback;
	void *p = h->private_data;
	struct ctdb_traverse_data *tdata = (struct ctdb_traverse_data *)rawdata;

	if (rawdata == NULL || length < 4 || length != tdata->length) {
		/* end of traverse */
		talloc_free(h);
		callback(p, tdb_null, tdb_null);
		return;
	}

	key.dsize = tdata->keylen;
	key.dptr  = &tdata->data[0];
	data.dsize = tdata->datalen;
	data.dptr = &tdata->data[tdata->keylen];

	callback(p, key, data);	
}

/*
  destroy a in-flight traverse operation
 */
static int traverse_destructor(struct ctdb_traverse_handle *h)
{
	close(h->fd[0]);
	kill(h->child, SIGKILL);
	waitpid(h->child, NULL, 0);
	return 0;
}

/*
  callback from tdb_traverse_read()x
 */
static int ctdb_traverse_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct ctdb_traverse_handle *h = talloc_get_type(p, struct ctdb_traverse_handle);
	struct ctdb_traverse_data *d;
	size_t length = offsetof(struct ctdb_traverse_data, data) + key.dsize + data.dsize;
	d = (struct ctdb_traverse_data *)talloc_size(h, length);
	if (d == NULL) {
		/* error handling is tricky in this child code .... */
		return -1;
	}
	d->length = length;
	d->keylen = key.dsize;
	d->datalen = data.dsize;
	memcpy(&d->data[0], key.dptr, key.dsize);
	memcpy(&d->data[key.dsize], data.dptr, data.dsize);
	if (ctdb_queue_send(h->queue, (uint8_t *)d, d->length) != 0) {
		return -1;
	}
	return 0;
}

/*
  setup a non-blocking traverse of a tdb. The callback function will
  be called on every record in the local ltdb. To stop the travserse,
  talloc_free() the travserse_handle.
 */
struct ctdb_traverse_handle *ctdb_traverse(struct ctdb_db_context *ctdb_db,
					    ctdb_traverse_fn_t callback,
					    void *private_data)
{
	struct ctdb_traverse_handle *h;
	int ret;

	ctdb_db->ctdb->status.traverse_calls++;

	if (!(h = talloc_zero(ctdb_db, struct ctdb_traverse_handle))) {
		return NULL;
	}

	ret = pipe(h->fd);

	if (ret != 0) {
		talloc_free(h);
		return NULL;
	}

	h->child = fork();

	if (h->child == (pid_t)-1) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	h->callback = callback;
	h->private_data = private_data;
	h->ctdb_db = ctdb_db;

	if (h->child == 0) {
		/* start the traverse in the child */
		close(h->fd[0]);
		tdb_traverse_read(ctdb_db->ltdb->tdb, ctdb_traverse_fn, h);
		_exit(0);
	}

	close(h->fd[1]);
	talloc_set_destructor(h, traverse_destructor);

	/*
	  setup a packet queue between the child and the parent. This
	  copes with all the async and packet boundary issues
	 */
	h->queue = ctdb_queue_setup(ctdb_db->ctdb, h, h->fd[0], 0, ctdb_traverse_handler, h);
	if (h->queue == NULL) {
		talloc_free(h);
		return NULL;
	}

	h->start_time = timeval_current();

	return h;
}
