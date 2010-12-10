#ifndef _LIBCTDB_IO_ELEM_H
#define _LIBCTDB_IO_ELEM_H
#include <stdbool.h>

/* Packets are of form: <u32 length><data>. */

/* Create a new queue element of at least len bytes (for reading or writing).
 * Len may be rounded up for alignment. */
struct io_elem *new_io_elem(size_t len);

/* Free a queue element. */
void free_io_elem(struct io_elem *io);

/* If finished, this returns the request header, otherwise NULL. */
bool io_elem_finished(const struct io_elem *io);

/* Reset an io_elem to the start. */
void io_elem_reset(struct io_elem *io);

/* Access to raw data: if len is non-NULL it is filled in. */
void *io_elem_data(const struct io_elem *io, size_t *len);

/* Initialise the struct ctdb_req_header at the front of the I/O. */
void io_elem_init_req_header(struct io_elem *io,
			     uint32_t operation,
			     uint32_t destnode,
			     uint32_t reqid);

/* Returns -1 if we hit an error.  Otherwise bytes read. */
int read_io_elem(int fd, struct io_elem *io);

/* Returns -1 if we hit an error.  Otherwise bytes written. */
int write_io_elem(int fd, struct io_elem *io);

/* Queues a received io element for later processing */
void io_elem_queue(struct ctdb_connection *ctdb, struct io_elem *io);

/* Removes an element from the queue */
void io_elem_dequeue(struct ctdb_connection *ctdb, struct io_elem *io);

#endif /* _LIBCTDB_IO_ELEM_H */
