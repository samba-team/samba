#ifndef _LIBCTDB_PRIVATE_H
#define _LIBCTDB_PRIVATE_H
#include <dlinklist.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctdb.h>
#include <ctdb_protocol.h>

#ifndef offsetof
#define offsetof(t,f) ((unsigned int)&((t *)0)->f)
#endif

struct message_handler_info;
struct ctdb_reply_call;

struct ctdb_request {
	struct ctdb_connection *ctdb;
	struct ctdb_request *next, *prev;
	bool cancelled;

	struct io_elem *io;
	union {
		struct ctdb_req_header *hdr;
		struct ctdb_req_call *call;
		struct ctdb_req_control *control;
		struct ctdb_req_message *message;
	} hdr;

	struct io_elem *reply;

	ctdb_callback_t callback;
	void *priv_data;

	/* Extra per-request info. */
	void (*extra_destructor)(struct ctdb_connection *,
				 struct ctdb_request *);
	void *extra;
};

struct ctdb_connection {
	/* Socket to ctdbd. */
	int fd;
	/* Currently our failure mode is simple; return -1 from ctdb_service */
	bool broken;
	/* Linked list of pending outgoings. */
	struct ctdb_request *outq;
	/* Finished outgoings (awaiting response) */
	struct ctdb_request *doneq;
	/* Current incoming. */
	struct io_elem *in;
	/* Guess at a good reqid to try next. */
	uint32_t next_id;
	/* List of messages */
	struct message_handler_info *message_handlers;
	/* PNN of this ctdb: valid by the time we do our first db connection. */
	uint32_t pnn;
};

/* ctdb.c */
struct ctdb_request *new_ctdb_request(size_t len, ctdb_callback_t, void *);
struct ctdb_request *new_ctdb_control_request(struct ctdb_connection *ctdb,
					      uint32_t opcode,
					      uint32_t destnode,
					      const void *extra_data,
					      size_t extra,
					      ctdb_callback_t, void *);
uint32_t new_reqid(struct ctdb_connection *ctdb);

struct ctdb_reply_control *unpack_reply_control(struct ctdb_connection *ctdb,
						struct ctdb_request *req,
						enum ctdb_controls control);
void ctdb_cancel_callback(struct ctdb_connection *ctdb,
			  struct ctdb_request *req,
			  void *unused);
#endif /* _LIBCTDB_PRIVATE_H */
