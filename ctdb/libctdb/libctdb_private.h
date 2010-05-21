#ifndef _LIBCTDB_PRIVATE_H
#define _LIBCTDB_PRIVATE_H
#include <dlinklist.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctdb.h>

struct message_handler_info;
struct ctdb_reply_call;

struct ctdb_request {
	struct ctdb_request *next, *prev;
	struct io_elem *io;
	union {
		struct ctdb_req_header *hdr;
		struct ctdb_req_call *call;
		struct ctdb_req_control *control;
		struct ctdb_req_message *message;
	} hdr;
	bool cancelled;
	union {
		ctdb_getrecmaster_cb getrecmaster;
		ctdb_getpnn_cb getpnn;
		void (*register_srvid)(int, struct message_handler_info *);
		void (*attachdb)(int, uint32_t id, struct ctdb_db *);
		void (*getdbpath)(int, const char *, void *);
		void (*nullfunc)(int, struct ctdb_reply_call *, void *);
		void (*immediate)(struct ctdb_request *, void *);
	} callback;
	void *priv_data;
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
	/* Successful sync requests, waiting for next service. */
	struct ctdb_request *immediateq;
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
struct ctdb_request *new_ctdb_request(size_t len);
struct ctdb_request *new_ctdb_control_request(struct ctdb_connection *ctdb,
					      uint32_t opcode,
					      uint32_t destnode,
					      const void *extra_data,
					      size_t extra);
uint32_t new_reqid(struct ctdb_connection *ctdb);
#endif /* _LIBCTDB_PRIVATE_H */
