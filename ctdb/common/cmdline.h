#ifndef CTDB_CMDLINE_H
#define CTDB_CMDLINE_H

extern struct poptOption popt_ctdb_cmdline[];

#define POPT_CTDB_CMDLINE { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_ctdb_cmdline, 0, "Common ctdb options:", NULL },

struct ctdb_context *ctdb_cmdline_init(struct tevent_context *ev);

struct ctdb_context *ctdb_cmdline_client(struct tevent_context *ev,
					 struct timeval req_timeout);

#endif /* CTDB_CMDLINE_H */
