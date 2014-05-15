#ifndef CTDB_CMDLINE_H
#define CTDB_CMDLINE_H

extern struct poptOption popt_ctdb_cmdline[];

#define POPT_CTDB_CMDLINE { NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_ctdb_cmdline, 0, "Common ctdb test options:", NULL },

struct ctdb_context *ctdb_cmdline_init(struct event_context *ev);

#endif /* CTDB_CMDLINE_H */
