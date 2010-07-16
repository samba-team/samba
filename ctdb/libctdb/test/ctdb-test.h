#ifndef __HAVE_CTDB_TEST_H
#define __HAVE_CTDB_TEST_H
#include <stdlib.h>

/* We hang all libctdb allocations off this talloc tree. */
extern void *allocations;

void check_allocations(void);

/* Our own working state gets hung off this tree. */
extern void *working;

/* The ctdb connection; created by 'connect' command. */
struct ctdb_connection *get_ctdb(void);

/* Talloc bytes from an fd until EOF.  Nul terminate. */
void *grab_fd(int fd, size_t *size);

#endif /* __HAVE_CTDB_TEST_H */
