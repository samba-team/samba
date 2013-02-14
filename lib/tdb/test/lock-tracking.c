/* We save the locks so we can reaquire them. */
#include "../common/tdb_private.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include "tap-interface.h"
#include "lock-tracking.h"

struct testlock {
	struct testlock *next;
	unsigned int off;
	unsigned int len;
	int type;
};
static struct testlock *testlocks;
int locking_errors = 0;
bool suppress_lockcheck = false;
bool nonblocking_locks;
int locking_would_block = 0;
void (*unlock_callback)(int fd);

int fcntl_with_lockcheck(int fd, int cmd, ... /* arg */ )
{
	va_list ap;
	int ret, arg3;
	struct flock *fl;
	bool may_block = false;

	if (cmd != F_SETLK && cmd != F_SETLKW) {
		/* This may be totally bogus, but we don't know in general. */
		va_start(ap, cmd);
		arg3 = va_arg(ap, int);
		va_end(ap);

		return fcntl(fd, cmd, arg3);
	}

	va_start(ap, cmd);
	fl = va_arg(ap, struct flock *);
	va_end(ap);

	if (cmd == F_SETLKW && nonblocking_locks) {
		cmd = F_SETLK;
		may_block = true;
	}
	ret = fcntl(fd, cmd, fl);

	/* Detect when we failed, but might have been OK if we waited. */
	if (may_block && ret == -1 && (errno == EAGAIN || errno == EACCES)) {
		locking_would_block++;
	}

	if (fl->l_type == F_UNLCK) {
		struct testlock **l;
		struct testlock *old = NULL;

		for (l = &testlocks; *l; l = &(*l)->next) {
			if ((*l)->off == fl->l_start
			    && (*l)->len == fl->l_len) {
				if (ret == 0) {
					old = *l;
					*l = (*l)->next;
					free(old);
				}
				break;
			}
			if (((*l)->off == fl->l_start)
			    && ((*l)->len == 0)
			    && (ret == 0)) {
				/*
				 * Remove a piece from the start of the
				 * allrecord_lock
				 */
				old = *l;
				(*l)->off += fl->l_len;
				break;
			}
		}
		if (!old && !suppress_lockcheck) {
			diag("Unknown unlock %u@%u - %i",
			     (int)fl->l_len, (int)fl->l_start, ret);
			locking_errors++;
		}
	} else {
		struct testlock *new, *i;
		unsigned int fl_end = fl->l_start + fl->l_len;
		if (fl->l_len == 0)
			fl_end = (unsigned int)-1;

		/* Check for overlaps: we shouldn't do this. */
		for (i = testlocks; i; i = i->next) {
			unsigned int i_end = i->off + i->len;
			if (i->len == 0)
				i_end = (unsigned int)-1;

			if (fl->l_start >= i->off && fl->l_start < i_end)
				break;
			if (fl_end >= i->off && fl_end < i_end)
				break;

			/* tdb_allrecord_lock does this, handle adjacent: */
			if (fl->l_start == i_end && fl->l_type == i->type) {
				if (ret == 0) {
					i->len = fl->l_len
						? i->len + fl->l_len
						: 0;
				}
				goto done;
			}
		}
		if (i) {
			/* Special case: upgrade of allrecord lock. */
			if (i->type == F_RDLCK && fl->l_type == F_WRLCK
			    && i->off == FREELIST_TOP
			    && fl->l_start == FREELIST_TOP
			    && i->len == 0
			    && fl->l_len == 0) {
				if (ret == 0)
					i->type = F_WRLCK;
				goto done;
			}
			if (!suppress_lockcheck) {
				diag("%s testlock %u@%u overlaps %u@%u",
				     fl->l_type == F_WRLCK ? "write" : "read",
				     (int)fl->l_len, (int)fl->l_start,
				     i->len, (int)i->off);
				locking_errors++;
			}
		}

		if (ret == 0) {
			new = malloc(sizeof *new);
			new->off = fl->l_start;
			new->len = fl->l_len;
			new->type = fl->l_type;
			new->next = testlocks;
			testlocks = new;
		}
	}
done:
	if (ret == 0 && fl->l_type == F_UNLCK && unlock_callback)
		unlock_callback(fd);
	return ret;
}

unsigned int forget_locking(void)
{
	unsigned int num = 0;
	while (testlocks) {
		struct testlock *next = testlocks->next;
		free(testlocks);
		testlocks = next;
		num++;
	}
	return num;
}
