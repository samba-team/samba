#include <tdb_compat.h>

/* Note: for the moment, we only need this file for TDB2, so we can
 * assume waf. */
#if BUILD_TDB2
TDB_DATA tdb_null = { NULL, 0 };

/* Proxy which sets waitflag to false so we never block. */
static int lock_nonblock(int fd, int rw, off_t off, off_t len, bool waitflag,
			 void *_orig)
{
	struct tdb_attribute_flock *orig = _orig;

	return orig->lock(fd, rw, off, len, false, orig->data);
}

enum TDB_ERROR tdb_transaction_start_nonblock(struct tdb_context *tdb)
{
	union tdb_attribute locking, orig;
	enum TDB_ERROR ecode;

	orig.base.attr = TDB_ATTRIBUTE_FLOCK;
	ecode = tdb_get_attribute(tdb, &orig);
	if (ecode != TDB_SUCCESS)
		return ecode;

	/* Replace locking function with our own. */
	locking = orig;
	locking.flock.data = &orig;
	locking.flock.lock = lock_nonblock;

	ecode = tdb_set_attribute(tdb, &locking);
	if (ecode != TDB_SUCCESS)
		return ecode;

	ecode = tdb_transaction_start(tdb);
	tdb_unset_attribute(tdb, TDB_ATTRIBUTE_FLOCK);
	return ecode;
}

/*
 * This handles TDB_CLEAR_IF_FIRST.
 */
static enum TDB_ERROR clear_if_first(int fd, void *unused)
{
	/* We hold a lock offset 63 always, so we can tell if anyone else is. */
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 63;
	fl.l_len = 1;

	if (fcntl(fd, F_SETLK, &fl) == 0) {
		/* We must be first ones to open it w/ TDB_CLEAR_IF_FIRST! */
		if (ftruncate(fd, 0) != 0) {
			return TDB_ERR_IO;
		}
	}
	fl.l_type = F_RDLCK;
	if (fcntl(fd, F_SETLKW, &fl) != 0) {
		return TDB_ERR_IO;
	}
	return TDB_SUCCESS;
}

struct tdb_context *
tdb_open_compat_(const char *name, int hash_size_unused,
		 int tdb_flags, int open_flags, mode_t mode,
		 void (*log_fn)(struct tdb_context *,
				enum tdb_log_level,
				const char *message,
				void *data),
		 void *log_data)
{
	union tdb_attribute cif, log, *attr = NULL;

	if (log_fn) {
		log.log.base.attr = TDB_ATTRIBUTE_LOG;
		log.log.base.next = NULL;
		log.log.fn = log_fn;
		log.log.data = log_data;
		attr = &log;
	}

	if (tdb_flags & TDB_CLEAR_IF_FIRST) {
		cif.openhook.base.attr = TDB_ATTRIBUTE_OPENHOOK;
		cif.openhook.base.next = attr;
		cif.openhook.fn = clear_if_first;
		attr = &cif;
		tdb_flags &= ~TDB_CLEAR_IF_FIRST;
	}
	return tdb_open(name, tdb_flags|TDB_ALLOW_NESTING, open_flags, mode,
			attr);
}
#endif
