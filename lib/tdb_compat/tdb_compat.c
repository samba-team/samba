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

enum TDB_ERROR tdb_chainlock_nonblock(struct tdb_context *tdb, TDB_DATA key)
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

	ecode = tdb_chainlock(tdb, key);
	tdb_unset_attribute(tdb, TDB_ATTRIBUTE_FLOCK);
	return ecode;
}

/* For TDB1 tdbs, read traverse vs normal matters: write traverse
   locks the entire thing! */
int64_t tdb_traverse_read_(struct tdb_context *tdb,
			   int (*fn)(struct tdb_context *,
						       TDB_DATA, TDB_DATA,
						       void *),
			   void *p)
{
	int64_t ret;

	if (tdb_get_flags(tdb) & TDB_RDONLY) {
		return tdb_traverse(tdb, fn, p);
	}

	tdb_add_flag(tdb, TDB_RDONLY);
	ret = tdb_traverse(tdb, fn, p);
	tdb_remove_flag(tdb, TDB_RDONLY);
	return ret;
}

/*
 * This handles TDB_CLEAR_IF_FIRST.
 */
static enum TDB_ERROR clear_if_first(int fd, void *unused)
{
	/* We hold a lock offset 4 always, so we can tell if anyone else is. */
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 4; /* ACTIVE_LOCK */
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
tdb_open_compat_(const char *name, int hash_size,
		 int tdb_flags, int open_flags, mode_t mode,
		 void (*log_fn)(struct tdb_context *,
				enum tdb_log_level,
				enum TDB_ERROR,
				const char *message,
				void *data),
		 void *log_data)
{
	union tdb_attribute cif, log, hash, max_dead, hsize, *attr = NULL;

	if (!getenv("TDB_COMPAT_USE_TDB2")) {
		tdb_flags |= TDB_VERSION1;
	}

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

	if (tdb_flags & TDB_INCOMPATIBLE_HASH) {
		if (tdb_flags & TDB_VERSION1) {
			hash.hash.base.attr = TDB_ATTRIBUTE_HASH;
			hash.hash.base.next = attr;
			hash.hash.fn = tdb1_incompatible_hash;
			attr = &hash;
		}
		tdb_flags &= ~TDB_INCOMPATIBLE_HASH;
	}

	if (tdb_flags & TDB_VOLATILE) {
		if (tdb_flags & TDB_VERSION1) {
			max_dead.base.attr = TDB_ATTRIBUTE_TDB1_MAX_DEAD;
			max_dead.base.next = attr;
			max_dead.tdb1_max_dead.max_dead = 5;
			attr = &max_dead;
		}
		tdb_flags &= ~TDB_VOLATILE;
	}

	if (hash_size && (tdb_flags & TDB_VERSION1) && (open_flags & O_CREAT)) {
		hsize.base.attr = TDB_ATTRIBUTE_TDB1_HASHSIZE;
		hsize.base.next = attr;
		hsize.tdb1_hashsize.hsize = hash_size;
		attr = &hsize;
	}

	/* Testsuite uses this to speed things up. */
	if (getenv("TDB_NO_FSYNC")) {
		tdb_flags |= TDB_NOSYNC;
	}

	return tdb_open(name, tdb_flags|TDB_ALLOW_NESTING, open_flags, mode,
			attr);
}

/* We only need these for the CLEAR_IF_FIRST lock. */
static int reacquire_cif_lock(struct tdb_context *tdb, bool *fail)
{
	struct flock fl;
	union tdb_attribute cif;

	cif.openhook.base.attr = TDB_ATTRIBUTE_OPENHOOK;
	cif.openhook.base.next = NULL;

	if (tdb_get_attribute(tdb, &cif) != TDB_SUCCESS
	    || cif.openhook.fn != clear_if_first) {
		return 0;
	}

	/* We hold a lock offset 4 always, so we can tell if anyone else is. */
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 4; /* ACTIVE_LOCK */
	fl.l_len = 1;
	if (fcntl(tdb_fd(tdb), F_SETLKW, &fl) != 0) {
		*fail = true;
		return -1;
	}
	return 0;
}

int tdb_reopen(struct tdb_context *tdb)
{
	bool unused;
	return reacquire_cif_lock(tdb, &unused);
}

int tdb_reopen_all(int parent_longlived)
{
	bool fail = false;

	if (parent_longlived) {
		return 0;
	}

	tdb_foreach(reacquire_cif_lock, &fail);
	if (fail)
		return -1;
	return 0;
}
#endif
