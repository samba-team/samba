/*
   Unix SMB/CIFS implementation.

   trivial database library

   Copyright (C) Volker Lendecke 2012,2013
   Copyright (C) Stefan Metzmacher 2013,2014
   Copyright (C) Michael Adam 2014

     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include "tdb_private.h"
#include "system/threads.h"

#ifdef USE_TDB_MUTEX_LOCKING

/*
 * If we run with mutexes, we store the "struct tdb_mutexes" at the
 * beginning of the file. We store an additional tdb_header right
 * beyond the mutex area, page aligned. All the offsets within the tdb
 * are relative to the area behind the mutex area. tdb->map_ptr points
 * behind the mmap area as well, so the read and write path in the
 * mutex case can remain unchanged.
 *
 * Early in the mutex development the mutexes were placed between the hash
 * chain pointers and the real tdb data. This had two drawbacks: First, it
 * made pointer calculations more complex. Second, we had to mmap the mutex
 * area twice. One was the normal map_ptr in the tdb. This frequently changed
 * from within tdb_oob. At least the Linux glibc robust mutex code assumes
 * constant pointers in memory, so a constantly changing mmap area destroys
 * the mutex list. So we had to mmap the first bytes of the file with a second
 * mmap call. With that scheme, very weird errors happened that could be
 * easily fixed by doing the mutex mmap in a second file. It seemed that
 * mapping the same memory area twice does not end up in accessing the same
 * physical page, looking at the mutexes in gdb it seemed that old data showed
 * up after some re-mapping. To avoid a separate mutex file, the code now puts
 * the real content of the tdb file after the mutex area. This way we do not
 * have overlapping mmap areas, the mutex area is mmapped once and not
 * changed, the tdb data area's mmap is constantly changed but does not
 * overlap.
 */

struct tdb_mutexes {
	struct tdb_header hdr;

	/* protect allrecord_lock */
	pthread_mutex_t allrecord_mutex;

	/*
	 * F_UNLCK: free,
	 * F_RDLCK: shared,
	 * F_WRLCK: exclusive
	 */
	short int allrecord_lock;

	/*
	 * Index 0 is the freelist mutex, followed by
	 * one mutex per hashchain.
	 */
	pthread_mutex_t hashchains[1];
};

bool tdb_have_mutexes(struct tdb_context *tdb)
{
	return ((tdb->feature_flags & TDB_FEATURE_FLAG_MUTEX) != 0);
}

size_t tdb_mutex_size(struct tdb_context *tdb)
{
	size_t mutex_size;

	if (!tdb_have_mutexes(tdb)) {
		return 0;
	}

	mutex_size = sizeof(struct tdb_mutexes);
	mutex_size += tdb->hash_size * sizeof(pthread_mutex_t);

	return TDB_ALIGN(mutex_size, tdb->page_size);
}

/*
 * Get the index for a chain mutex
 */
static bool tdb_mutex_index(struct tdb_context *tdb, off_t off, off_t len,
			    unsigned *idx)
{
	/*
	 * Weird but true: We fcntl lock 1 byte at an offset 4 bytes before
	 * the 4 bytes of the freelist start and the hash chain that is about
	 * to be locked. See lock_offset() where the freelist is -1 vs the
	 * "+1" in TDB_HASH_TOP(). Because the mutex array is represented in
	 * the tdb file itself as data, we need to adjust the offset here.
	 */
	const off_t freelist_lock_ofs = FREELIST_TOP - sizeof(tdb_off_t);

	if (!tdb_have_mutexes(tdb)) {
		return false;
	}
	if (len != 1) {
		/* Possibly the allrecord lock */
		return false;
	}
	if (off < freelist_lock_ofs) {
		/* One of the special locks */
		return false;
	}
	if (tdb->hash_size == 0) {
		/* tdb not initialized yet, called from tdb_open_ex() */
		return false;
	}
	if (off >= TDB_DATA_START(tdb->hash_size)) {
		/* Single record lock from traverses */
		return false;
	}

	/*
	 * Now we know it's a freelist or hash chain lock. Those are always 4
	 * byte aligned. Paranoia check.
	 */
	if ((off % sizeof(tdb_off_t)) != 0) {
		abort();
	}

	/*
	 * Re-index the fcntl offset into an offset into the mutex array
	 */
	off -= freelist_lock_ofs; /* rebase to index 0 */
	off /= sizeof(tdb_off_t); /* 0 for freelist 1-n for hashchain */

	*idx = off;
	return true;
}

static bool tdb_have_mutex_chainlocks(struct tdb_context *tdb)
{
	size_t i;

	for (i=0; i < tdb->num_lockrecs; i++) {
		bool ret;
		unsigned idx;

		ret = tdb_mutex_index(tdb,
				      tdb->lockrecs[i].off,
				      tdb->lockrecs[i].count,
				      &idx);
		if (!ret) {
			continue;
		}

		if (idx == 0) {
			/* this is the freelist mutex */
			continue;
		}

		return true;
	}

	return false;
}

static int chain_mutex_lock(pthread_mutex_t *m, bool waitflag)
{
	int ret;

	if (waitflag) {
		ret = pthread_mutex_lock(m);
	} else {
		ret = pthread_mutex_trylock(m);
	}
	if (ret != EOWNERDEAD) {
		return ret;
	}

	/*
	 * For chainlocks, we don't do any cleanup (yet?)
	 */
	return pthread_mutex_consistent(m);
}

static int allrecord_mutex_lock(struct tdb_mutexes *m, bool waitflag)
{
	int ret;

	if (waitflag) {
		ret = pthread_mutex_lock(&m->allrecord_mutex);
	} else {
		ret = pthread_mutex_trylock(&m->allrecord_mutex);
	}
	if (ret != EOWNERDEAD) {
		return ret;
	}

	/*
	 * The allrecord lock holder died. We need to reset the allrecord_lock
	 * to F_UNLCK. This should also be the indication for
	 * tdb_needs_recovery.
	 */
	m->allrecord_lock = F_UNLCK;

	return pthread_mutex_consistent(&m->allrecord_mutex);
}

bool tdb_mutex_lock(struct tdb_context *tdb, int rw, off_t off, off_t len,
		    bool waitflag, int *pret)
{
	struct tdb_mutexes *m = tdb->mutexes;
	pthread_mutex_t *chain;
	int ret;
	unsigned idx;
	bool allrecord_ok;

	if (!tdb_mutex_index(tdb, off, len, &idx)) {
		return false;
	}
	chain = &m->hashchains[idx];

again:
	ret = chain_mutex_lock(chain, waitflag);
	if (ret == EBUSY) {
		ret = EAGAIN;
	}
	if (ret != 0) {
		errno = ret;
		goto fail;
	}

	if (idx == 0) {
		/*
		 * This is a freelist lock, which is independent to
		 * the allrecord lock. So we're done once we got the
		 * freelist mutex.
		 */
		*pret = 0;
		return true;
	}

	if (tdb_have_mutex_chainlocks(tdb)) {
		/*
		 * We can only check the allrecord lock once. If we do it with
		 * one chain mutex locked, we will deadlock with the allrecord
		 * locker process in the following way: We lock the first hash
		 * chain, we check for the allrecord lock. We keep the hash
		 * chain locked. Then the allrecord locker locks the
		 * allrecord_mutex. It walks the list of chain mutexes,
		 * locking them all in sequence. Meanwhile, we have the chain
		 * mutex locked, so the allrecord locker blocks trying to lock
		 * our chain mutex. Then we come in and try to lock the second
		 * chain lock, which in most cases will be the freelist. We
		 * see that the allrecord lock is locked and put ourselves on
		 * the allrecord_mutex. This will never be signalled though
		 * because the allrecord locker waits for us to give up the
		 * chain lock.
		 */

		*pret = 0;
		return true;
	}

	/*
	 * Check if someone is has the allrecord lock: queue if so.
	 */

	allrecord_ok = false;

	if (m->allrecord_lock == F_UNLCK) {
		/*
		 * allrecord lock not taken
		 */
		allrecord_ok = true;
	}

	if ((m->allrecord_lock == F_RDLCK) && (rw == F_RDLCK)) {
		/*
		 * allrecord shared lock taken, but we only want to read
		 */
		allrecord_ok = true;
	}

	if (allrecord_ok) {
		*pret = 0;
		return true;
	}

	ret = pthread_mutex_unlock(chain);
	if (ret != 0) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_unlock"
			 "(chain_mutex) failed: %s\n", strerror(ret)));
		errno = ret;
		goto fail;
	}
	ret = allrecord_mutex_lock(m, waitflag);
	if (ret == EBUSY) {
		ret = EAGAIN;
	}
	if (ret != 0) {
		if (waitflag || (ret != EAGAIN)) {
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_%slock"
				 "(allrecord_mutex) failed: %s\n",
				 waitflag ? "" : "try_",  strerror(ret)));
		}
		errno = ret;
		goto fail;
	}
	ret = pthread_mutex_unlock(&m->allrecord_mutex);
	if (ret != 0) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_unlock"
			 "(allrecord_mutex) failed: %s\n", strerror(ret)));
		errno = ret;
		goto fail;
	}
	goto again;

fail:
	*pret = -1;
	return true;
}

bool tdb_mutex_unlock(struct tdb_context *tdb, int rw, off_t off, off_t len,
		      int *pret)
{
	struct tdb_mutexes *m = tdb->mutexes;
	pthread_mutex_t *chain;
	int ret;
	unsigned idx;

	if (!tdb_mutex_index(tdb, off, len, &idx)) {
		return false;
	}
	chain = &m->hashchains[idx];

	ret = pthread_mutex_unlock(chain);
	if (ret == 0) {
		*pret = 0;
		return true;
	}
	errno = ret;
	*pret = -1;
	return true;
}

int tdb_mutex_allrecord_lock(struct tdb_context *tdb, int ltype,
			     enum tdb_lock_flags flags)
{
	struct tdb_mutexes *m = tdb->mutexes;
	int ret;
	uint32_t i;
	bool waitflag = (flags & TDB_LOCK_WAIT);
	int saved_errno;

	if (tdb->flags & TDB_NOLOCK) {
		return 0;
	}

	if (flags & TDB_LOCK_MARK_ONLY) {
		return 0;
	}

	ret = allrecord_mutex_lock(m, waitflag);
	if (!waitflag && (ret == EBUSY)) {
		errno = EAGAIN;
		tdb->ecode = TDB_ERR_LOCK;
		return -1;
	}
	if (ret != 0) {
		if (!(flags & TDB_LOCK_PROBE)) {
			TDB_LOG((tdb, TDB_DEBUG_TRACE,
				 "allrecord_mutex_lock() failed: %s\n",
				 strerror(ret)));
		}
		tdb->ecode = TDB_ERR_LOCK;
		return -1;
	}

	if (m->allrecord_lock != F_UNLCK) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "allrecord_lock == %d\n",
			 (int)m->allrecord_lock));
		goto fail_unlock_allrecord_mutex;
	}
	m->allrecord_lock = (ltype == F_RDLCK) ? F_RDLCK : F_WRLCK;

	for (i=0; i<tdb->hash_size; i++) {

		/* ignore hashchains[0], the freelist */
		pthread_mutex_t *chain = &m->hashchains[i+1];

		ret = chain_mutex_lock(chain, waitflag);
		if (!waitflag && (ret == EBUSY)) {
			errno = EAGAIN;
			goto fail_unroll_allrecord_lock;
		}
		if (ret != 0) {
			if (!(flags & TDB_LOCK_PROBE)) {
				TDB_LOG((tdb, TDB_DEBUG_TRACE,
					 "chain_mutex_lock() failed: %s\n",
					 strerror(ret)));
			}
			errno = ret;
			goto fail_unroll_allrecord_lock;
		}

		ret = pthread_mutex_unlock(chain);
		if (ret != 0) {
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_unlock"
				 "(chainlock) failed: %s\n", strerror(ret)));
			errno = ret;
			goto fail_unroll_allrecord_lock;
		}
	}
	/*
	 * We leave this routine with m->allrecord_mutex locked
	 */
	return 0;

fail_unroll_allrecord_lock:
	m->allrecord_lock = F_UNLCK;

fail_unlock_allrecord_mutex:
	saved_errno = errno;
	ret = pthread_mutex_unlock(&m->allrecord_mutex);
	if (ret != 0) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_unlock"
			 "(allrecord_mutex) failed: %s\n", strerror(ret)));
	}
	errno = saved_errno;
	tdb->ecode = TDB_ERR_LOCK;
	return -1;
}

int tdb_mutex_allrecord_upgrade(struct tdb_context *tdb)
{
	struct tdb_mutexes *m = tdb->mutexes;
	int ret;
	uint32_t i;

	if (tdb->flags & TDB_NOLOCK) {
		return 0;
	}

	/*
	 * Our only caller tdb_allrecord_upgrade()
	 * garantees that we already own the allrecord lock.
	 *
	 * Which means m->allrecord_mutex is still locked by us.
	 */

	if (m->allrecord_lock != F_RDLCK) {
		tdb->ecode = TDB_ERR_LOCK;
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "allrecord_lock == %d\n",
			 (int)m->allrecord_lock));
		return -1;
	}

	m->allrecord_lock = F_WRLCK;

	for (i=0; i<tdb->hash_size; i++) {

		/* ignore hashchains[0], the freelist */
		pthread_mutex_t *chain = &m->hashchains[i+1];

		ret = chain_mutex_lock(chain, true);
		if (ret != 0) {
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_lock"
				 "(chainlock) failed: %s\n", strerror(ret)));
			goto fail_unroll_allrecord_lock;
		}

		ret = pthread_mutex_unlock(chain);
		if (ret != 0) {
			TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_unlock"
				 "(chainlock) failed: %s\n", strerror(ret)));
			goto fail_unroll_allrecord_lock;
		}
	}

	return 0;

fail_unroll_allrecord_lock:
	m->allrecord_lock = F_RDLCK;
	tdb->ecode = TDB_ERR_LOCK;
	return -1;
}

void tdb_mutex_allrecord_downgrade(struct tdb_context *tdb)
{
	struct tdb_mutexes *m = tdb->mutexes;

	/*
	 * Our only caller tdb_allrecord_upgrade() (in the error case)
	 * garantees that we already own the allrecord lock.
	 *
	 * Which means m->allrecord_mutex is still locked by us.
	 */

	if (m->allrecord_lock != F_WRLCK) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "allrecord_lock == %d\n",
			 (int)m->allrecord_lock));
		return;
	}

	m->allrecord_lock = F_RDLCK;
	return;
}


int tdb_mutex_allrecord_unlock(struct tdb_context *tdb)
{
	struct tdb_mutexes *m = tdb->mutexes;
	short old;
	int ret;

	if (tdb->flags & TDB_NOLOCK) {
		return 0;
	}

	/*
	 * Our only callers tdb_allrecord_unlock() and
	 * tdb_allrecord_lock() (in the error path)
	 * garantee that we already own the allrecord lock.
	 *
	 * Which means m->allrecord_mutex is still locked by us.
	 */

	if ((m->allrecord_lock != F_RDLCK) && (m->allrecord_lock != F_WRLCK)) {
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "allrecord_lock == %d\n",
			 (int)m->allrecord_lock));
		return -1;
	}

	old = m->allrecord_lock;
	m->allrecord_lock = F_UNLCK;

	ret = pthread_mutex_unlock(&m->allrecord_mutex);
	if (ret != 0) {
		m->allrecord_lock = old;
		TDB_LOG((tdb, TDB_DEBUG_FATAL, "pthread_mutex_unlock"
			 "(allrecord_mutex) failed: %s\n", strerror(ret)));
		return -1;
	}
	return 0;
}

int tdb_mutex_init(struct tdb_context *tdb)
{
	struct tdb_mutexes *m;
	pthread_mutexattr_t ma;
	int i, ret;

	ret = tdb_mutex_mmap(tdb);
	if (ret == -1) {
		return -1;
	}
	m = tdb->mutexes;

	ret = pthread_mutexattr_init(&ma);
	if (ret != 0) {
		goto fail_munmap;
	}
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
	if (ret != 0) {
		goto fail;
	}
	ret = pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
	if (ret != 0) {
		goto fail;
	}
	ret = pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
	if (ret != 0) {
		goto fail;
	}

	for (i=0; i<tdb->hash_size+1; i++) {
		pthread_mutex_t *chain = &m->hashchains[i];

		ret = pthread_mutex_init(chain, &ma);
		if (ret != 0) {
			goto fail;
		}
	}

	m->allrecord_lock = F_UNLCK;

	ret = pthread_mutex_init(&m->allrecord_mutex, &ma);
	if (ret != 0) {
		goto fail;
	}
	ret = 0;
fail:
	pthread_mutexattr_destroy(&ma);
fail_munmap:

	if (ret == 0) {
		return 0;
	}

	tdb_mutex_munmap(tdb);

	errno = ret;
	return -1;
}

int tdb_mutex_mmap(struct tdb_context *tdb)
{
	size_t len;
	void *ptr;

	len = tdb_mutex_size(tdb);
	if (len == 0) {
		return 0;
	}

	if (tdb->mutexes != NULL) {
		return 0;
	}

	ptr = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FILE,
		   tdb->fd, 0);
	if (ptr == MAP_FAILED) {
		return -1;
	}
	tdb->mutexes = (struct tdb_mutexes *)ptr;

	return 0;
}

int tdb_mutex_munmap(struct tdb_context *tdb)
{
	size_t len;
	int ret;

	len = tdb_mutex_size(tdb);
	if (len == 0) {
		return 0;
	}

	ret = munmap(tdb->mutexes, len);
	if (ret == -1) {
		return -1;
	}
	tdb->mutexes = NULL;

	return 0;
}

static bool tdb_mutex_locking_cached;

static bool tdb_mutex_locking_supported(void)
{
	pthread_mutexattr_t ma;
	pthread_mutex_t m;
	int ret;
	static bool initialized;

	if (initialized) {
		return tdb_mutex_locking_cached;
	}

	initialized = true;

	ret = pthread_mutexattr_init(&ma);
	if (ret != 0) {
		return false;
	}
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
	if (ret != 0) {
		goto cleanup_ma;
	}
	ret = pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
	if (ret != 0) {
		goto cleanup_ma;
	}
	ret = pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
	if (ret != 0) {
		goto cleanup_ma;
	}
	ret = pthread_mutex_init(&m, &ma);
	if (ret != 0) {
		goto cleanup_ma;
	}
	ret = pthread_mutex_lock(&m);
	if (ret != 0) {
		goto cleanup_m;
	}
	/*
	 * This makes sure we have real mutexes
	 * from a threading library instead of just
	 * stubs from libc.
	 */
	ret = pthread_mutex_lock(&m);
	if (ret != EDEADLK) {
		goto cleanup_lock;
	}
	ret = pthread_mutex_unlock(&m);
	if (ret != 0) {
		goto cleanup_m;
	}

	tdb_mutex_locking_cached = true;
	goto cleanup_m;

cleanup_lock:
	pthread_mutex_unlock(&m);
cleanup_m:
	pthread_mutex_destroy(&m);
cleanup_ma:
	pthread_mutexattr_destroy(&ma);
	return tdb_mutex_locking_cached;
}

static void (*tdb_robust_mutext_old_handler)(int) = SIG_ERR;
static pid_t tdb_robust_mutex_pid = -1;

static bool tdb_robust_mutex_setup_sigchild(void (*handler)(int),
			void (**p_old_handler)(int))
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
	struct sigaction oldact;

	memset(&act, '\0', sizeof(act));

	act.sa_handler = handler;
#ifdef SA_RESTART
	act.sa_flags = SA_RESTART;
#endif
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);
	sigaction(SIGCHLD, &act, &oldact);
	if (p_old_handler) {
		*p_old_handler = oldact.sa_handler;
	}
	return true;
#else /* !HAVE_SIGACTION */
	return false;
#endif
}

static void tdb_robust_mutex_handler(int sig)
{
	pid_t child_pid = tdb_robust_mutex_pid;

	if (child_pid != -1) {
		pid_t pid;

		pid = waitpid(child_pid, NULL, WNOHANG);
		if (pid == -1) {
			switch (errno) {
			case ECHILD:
				tdb_robust_mutex_pid = -1;
				return;

			default:
				return;
			}
		}
		if (pid == child_pid) {
			tdb_robust_mutex_pid = -1;
			return;
		}
	}

	if (tdb_robust_mutext_old_handler == SIG_DFL) {
		return;
	}
	if (tdb_robust_mutext_old_handler == SIG_IGN) {
		return;
	}
	if (tdb_robust_mutext_old_handler == SIG_ERR) {
		return;
	}

	tdb_robust_mutext_old_handler(sig);
}

static void tdb_robust_mutex_wait_for_child(pid_t *child_pid)
{
	int options = WNOHANG;

	if (*child_pid == -1) {
		return;
	}

	while (tdb_robust_mutex_pid > 0) {
		pid_t pid;

		/*
		 * First we try with WNOHANG, as the process might not exist
		 * anymore. Once we've sent SIGKILL we block waiting for the
		 * exit.
		 */
		pid = waitpid(*child_pid, NULL, options);
		if (pid == -1) {
			if (errno == EINTR) {
				continue;
			} else if (errno == ECHILD) {
				break;
			} else {
				abort();
			}
		}
		if (pid == *child_pid) {
			break;
		}

		kill(*child_pid, SIGKILL);
		options = 0;
	}

	tdb_robust_mutex_pid = -1;
	*child_pid = -1;
}

_PUBLIC_ bool tdb_runtime_check_for_robust_mutexes(void)
{
	void *ptr = NULL;
	pthread_mutex_t *m = NULL;
	pthread_mutexattr_t ma;
	int ret = 1;
	int pipe_down[2] = { -1, -1 };
	int pipe_up[2] = { -1, -1 };
	ssize_t nread;
	char c = 0;
	bool ok;
	static bool initialized;
	pid_t saved_child_pid = -1;
	bool cleanup_ma = false;

	if (initialized) {
		return tdb_mutex_locking_cached;
	}

	initialized = true;

	ok = tdb_mutex_locking_supported();
	if (!ok) {
		return false;
	}

	tdb_mutex_locking_cached = false;

	ptr = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE,
		   MAP_SHARED|MAP_ANON, -1 /* fd */, 0);
	if (ptr == MAP_FAILED) {
		return false;
	}

	ret = pipe(pipe_down);
	if (ret != 0) {
		goto cleanup;
	}
	ret = pipe(pipe_up);
	if (ret != 0) {
		goto cleanup;
	}

	ret = pthread_mutexattr_init(&ma);
	if (ret != 0) {
		goto cleanup;
	}
	cleanup_ma = true;
	ret = pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
	if (ret != 0) {
		goto cleanup;
	}
	ret = pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED);
	if (ret != 0) {
		goto cleanup;
	}
	ret = pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
	if (ret != 0) {
		goto cleanup;
	}
	ret = pthread_mutex_init(ptr, &ma);
	if (ret != 0) {
		goto cleanup;
	}
	m = (pthread_mutex_t *)ptr;

	if (tdb_robust_mutex_setup_sigchild(tdb_robust_mutex_handler,
			&tdb_robust_mutext_old_handler) == false) {
		goto cleanup;
	}

	tdb_robust_mutex_pid = fork();
	saved_child_pid = tdb_robust_mutex_pid;
	if (tdb_robust_mutex_pid == 0) {
		size_t nwritten;
		close(pipe_down[1]);
		close(pipe_up[0]);
		ret = pthread_mutex_lock(m);
		nwritten = write(pipe_up[1], &ret, sizeof(ret));
		if (nwritten != sizeof(ret)) {
			_exit(1);
		}
		if (ret != 0) {
			_exit(1);
		}
		nread = read(pipe_down[0], &c, 1);
		if (nread != 1) {
			_exit(1);
		}
		/* leave locked */
		_exit(0);
	}
	if (tdb_robust_mutex_pid == -1) {
		goto cleanup;
	}
	close(pipe_down[0]);
	pipe_down[0] = -1;
	close(pipe_up[1]);
	pipe_up[1] = -1;

	nread = read(pipe_up[0], &ret, sizeof(ret));
	if (nread != sizeof(ret)) {
		goto cleanup;
	}

	ret = pthread_mutex_trylock(m);
	if (ret != EBUSY) {
		if (ret == 0) {
			pthread_mutex_unlock(m);
		}
		goto cleanup;
	}

	if (write(pipe_down[1], &c, 1) != 1) {
		goto cleanup;
	}

	nread = read(pipe_up[0], &c, 1);
	if (nread != 0) {
		goto cleanup;
	}

	tdb_robust_mutex_wait_for_child(&saved_child_pid);

	ret = pthread_mutex_trylock(m);
	if (ret != EOWNERDEAD) {
		if (ret == 0) {
			pthread_mutex_unlock(m);
		}
		goto cleanup;
	}

	ret = pthread_mutex_consistent(m);
	if (ret != 0) {
		goto cleanup;
	}

	ret = pthread_mutex_trylock(m);
	if (ret != EDEADLK && ret != EBUSY) {
		pthread_mutex_unlock(m);
		goto cleanup;
	}

	ret = pthread_mutex_unlock(m);
	if (ret != 0) {
		goto cleanup;
	}

	tdb_mutex_locking_cached = true;

cleanup:
	/*
	 * Note that we don't reset the signal handler we just reset
	 * tdb_robust_mutex_pid to -1. This is ok as this code path is only
	 * called once per process.
	 *
	 * Leaving our signal handler avoids races with other threads potentialy
	 * setting up their SIGCHLD handlers.
	 *
	 * The worst thing that can happen is that the other newer signal
	 * handler will get the SIGCHLD signal for our child and/or reap the
	 * child with a wait() function. tdb_robust_mutex_wait_for_child()
	 * handles the case where waitpid returns ECHILD.
	 */
	tdb_robust_mutex_wait_for_child(&saved_child_pid);

	if (m != NULL) {
		pthread_mutex_destroy(m);
	}
	if (cleanup_ma) {
		pthread_mutexattr_destroy(&ma);
	}
	if (pipe_down[0] != -1) {
		close(pipe_down[0]);
	}
	if (pipe_down[1] != -1) {
		close(pipe_down[1]);
	}
	if (pipe_up[0] != -1) {
		close(pipe_up[0]);
	}
	if (pipe_up[1] != -1) {
		close(pipe_up[1]);
	}
	if (ptr != NULL) {
		munmap(ptr, sizeof(pthread_mutex_t));
	}

	return tdb_mutex_locking_cached;
}

#else

size_t tdb_mutex_size(struct tdb_context *tdb)
{
	return 0;
}

bool tdb_have_mutexes(struct tdb_context *tdb)
{
	return false;
}

int tdb_mutex_allrecord_lock(struct tdb_context *tdb, int ltype,
			     enum tdb_lock_flags flags)
{
	tdb->ecode = TDB_ERR_LOCK;
	return -1;
}

int tdb_mutex_allrecord_unlock(struct tdb_context *tdb)
{
	return -1;
}

int tdb_mutex_allrecord_upgrade(struct tdb_context *tdb)
{
	tdb->ecode = TDB_ERR_LOCK;
	return -1;
}

void tdb_mutex_allrecord_downgrade(struct tdb_context *tdb)
{
	return;
}

int tdb_mutex_mmap(struct tdb_context *tdb)
{
	errno = ENOSYS;
	return -1;
}

int tdb_mutex_munmap(struct tdb_context *tdb)
{
	errno = ENOSYS;
	return -1;
}

int tdb_mutex_init(struct tdb_context *tdb)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_ bool tdb_runtime_check_for_robust_mutexes(void)
{
	return false;
}

#endif
