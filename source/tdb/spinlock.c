#if STANDALONE
#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include "tdb.h"
#include "spinlock.h"

#define DEBUG
#else
#include "includes.h"
#endif

#ifdef USE_SPINLOCKS

/*
 * ARCH SPECIFIC
 */

#if defined(SPARC_SPINLOCKS)

static inline int __spin_trylock(spinlock_t *lock)
{
	unsigned int result;

	asm volatile("ldstub    [%1], %0"
		: "=r" (result)
		: "r" (lock)
		: "memory");

	return (result == 0) ? 0 : EBUSY;
}

static inline void __spin_unlock(spinlock_t *lock)
{
	*lock = 0;
}

static inline void __spin_lock_init(spinlock_t *lock)
{
	*lock = 0;
}

static inline int __spin_is_locked(spinlock_t *lock)
{
	return (*lock != 0);
}

#elif defined(POWERPC_SPINLOCKS) 

static inline int __spin_trylock(spinlock_t *lock)
{
	int result;

	__asm__ __volatile__ (
		"	eieio;"
		"0:	lwarx %0,0,%1;"
		"	cmpwi 0,%0,0;"
		"	bne- 1f;"
		"	stwcx. %2,0,%1;"
		"	bne- 0b;"
		"	sync;"
		"1:"
                : "=&r"(result)
                : "r"(lock), "r"(1)
                : "cr0", "memory");

	return (result == 0) ? 0 : EBUSY;
}

static inline void __spin_unlock(spinlock_t *lock)
{
	asm volatile("sync");
	*lock = 0;
}

static inline void __spin_lock_init(spinlock_t *lock)
{
	*lock = 0;
}

static inline int __spin_is_locked(spinlock_t *lock)
{
	return (*lock != 0);
}

#elif defined(INTEL_SPINLOCKS) 

static inline int __spin_trylock(spinlock_t *lock)
{
	int oldval;

	asm volatile("xchgl %0,%1"
		: "=r" (oldval), "=m" (*lock)
		: "0" (0));
	return oldval > 0 ? 0 : EBUSY;
}

static inline void __spin_unlock(spinlock_t *lock)
{
	*lock = 1;
}

static inline void __spin_lock_init(spinlock_t *lock)
{
	*lock = 1;
}

static inline int __spin_is_locked(spinlock_t *lock)
{
	return (*lock != 1);
}

#elif defined(MIPS_SPINLOCKS) 

static inline unsigned int load_linked(unsigned long addr)
{
	unsigned int res;

	__asm__ __volatile__("ll\t%0,(%1)"
		: "=r" (res)
		: "r" (addr));

	return res;
}

static inline unsigned int store_conditional(unsigned long addr, unsigned int value)
{
	unsigned int res;

	__asm__ __volatile__("sc\t%0,(%2)"
		: "=r" (res)
		: "0" (value), "r" (addr));
	return res;
}

static inline int __spin_trylock(spinlock_t *lock)
{
	unsigned int mw;

	do {
		mw = load_linked(lock);
		if (mw) 
			return EBUSY;
	} while (!store_conditional(lock, 1));

	return 0;
}

static inline void __spin_unlock(spinlock_t *lock)
{
	*lock = 0;
}

static inline void __spin_lock_init(spinlock_t *lock)
{
	*lock = 0;
}

static inline int __spin_is_locked(spinlock_t *lock)
{
	return (*lock != 0);
}

#else
#error Need to implement spinlock code in spinlock.c
#endif

/*
 * OS SPECIFIC
 */

static void yield_cpu(void)
{
	struct timespec tm;

#ifdef USE_SCHED_YIELD
	sched_yield();
#else
	/* Linux will busy loop for delays < 2ms on real time tasks */
	tm.tv_sec = 0;
	tm.tv_nsec = 2000000L + 1;
	nanosleep(&tm, NULL);
#endif
}

static int this_is_smp(void)
{
	return 0;
}

/*
 * GENERIC
 */

static int smp_machine = 0;

static inline void __spin_lock(spinlock_t *lock)
{
	int ntries = 0;

	while(__spin_trylock(lock)) {
		while(__spin_is_locked(lock)) {
			if (smp_machine && ntries++ < MAX_BUSY_LOOPS)
				continue;
			yield_cpu();
		}
	}
}

static void __read_lock(rwlock_t *rwlock)
{
	int ntries = 0;

	while(1) {
		__spin_lock(&rwlock->lock);

		if (!(rwlock->count & RWLOCK_BIAS)) {
			rwlock->count++;
			__spin_unlock(&rwlock->lock);
			return;
		}
	
		__spin_unlock(&rwlock->lock);

		while(rwlock->count & RWLOCK_BIAS) {
			if (smp_machine && ntries++ < MAX_BUSY_LOOPS)
				continue;
			yield_cpu();
		}
	}
}

static void __write_lock(rwlock_t *rwlock)
{
	int ntries = 0;

	while(1) {
		__spin_lock(&rwlock->lock);

		if (rwlock->count == 0) {
			rwlock->count |= RWLOCK_BIAS;
			__spin_unlock(&rwlock->lock);
			return;
		}

		__spin_unlock(&rwlock->lock);

		while(rwlock->count != 0) {
			if (smp_machine && ntries++ < MAX_BUSY_LOOPS)
				continue;
			yield_cpu();
		}
	}
}

static void __write_unlock(rwlock_t *rwlock)
{
	__spin_lock(&rwlock->lock);

#ifdef DEBUG
	if (!(rwlock->count & RWLOCK_BIAS))
		fprintf(stderr, "bug: write_unlock\n");
#endif

	rwlock->count &= ~RWLOCK_BIAS;
	__spin_unlock(&rwlock->lock);
}

static void __read_unlock(rwlock_t *rwlock)
{
	__spin_lock(&rwlock->lock);

#ifdef DEBUG
	if (!rwlock->count)
		fprintf(stderr, "bug: read_unlock\n");

	if (rwlock->count & RWLOCK_BIAS)
		fprintf(stderr, "bug: read_unlock\n");
#endif

	rwlock->count--;
	__spin_unlock(&rwlock->lock);
}

/* TDB SPECIFIC */

/* lock a list in the database. list -1 is the alloc list */
int tdb_spinlock(TDB_CONTEXT *tdb, int list, int rw_type)
{
	rwlock_t *rwlocks;

	if (!tdb->map_ptr) return -1;
	rwlocks = (rwlock_t *)((char *)tdb->map_ptr + tdb->header.rwlocks);

	switch(rw_type) {
	case F_RDLCK:
		__read_lock(&rwlocks[list+1]);
		break;

	case F_WRLCK:
		__write_lock(&rwlocks[list+1]);
		break;

	default:
		return TDB_ERRCODE(TDB_ERR_LOCK, -1);
	}
	return 0;
}

/* unlock the database. */
int tdb_spinunlock(TDB_CONTEXT *tdb, int list, int rw_type)
{
	rwlock_t *rwlocks;

	if (!tdb->map_ptr) return -1;
	rwlocks = (rwlock_t *)((char *)tdb->map_ptr + tdb->header.rwlocks);

	switch(rw_type) {
	case F_RDLCK:
		__read_unlock(&rwlocks[list+1]);
		break;

	case F_WRLCK:
		__write_unlock(&rwlocks[list+1]);
		break;

	default:
		return TDB_ERRCODE(TDB_ERR_LOCK, -1);
	}

	return 0;
}

int tdb_create_rwlocks(int fd, unsigned int hash_size)
{
	unsigned size, i;
	rwlock_t *rwlocks;

	size = (hash_size + 1) * sizeof(rwlock_t);
	rwlocks = malloc(size);
	if (!rwlocks)
		return -1;

	for(i = 0; i < hash_size+1; i++) {
		__spin_lock_init(&rwlocks[i].lock);
		rwlocks[i].count = 0;
	}

	/* Write it out (appending to end) */
	if (write(fd, rwlocks, size) != size) {
		free(rwlocks);
		return -1;
	}
	smp_machine = this_is_smp();
	free(rwlocks);
	return 0;
}

int tdb_clear_spinlocks(TDB_CONTEXT *tdb)
{
	rwlock_t *rwlocks;
	unsigned i;

	if (tdb->header.rwlocks == 0) return 0;
	if (!tdb->map_ptr) return -1;

	/* We're mmapped here */
	rwlocks = (rwlock_t *)((char *)tdb->map_ptr + tdb->header.rwlocks);
	for(i = 0; i < tdb->header.hash_size+1; i++) {
		__spin_lock_init(&rwlocks[i].lock);
		rwlocks[i].count = 0;
	}
	return 0;
}
#else
int tdb_create_rwlocks(int fd, unsigned int hash_size) { return 0; }
int tdb_spinlock(TDB_CONTEXT *tdb, int list, int rw_type) { return -1; }
int tdb_spinunlock(TDB_CONTEXT *tdb, int list, int rw_type) { return -1; }

/* Non-spinlock version: remove spinlock pointer */
int tdb_clear_spinlocks(TDB_CONTEXT *tdb)
{
	tdb_off off = (tdb_off)((char *)&tdb->header.rwlocks
				- (char *)&tdb->header);

	tdb->header.rwlocks = 0;
	if (lseek(tdb->fd, off, SEEK_SET) != off
	    || write(tdb->fd, (void *)&tdb->header.rwlocks,
		     sizeof(tdb->header.rwlocks)) 
	    != sizeof(tdb->header.rwlocks))
		return -1;
	return 0;
}
#endif
