#ifndef _PROFILE_H_
#define _PROFILE_H_
/*
   Unix SMB/CIFS implementation.
   store smbd profiling information in shared memory
   Copyright (C) Andrew Tridgell 1999
   Copyright (C) James Peach 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

struct tevent_context;

#ifdef WITH_PROFILE

#define SMBPROFILE_STATS_ALL_SECTIONS \
	SMBPROFILE_STATS_START \
	\
	SMBPROFILE_STATS_SECTION_START(global, "SMBD loop") \
	SMBPROFILE_STATS_COUNT(connect) \
	SMBPROFILE_STATS_COUNT(disconnect) \
	SMBPROFILE_STATS_BASIC(idle) \
	SMBPROFILE_STATS_TIME(cpu_user) \
	SMBPROFILE_STATS_TIME(cpu_system) \
	SMBPROFILE_STATS_COUNT(request) \
	SMBPROFILE_STATS_BASIC(push_sec_ctx) \
	SMBPROFILE_STATS_BASIC(set_sec_ctx) \
	SMBPROFILE_STATS_BASIC(set_root_sec_ctx) \
	SMBPROFILE_STATS_BASIC(pop_sec_ctx) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(syscall, "System Calls") \
	SMBPROFILE_STATS_BASIC(syscall_opendir) \
	SMBPROFILE_STATS_BASIC(syscall_fdopendir) \
	SMBPROFILE_STATS_BASIC(syscall_readdir) \
	SMBPROFILE_STATS_BASIC(syscall_seekdir) \
	SMBPROFILE_STATS_BASIC(syscall_telldir) \
	SMBPROFILE_STATS_BASIC(syscall_rewinddir) \
	SMBPROFILE_STATS_BASIC(syscall_mkdirat) \
	SMBPROFILE_STATS_BASIC(syscall_closedir) \
	SMBPROFILE_STATS_BASIC(syscall_open) \
	SMBPROFILE_STATS_BASIC(syscall_openat) \
	SMBPROFILE_STATS_BASIC(syscall_createfile) \
	SMBPROFILE_STATS_BASIC(syscall_close) \
	SMBPROFILE_STATS_BYTES(syscall_pread) \
	SMBPROFILE_STATS_BYTES(syscall_asys_pread) \
	SMBPROFILE_STATS_BYTES(syscall_pwrite) \
	SMBPROFILE_STATS_BYTES(syscall_asys_pwrite) \
	SMBPROFILE_STATS_BASIC(syscall_lseek) \
	SMBPROFILE_STATS_BYTES(syscall_sendfile) \
	SMBPROFILE_STATS_BYTES(syscall_recvfile) \
	SMBPROFILE_STATS_BASIC(syscall_renameat) \
	SMBPROFILE_STATS_BYTES(syscall_asys_fsync) \
	SMBPROFILE_STATS_BASIC(syscall_stat) \
	SMBPROFILE_STATS_BASIC(syscall_fstat) \
	SMBPROFILE_STATS_BASIC(syscall_lstat) \
	SMBPROFILE_STATS_BASIC(syscall_get_alloc_size) \
	SMBPROFILE_STATS_BASIC(syscall_unlinkat) \
	SMBPROFILE_STATS_BASIC(syscall_chmod) \
	SMBPROFILE_STATS_BASIC(syscall_fchmod) \
	SMBPROFILE_STATS_BASIC(syscall_fchown) \
	SMBPROFILE_STATS_BASIC(syscall_lchown) \
	SMBPROFILE_STATS_BASIC(syscall_chdir) \
	SMBPROFILE_STATS_BASIC(syscall_getwd) \
	SMBPROFILE_STATS_BASIC(syscall_ntimes) \
	SMBPROFILE_STATS_BASIC(syscall_ftruncate) \
	SMBPROFILE_STATS_BASIC(syscall_fallocate) \
	SMBPROFILE_STATS_BASIC(syscall_fcntl_lock) \
	SMBPROFILE_STATS_BASIC(syscall_kernel_flock) \
	SMBPROFILE_STATS_BASIC(syscall_fcntl) \
	SMBPROFILE_STATS_BASIC(syscall_linux_setlease) \
	SMBPROFILE_STATS_BASIC(syscall_fcntl_getlock) \
	SMBPROFILE_STATS_BASIC(syscall_readlinkat) \
	SMBPROFILE_STATS_BASIC(syscall_symlinkat) \
	SMBPROFILE_STATS_BASIC(syscall_linkat) \
	SMBPROFILE_STATS_BASIC(syscall_mknodat) \
	SMBPROFILE_STATS_BASIC(syscall_realpath) \
	SMBPROFILE_STATS_BASIC(syscall_get_quota) \
	SMBPROFILE_STATS_BASIC(syscall_set_quota) \
	SMBPROFILE_STATS_BASIC(syscall_get_sd) \
	SMBPROFILE_STATS_BASIC(syscall_set_sd) \
	SMBPROFILE_STATS_BASIC(syscall_brl_lock) \
	SMBPROFILE_STATS_BASIC(syscall_brl_unlock) \
	SMBPROFILE_STATS_BASIC(syscall_brl_cancel) \
	SMBPROFILE_STATS_BYTES(syscall_asys_getxattrat) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(acl, "ACL Calls") \
	SMBPROFILE_STATS_BASIC(get_nt_acl) \
	SMBPROFILE_STATS_BASIC(get_nt_acl_at) \
	SMBPROFILE_STATS_BASIC(fget_nt_acl) \
	SMBPROFILE_STATS_BASIC(fset_nt_acl) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(statcache, "Stat Cache") \
	SMBPROFILE_STATS_COUNT(statcache_lookups) \
	SMBPROFILE_STATS_COUNT(statcache_misses) \
	SMBPROFILE_STATS_COUNT(statcache_hits) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(SMB, "SMB Calls") \
	SMBPROFILE_STATS_BASIC(SMBmkdir) \
	SMBPROFILE_STATS_BASIC(SMBrmdir) \
	SMBPROFILE_STATS_BASIC(SMBopen) \
	SMBPROFILE_STATS_BASIC(SMBcreate) \
	SMBPROFILE_STATS_BASIC(SMBclose) \
	SMBPROFILE_STATS_BASIC(SMBflush) \
	SMBPROFILE_STATS_BASIC(SMBunlink) \
	SMBPROFILE_STATS_BASIC(SMBmv) \
	SMBPROFILE_STATS_BASIC(SMBgetatr) \
	SMBPROFILE_STATS_BASIC(SMBsetatr) \
	SMBPROFILE_STATS_BASIC(SMBread) \
	SMBPROFILE_STATS_BASIC(SMBwrite) \
	SMBPROFILE_STATS_BASIC(SMBlock) \
	SMBPROFILE_STATS_BASIC(SMBunlock) \
	SMBPROFILE_STATS_BASIC(SMBctemp) \
	SMBPROFILE_STATS_BASIC(SMBmknew) \
	SMBPROFILE_STATS_BASIC(SMBcheckpath) \
	SMBPROFILE_STATS_BASIC(SMBexit) \
	SMBPROFILE_STATS_BASIC(SMBlseek) \
	SMBPROFILE_STATS_BASIC(SMBlockread) \
	SMBPROFILE_STATS_BASIC(SMBwriteunlock) \
	SMBPROFILE_STATS_BASIC(SMBreadbraw) \
	SMBPROFILE_STATS_BASIC(SMBreadBmpx) \
	SMBPROFILE_STATS_BASIC(SMBreadBs) \
	SMBPROFILE_STATS_BASIC(SMBwritebraw) \
	SMBPROFILE_STATS_BASIC(SMBwriteBmpx) \
	SMBPROFILE_STATS_BASIC(SMBwriteBs) \
	SMBPROFILE_STATS_BASIC(SMBwritec) \
	SMBPROFILE_STATS_BASIC(SMBsetattrE) \
	SMBPROFILE_STATS_BASIC(SMBgetattrE) \
	SMBPROFILE_STATS_BASIC(SMBlockingX) \
	SMBPROFILE_STATS_BASIC(SMBtrans) \
	SMBPROFILE_STATS_BASIC(SMBtranss) \
	SMBPROFILE_STATS_BASIC(SMBioctl) \
	SMBPROFILE_STATS_BASIC(SMBioctls) \
	SMBPROFILE_STATS_BASIC(SMBcopy) \
	SMBPROFILE_STATS_BASIC(SMBmove) \
	SMBPROFILE_STATS_BASIC(SMBecho) \
	SMBPROFILE_STATS_BASIC(SMBwriteclose) \
	SMBPROFILE_STATS_BASIC(SMBopenX) \
	SMBPROFILE_STATS_BASIC(SMBreadX) \
	SMBPROFILE_STATS_BASIC(SMBwriteX) \
	SMBPROFILE_STATS_BASIC(SMBtrans2) \
	SMBPROFILE_STATS_BASIC(SMBtranss2) \
	SMBPROFILE_STATS_BASIC(SMBfindclose) \
	SMBPROFILE_STATS_BASIC(SMBfindnclose) \
	SMBPROFILE_STATS_BASIC(SMBtcon) \
	SMBPROFILE_STATS_BASIC(SMBtdis) \
	SMBPROFILE_STATS_BASIC(SMBnegprot) \
	SMBPROFILE_STATS_BASIC(SMBsesssetupX) \
	SMBPROFILE_STATS_BASIC(SMBulogoffX) \
	SMBPROFILE_STATS_BASIC(SMBtconX) \
	SMBPROFILE_STATS_BASIC(SMBdskattr) \
	SMBPROFILE_STATS_BASIC(SMBsearch) \
	SMBPROFILE_STATS_BASIC(SMBffirst) \
	SMBPROFILE_STATS_BASIC(SMBfunique) \
	SMBPROFILE_STATS_BASIC(SMBfclose) \
	SMBPROFILE_STATS_BASIC(SMBnttrans) \
	SMBPROFILE_STATS_BASIC(SMBnttranss) \
	SMBPROFILE_STATS_BASIC(SMBntcreateX) \
	SMBPROFILE_STATS_BASIC(SMBntcancel) \
	SMBPROFILE_STATS_BASIC(SMBntrename) \
	SMBPROFILE_STATS_BASIC(SMBsplopen) \
	SMBPROFILE_STATS_BASIC(SMBsplwr) \
	SMBPROFILE_STATS_BASIC(SMBsplclose) \
	SMBPROFILE_STATS_BASIC(SMBsplretq) \
	SMBPROFILE_STATS_BASIC(SMBsends) \
	SMBPROFILE_STATS_BASIC(SMBsendb) \
	SMBPROFILE_STATS_BASIC(SMBfwdname) \
	SMBPROFILE_STATS_BASIC(SMBcancelf) \
	SMBPROFILE_STATS_BASIC(SMBgetmac) \
	SMBPROFILE_STATS_BASIC(SMBsendstrt) \
	SMBPROFILE_STATS_BASIC(SMBsendend) \
	SMBPROFILE_STATS_BASIC(SMBsendtxt) \
	SMBPROFILE_STATS_BASIC(SMBinvalid) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(Trans2, "Trans2 Calls") \
	SMBPROFILE_STATS_BASIC(Trans2_open) \
	SMBPROFILE_STATS_BASIC(Trans2_findfirst) \
	SMBPROFILE_STATS_BASIC(Trans2_findnext) \
	SMBPROFILE_STATS_BASIC(Trans2_qfsinfo) \
	SMBPROFILE_STATS_BASIC(Trans2_setfsinfo) \
	SMBPROFILE_STATS_BASIC(Trans2_qpathinfo) \
	SMBPROFILE_STATS_BASIC(Trans2_setpathinfo) \
	SMBPROFILE_STATS_BASIC(Trans2_qfileinfo) \
	SMBPROFILE_STATS_BASIC(Trans2_setfileinfo) \
	SMBPROFILE_STATS_BASIC(Trans2_fsctl) \
	SMBPROFILE_STATS_BASIC(Trans2_ioctl) \
	SMBPROFILE_STATS_BASIC(Trans2_findnotifyfirst) \
	SMBPROFILE_STATS_BASIC(Trans2_findnotifynext) \
	SMBPROFILE_STATS_BASIC(Trans2_mkdir) \
	SMBPROFILE_STATS_BASIC(Trans2_session_setup) \
	SMBPROFILE_STATS_BASIC(Trans2_get_dfs_referral) \
	SMBPROFILE_STATS_BASIC(Trans2_report_dfs_inconsistancy) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(NT_transact, "NT Transact Calls") \
	SMBPROFILE_STATS_BASIC(NT_transact_create) \
	SMBPROFILE_STATS_BASIC(NT_transact_ioctl) \
	SMBPROFILE_STATS_BASIC(NT_transact_set_security_desc) \
	SMBPROFILE_STATS_BASIC(NT_transact_notify_change) \
	SMBPROFILE_STATS_BASIC(NT_transact_rename) \
	SMBPROFILE_STATS_BASIC(NT_transact_query_security_desc) \
	SMBPROFILE_STATS_BASIC(NT_transact_get_user_quota) \
	SMBPROFILE_STATS_BASIC(NT_transact_set_user_quota) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_SECTION_START(smb2, "SMB2 Calls") \
	SMBPROFILE_STATS_IOBYTES(smb2_negprot) \
	SMBPROFILE_STATS_IOBYTES(smb2_sesssetup) \
	SMBPROFILE_STATS_IOBYTES(smb2_logoff) \
	SMBPROFILE_STATS_IOBYTES(smb2_tcon) \
	SMBPROFILE_STATS_IOBYTES(smb2_tdis) \
	SMBPROFILE_STATS_IOBYTES(smb2_create) \
	SMBPROFILE_STATS_IOBYTES(smb2_close) \
	SMBPROFILE_STATS_IOBYTES(smb2_flush) \
	SMBPROFILE_STATS_IOBYTES(smb2_read) \
	SMBPROFILE_STATS_IOBYTES(smb2_write) \
	SMBPROFILE_STATS_IOBYTES(smb2_lock) \
	SMBPROFILE_STATS_IOBYTES(smb2_ioctl) \
	SMBPROFILE_STATS_IOBYTES(smb2_cancel) \
	SMBPROFILE_STATS_IOBYTES(smb2_keepalive) \
	SMBPROFILE_STATS_IOBYTES(smb2_find) \
	SMBPROFILE_STATS_IOBYTES(smb2_notify) \
	SMBPROFILE_STATS_IOBYTES(smb2_getinfo) \
	SMBPROFILE_STATS_IOBYTES(smb2_setinfo) \
	SMBPROFILE_STATS_IOBYTES(smb2_break) \
	SMBPROFILE_STATS_SECTION_END \
	\
	SMBPROFILE_STATS_END

/* this file defines the profile structure in the profile shared
   memory area */

/* time values in the following structure are in microseconds */

struct smbprofile_stats_count {
	uint64_t count;		/* number of events */
};

struct smbprofile_stats_time {
	uint64_t time;		/* microseconds */
};

struct smbprofile_stats_time_async {
	uint64_t start;
	struct smbprofile_stats_time *stats;
};

struct smbprofile_stats_basic {
	uint64_t count;		/* number of events */
	uint64_t time;		/* microseconds */
};

struct smbprofile_stats_basic_async {
	uint64_t start;
	struct smbprofile_stats_basic *stats;
};

struct smbprofile_stats_bytes {
	uint64_t count;		/* number of events */
	uint64_t time;		/* microseconds */
	uint64_t idle;		/* idle time compared to 'time' microseconds */
	uint64_t bytes;		/* bytes */
};

struct smbprofile_stats_bytes_async {
	uint64_t start;
	uint64_t idle_start;
	uint64_t idle_time;
	struct smbprofile_stats_bytes *stats;
};

struct smbprofile_stats_iobytes {
	uint64_t count;		/* number of events */
	uint64_t time;		/* microseconds */
	uint64_t idle;		/* idle time compared to 'time' microseconds */
	uint64_t inbytes;	/* bytes read */
	uint64_t outbytes;	/* bytes written */
};

struct smbprofile_stats_iobytes_async {
	uint64_t start;
	uint64_t idle_start;
	uint64_t idle_time;
	struct smbprofile_stats_iobytes *stats;
};

struct profile_stats {
	uint64_t magic;
	struct {
#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name) \
	struct smbprofile_stats_count name##_stats;
#define SMBPROFILE_STATS_TIME(name) \
	struct smbprofile_stats_time name##_stats;
#define SMBPROFILE_STATS_BASIC(name) \
	struct smbprofile_stats_basic name##_stats;
#define SMBPROFILE_STATS_BYTES(name) \
	struct smbprofile_stats_bytes name##_stats;
#define SMBPROFILE_STATS_IOBYTES(name) \
	struct smbprofile_stats_iobytes name##_stats;
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END
	} values;
};

#define _SMBPROFILE_COUNT_INCREMENT(_stats, _area, _v) do { \
	if (smbprofile_state.config.do_count) { \
		(_area)->values._stats.count += (_v); \
		smbprofile_dump_schedule(); \
	} \
} while(0)
#define SMBPROFILE_COUNT_INCREMENT(_name, _area, _v) \
	_SMBPROFILE_COUNT_INCREMENT(_name##_stats, _area, _v)

#define SMBPROFILE_TIME_ASYNC_STATE(_async_name) \
	struct smbprofile_stats_time_async _async_name;
#define _SMBPROFILE_TIME_ASYNC_START(_stats, _area, _async) do { \
	(_async) = (struct smbprofile_stats_time_async) {}; \
	if (smbprofile_state.config.do_times) { \
		(_async).stats = &((_area)->values._stats), \
		(_async).start = profile_timestamp(); \
	} \
} while(0)
#define SMBPROFILE_TIME_ASYNC_START(_name, _area, _async) \
	_SMBPROFILE_TIME_ASYNC_START(_name##_stats, _area, _async)
#define SMBPROFILE_TIME_ASYNC_END(_async) do { \
	if ((_async).start != 0) { \
		(_async).stats->time += profile_timestamp() - (_async).start; \
		(_async) = (struct smbprofile_stats_basic_async) {}; \
		smbprofile_dump_schedule(); \
	} \
} while(0)

#define SMBPROFILE_BASIC_ASYNC_STATE(_async_name) \
	struct smbprofile_stats_basic_async _async_name;
#define _SMBPROFILE_BASIC_ASYNC_START(_stats, _area, _async) do { \
	(_async) = (struct smbprofile_stats_basic_async) {}; \
	if (smbprofile_state.config.do_count) { \
		if (smbprofile_state.config.do_times) { \
			(_async).start = profile_timestamp(); \
			(_async).stats = &((_area)->values._stats); \
		} \
		(_area)->values._stats.count += 1; \
		smbprofile_dump_schedule(); \
	} \
} while(0)
#define SMBPROFILE_BASIC_ASYNC_START(_name, _area, _async) \
	_SMBPROFILE_BASIC_ASYNC_START(_name##_stats, _area, _async)
#define SMBPROFILE_BASIC_ASYNC_END(_async) do { \
	if ((_async).start != 0) { \
		(_async).stats->time += profile_timestamp() - (_async).start; \
		(_async) = (struct smbprofile_stats_basic_async) {}; \
		smbprofile_dump_schedule(); \
	} \
} while(0)

#define _SMBPROFILE_TIMER_ASYNC_START(_stats, _area, _async) do { \
	(_async).stats = &((_area)->values._stats); \
	if (smbprofile_state.config.do_times) { \
		(_async).start = profile_timestamp(); \
	} \
} while(0)
#define _SMBPROFILE_TIMER_ASYNC_SET_IDLE(_async) do { \
	if ((_async).start != 0) { \
		if ((_async).idle_start == 0) { \
			(_async).idle_start = profile_timestamp(); \
		} \
	} \
} while(0)
#define _SMBPROFILE_TIMER_ASYNC_SET_BUSY(_async) do { \
	if ((_async).idle_start != 0) { \
		(_async).idle_time += \
			profile_timestamp() - (_async).idle_start; \
		(_async).idle_start = 0; \
	} \
} while(0)
#define _SMBPROFILE_TIMER_ASYNC_END(_async) do { \
	if ((_async).start != 0) { \
		_SMBPROFILE_TIMER_ASYNC_SET_BUSY(_async); \
		(_async).stats->time += profile_timestamp() - (_async).start; \
		(_async).stats->idle += (_async).idle_time; \
	} \
} while(0)

#define SMBPROFILE_BYTES_ASYNC_STATE(_async_name) \
	struct smbprofile_stats_bytes_async _async_name;
#define _SMBPROFILE_BYTES_ASYNC_START(_stats, _area, _async, _bytes) do { \
	(_async) = (struct smbprofile_stats_bytes_async) {}; \
	if (smbprofile_state.config.do_count) { \
		_SMBPROFILE_TIMER_ASYNC_START(_stats, _area, _async); \
		(_area)->values._stats.count += 1; \
		(_area)->values._stats.bytes += (_bytes); \
		smbprofile_dump_schedule(); \
	} \
} while(0)
#define SMBPROFILE_BYTES_ASYNC_START(_name, _area, _async, _bytes) \
	_SMBPROFILE_BYTES_ASYNC_START(_name##_stats, _area, _async, _bytes)
#define SMBPROFILE_BYTES_ASYNC_SET_IDLE(_async) \
	_SMBPROFILE_TIMER_ASYNC_SET_IDLE(_async)
#define SMBPROFILE_BYTES_ASYNC_SET_BUSY(_async) \
	_SMBPROFILE_TIMER_ASYNC_SET_BUSY(_async)
#define SMBPROFILE_BYTES_ASYNC_END(_async) do { \
	if ((_async).stats != NULL) { \
		_SMBPROFILE_TIMER_ASYNC_END(_async); \
		(_async) = (struct smbprofile_stats_bytes_async) {}; \
		smbprofile_dump_schedule(); \
	} \
} while(0)

#define SMBPROFILE_IOBYTES_ASYNC_STATE(_async_name) \
	struct smbprofile_stats_iobytes_async _async_name;
#define _SMBPROFILE_IOBYTES_ASYNC_START(_stats, _area, _async, _inbytes) do { \
	(_async) = (struct smbprofile_stats_iobytes_async) {}; \
	if (smbprofile_state.config.do_count) { \
		_SMBPROFILE_TIMER_ASYNC_START(_stats, _area, _async); \
		(_area)->values._stats.count += 1; \
		(_area)->values._stats.inbytes += (_inbytes); \
		smbprofile_dump_schedule(); \
	} \
} while(0)
#define SMBPROFILE_IOBYTES_ASYNC_START(_name, _area, _async, _inbytes) \
	_SMBPROFILE_IOBYTES_ASYNC_START(_name##_stats, _area, _async, _inbytes)
#define SMBPROFILE_IOBYTES_ASYNC_SET_IDLE(_async) \
	_SMBPROFILE_TIMER_ASYNC_SET_IDLE(_async)
#define SMBPROFILE_IOBYTES_ASYNC_SET_BUSY(_async) \
	_SMBPROFILE_TIMER_ASYNC_SET_BUSY(_async)
#define SMBPROFILE_IOBYTES_ASYNC_END(_async, _outbytes) do { \
	if ((_async).stats != NULL) { \
		(_async).stats->outbytes += (_outbytes); \
		_SMBPROFILE_TIMER_ASYNC_END(_async); \
		(_async) = (struct smbprofile_stats_iobytes_async) {}; \
		smbprofile_dump_schedule(); \
	} \
} while(0)

extern struct profile_stats *profile_p;

struct smbprofile_global_state {
	struct {
		struct tdb_wrap *db;
		struct tevent_context *ev;
		struct tevent_timer *te;
	} internal;

	struct {
		bool do_count;
		bool do_times;
	} config;

	struct {
		struct profile_stats global;
	} stats;
};

extern struct smbprofile_global_state smbprofile_state;

void smbprofile_dump_schedule_timer(void);
void smbprofile_dump_setup(struct tevent_context *ev);

static inline void smbprofile_dump_schedule(void)
{
	if (likely(smbprofile_state.internal.te != NULL)) {
		return;
	}

	if (unlikely(smbprofile_state.internal.ev == NULL)) {
		return;
	}

	smbprofile_dump_schedule_timer();
}

static inline bool smbprofile_dump_pending(void)
{
	if (smbprofile_state.internal.te == NULL) {
		return false;
	}

	return true;
}

void smbprofile_dump(void);

void smbprofile_cleanup(pid_t pid, pid_t dst);
void smbprofile_stats_accumulate(struct profile_stats *acc,
				 const struct profile_stats *add);
void smbprofile_collect(struct profile_stats *stats);

static inline uint64_t profile_timestamp(void)
{
	struct timespec ts;

	/* we might prefer to use the _COARSE clock variant of CLOCK_MONOTONIC
	   that one is faster but cached and "just" tick-wise precise */
	clock_gettime_mono(&ts);
	return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000); /* usec */
}

#define DO_PROFILE_INC(x) \
	_SMBPROFILE_COUNT_INCREMENT(x##_stats, profile_p, 1); \

#define START_PROFILE(x) \
	struct smbprofile_stats_basic_async __profasync_##x = {}; \
	_SMBPROFILE_BASIC_ASYNC_START(x##_stats, profile_p, __profasync_##x);

#define START_PROFILE_BYTES(x,n) \
	struct smbprofile_stats_bytes_async __profasync_##x = {}; \
	_SMBPROFILE_BYTES_ASYNC_START(x##_stats, profile_p, __profasync_##x, n);

#define END_PROFILE(x) \
	SMBPROFILE_BASIC_ASYNC_END(__profasync_##x)

#define END_PROFILE_BYTES(x) \
	SMBPROFILE_BYTES_ASYNC_END(__profasync_##x)

#define PROFILE_TIMESTAMP(x) clock_gettime_mono(x)

#else /* WITH_PROFILE */

#define SMBPROFILE_COUNT_INCREMENT(_name, _area, _v)

#define SMBPROFILE_TIME_ASYNC_STATE(_async_name)
#define SMBPROFILE_TIME_ASYNC_START(_name, _area, _async)
#define SMBPROFILE_TIME_ASYNC_END(_async)

#define SMBPROFILE_BASIC_ASYNC_STATE(_async_name)
#define SMBPROFILE_BASIC_ASYNC_START(_name, _area, _async)
#define SMBPROFILE_BASIC_ASYNC_END(_async)

#define SMBPROFILE_BYTES_ASYNC_STATE(_async_name)
#define SMBPROFILE_BYTES_ASYNC_START(_name, _area, _async, _inbytes)
#define SMBPROFILE_BYTES_ASYNC_SET_IDLE(_async)
#define SMBPROFILE_BYTES_ASYNC_SET_BUSY(_async)
#define SMBPROFILE_BYTES_ASYNC_END(_async)

#define SMBPROFILE_IOBYTES_ASYNC_STATE(_async_name)
#define SMBPROFILE_IOBYTES_ASYNC_START(_name, _area, _async, _inbytes)
#define SMBPROFILE_IOBYTES_ASYNC_SET_IDLE(_async)
#define SMBPROFILE_IOBYTES_ASYNC_SET_BUSY(_async)
#define SMBPROFILE_IOBYTES_ASYNC_END(_async, _outbytes)

#define DO_PROFILE_INC(x)
#define START_PROFILE(x)
#define START_PROFILE_BYTES(x,n)
#define END_PROFILE(x)
#define END_PROFILE_BYTES(x)

#define PROFILE_TIMESTAMP(x) (*(x)=(struct timespec){0})

static inline bool smbprofile_dump_pending(void)
{
	return false;
}

static inline void smbprofile_dump_setup(struct tevent_context *ev)
{
	return;
}

static inline void smbprofile_dump(void)
{
	return;
}

static inline void smbprofile_cleanup(pid_t pid, pid_t dst)
{
	return;
}

#endif /* WITH_PROFILE */

/* The following definitions come from profile/profile.c  */
struct server_id;

void set_profile_level(int level, const struct server_id *src);

struct messaging_context;
bool profile_setup(struct messaging_context *msg_ctx, bool rdonly);

#endif
