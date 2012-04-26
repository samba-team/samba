/* 
   ctdb lock handling 
   provide API to do non-blocking locks for single or all databases

   Copyright (C) Amitay Isaacs  2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include "includes.h"
#include "include/ctdb_private.h"
#include "include/ctdb_protocol.h"
#include "tevent.h"
#include "tdb.h"
#include "db_wrap.h"
#include "system/filesys.h"

/* 
 * Locking API
 *
 * 1. Try locking with non-blocking tdb calls
 * 2. If it fails, create a child process to do blocking calls
 * 3. If the child process cannot get locks within certain time, 
 *    diagnose using /proc/locks and log warning message
 * 4. Additionally terminate the blocking process
 *
 * ctdb_lock_record()
 * ctdb_lock_db()
 * ctdb_lock_alldb()
 */

enum lock_db_type {
	LOCK_DB_RECORD,
	LOCK_DB_ONE,
	LOCK_DB_ALL_PRIO,
};

struct lock_db_handle {
	enum lock_db_type type;
	struct lock_db_handle *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	uint32_t priority;
	void (*lock_callback)(void *);
	void *lock_private_data;
	void (*timeout_callback)(void *);
	void *timeout_private_data;
	int fd[2];
	pid_t child;
	struct tevent_fd *tfd;
	struct tevent_timer *ttimer;
	struct timeval start_time;
	bool lock_in_parent;
};

struct lock_record {
	ino_t inode;
	off_t start, end;
};

static bool ignore_db(struct ctdb_db_context *ctdb_db)
{
	const char *name = ctdb_db->db_name;
	return (strstr(name, "notify") || strstr(name, "serverid"));
}


/*
 * lock all databases
 */
static int ctdb_lockall(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (ignore_db(ctdb_db)) {
			continue;
		}
		if (tdb_lockall(ctdb_db->ltdb->tdb) != 0) {
			DEBUG(DEBUG_ERR, ("Failed to lock database %s\n", ctdb_db->db_name));
			return -1;
		}
	}

	return 0;
}


/*
 * unlock all databases
 */
static int ctdb_unlockall(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (ignore_db(ctdb_db)) {
			continue;
		}
		if (tdb_unlockall(ctdb_db->ltdb->tdb) != 0) {
			DEBUG(DEBUG_ERR, ("Failed to unlock database %s\n", ctdb_db->db_name));
			return -1;
		}
	}

	return 0;
}


/*
 * lock all databases - mark only
 */
static int ctdb_lockall_mark(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;

	if (priority < 1 || priority > NUM_DB_PRIORITIES) {
		DEBUG(DEBUG_ERR, ("Illegal priority %u in ctdb_lockall_mark", priority));
		return -1;
	}

	/* TODO: What is this? */
	if (ctdb->freeze_mode[priority] != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Attempt to mark all databases locked when not frozen"));
		return -1;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (ignore_db(ctdb_db)) {
			continue;
		}
#if 0
		/* FIXME: Why do we need this? Isn't tdb_lockall_mark sufficient? */
		if (tdb_transaction_write_lock_mark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
#endif
		if (tdb_lockall_mark(ctdb_db->ltdb->tdb) != 0) {
			/* FIXME: Shouldn't we unmark here? */
			return -1;
		}
	}

	return 0;
}


/*
 * lock all databases - unmark only
 */
static int ctdb_lockall_unmark(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;

	if (priority < 1 || priority > NUM_DB_PRIORITIES) {
		DEBUG(DEBUG_ERR, ("Illegal priority %u in ctdb_lockall_unmark", priority));
		return -1;
	}

	/* TODO: What is this? */
	if (ctdb->freeze_mode[priority] != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Attempt to unmark all databases locked when not frozen"));
		return -1;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (ignore_db(ctdb_db)) {
			continue;
		}
#if 0
		if (tdb_transaction_write_lock_unmark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
#endif
		if (tdb_lockall_unmark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * Lock record / db / all db depending on h->type
 * Called from parent context.
 */
static bool ctdb_lock_item_nonblock(struct lock_db_handle *h)
{
	bool status = false;

	switch (h->type) {
	case LOCK_DB_RECORD:
		if (tdb_chainlock_nonblock(h->ctdb_db->ltdb->tdb, h->key) == 0) {
			status = true;
		}
		break;

	case LOCK_DB_ONE:
		if (tdb_lockall_nonblock(h->ctdb_db->ltdb->tdb) == 0) {
			status = true;
		}
		break;

	case LOCK_DB_ALL_PRIO:
		/* Is there a chance we will ever succeed here? */
		status = false;
		break;
	}

	return status;
}


/*
 * Lock record / db / all-db depending on h->type
 * Called from child context.
 */
static bool ctdb_lock_item(struct lock_db_handle *h)
{
	bool status = false;

	switch (h->type) {
	case LOCK_DB_RECORD:
		if (tdb_chainlock(h->ctdb_db->ltdb->tdb, h->key) == 0) {
			status = true;
		}
		break;

	case LOCK_DB_ONE:
		if (tdb_lockall(h->ctdb_db->ltdb->tdb) == 0) {
			status = true;
		}
		break;

	case LOCK_DB_ALL_PRIO:
		if (ctdb_lockall(h->ctdb, h->priority) == 0) {
			status = true;
		}
		break;
	}

	return status;
}


/*
 * Unlock record / db / all-db depending on h->type
 */
bool ctdb_unlock_item(struct lock_db_handle *h)
{
	bool status = true;

	switch (h->type) {
	case LOCK_DB_RECORD:
		tdb_chainunlock(h->ctdb_db->ltdb->tdb, h->key);
		break;

	case LOCK_DB_ONE:
		tdb_unlockall(h->ctdb_db->ltdb->tdb);
		break;

	case LOCK_DB_ALL_PRIO:
		ctdb_unlockall(h->ctdb, h->priority);
		break;
	}

	return status;
}


/*
 * Parsing a line from /proc/locks, 
 *
 * FIXME: This should be moved to system_linux.c
 */
static bool parse_proc_locks_line(char *line, pid_t *pid,
				  struct lock_record *curlock)
{
	char *ptr, *saveptr;

	/* 57: POSIX  ADVISORY  WRITE 1301 00:11:15132 0 EOF */

	/* Id: */
	ptr = strtok_r(line, " ", &saveptr);
	if (ptr == NULL) return false;

	/* POSIX */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL || strcmp(ptr, "POSIX") != 0) {
		return false;
	}

	/* ADVISORY */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;

	/* WRITE */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL || strcmp(ptr, "WRITE") != 0) {
		return false;
	}

	/* PID */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	*pid = atoi(ptr);

	/* MAJOR:MINOR:INODE */
	ptr = strtok_r(NULL, " :", &saveptr);
	if (ptr == NULL) return false;
	ptr = strtok_r(NULL, " :", &saveptr);
	if (ptr == NULL) return false;
	ptr = strtok_r(NULL, " :", &saveptr);
	if (ptr == NULL) return false;
	curlock->inode = atol(ptr);

	/* START OFFSET */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	curlock->start = atol(ptr);

	/* END OFFSET */
	ptr = strtok_r(NULL, " ", &saveptr);
	if (ptr == NULL) return false;
	if (strncmp(ptr, "EOF", 3) == 0) {
		curlock->end = (off_t)-1;
	} else {
		curlock->end = atol(ptr);
	}

	return true;
}


/*
 * Find the process name from proceed id
 *
 * FIXME: This should be moved to system_linux.c
 */
static char *get_process_name(int pid)
{
	char path[32];
	char buf[PATH_MAX];
	char *ptr;
	int n;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	n = readlink(path, buf, sizeof(buf));
	if (n < 0) {
		return NULL;
	}

	/* Remove any extra fields */
	buf[n] = '\0';
	ptr = strtok(buf, " ");
	return strdup(ptr);
}


static bool get_tdb_lock_info(struct ctdb_db_context *ctdb_db, TDB_DATA key,
			       struct lock_record *rec)
{
	struct stat statbuf;

	if (stat(ctdb_db->db_path, &statbuf) < 0) {
		DEBUG(DEBUG_ERR, ("Fail to get inode info for TDB %s", ctdb_db->db_path));
		return false;
	}
	rec->inode = statbuf.st_ino;

	/* TODO: find the required offset from key */
	rec->start = 0;
	rec->end = (off_t)-1;
	return true;
}


static bool get_blocker_pid(struct lock_record *reqlock, pid_t *blocker_pid)
{
	FILE *fp;
	char buf[1024];
	char *ptr;
	pid_t pid;
	struct lock_record curlock;
	bool status = false;

	fp = fopen("/proc/locks", "r");
	if (!fp) {
		DEBUG(DEBUG_ERR, ("Failed to read locks information"));
		return false;
	}
	while ((ptr = fgets(buf, sizeof(buf), fp)) != NULL) {
		if (! parse_proc_locks_line(buf, &pid, &curlock)) {
			continue;
		}

		if ((curlock.inode == reqlock->inode) && 
		    (curlock.start > reqlock->end || 
		     curlock.end < reqlock->start)) {
			/* Outside the required range */
			continue;
		}
		*blocker_pid = pid;
		status = true;
		break;
	}
	fclose(fp);

	if (!status) {
		DEBUG(DEBUG_WARNING, ("Failed to find blocking culprit"));
	}

	return status;
}


static void terminate_pid(pid_t blocker_pid, bool terminate)
{
	char *process_name;

	process_name = get_process_name(blocker_pid);
	if (process_name) {
		DEBUG(DEBUG_INFO, ("Process %s (pid=%d) is blocking", process_name, blocker_pid));
		free(process_name);
	}
	
	/* Kill process if required */
	if (terminate) {
		kill(blocker_pid, SIGKILL);
	}
}


/*
 * Find processes that holds lock we are interested in
 */
void ctdb_lock_find_blocker(struct lock_db_handle *h, bool terminate)
{
	struct lock_record reqlock;
	pid_t blocker_pid;
	struct ctdb_db_context *ctdb_db;

	switch (h->type) {
	case LOCK_DB_RECORD:
		if (!get_tdb_lock_info(h->ctdb_db, h->key, &reqlock)) {
			return;
		}
		if (!get_blocker_pid(&reqlock, &blocker_pid)) {
			return;
		}
		terminate_pid(blocker_pid, terminate);
		break;

	case LOCK_DB_ONE:
		if (!get_tdb_lock_info(h->ctdb_db, tdb_null, &reqlock)) {
			return;
		}
		if (!get_blocker_pid(&reqlock, &blocker_pid)) {
			return;
		}
		terminate_pid(blocker_pid, terminate);
		break;

	case LOCK_DB_ALL_PRIO:
		for (ctdb_db = h->ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
			if (!get_tdb_lock_info(ctdb_db, tdb_null, &reqlock)) {
				continue;
			}
			if (!get_blocker_pid(&reqlock, &blocker_pid)) {
				continue;
			}
			terminate_pid(blocker_pid, terminate);
		}
		break;
	}
}


/*
 * Destructor to kill the child locking process
 */
static int lock_db_destructor(struct lock_db_handle *h)
{
	kill(h->child, SIGKILL);
	return 0;
}


/*
 * Callback routine when the required locks are obtained.
 * Called from parent context
 */
static void lock_db_handler(struct tevent_context *ev, 
			    struct tevent_fd *tfd,
			    uint16_t flags,
			    void *private_data)
{
	struct lock_db_handle *h;
	TALLOC_CTX *tmp_ctx;

	h = talloc_get_type_abort(private_data, struct lock_db_handle);

	/* cancel the timeout event */
	if (h->ttimer) {
		talloc_free(h->ttimer);
		h->ttimer = NULL;
	}

	tmp_ctx = talloc_new(ev);
	talloc_steal(tmp_ctx, h);
	
	/* TODO: read the byte from the pipe and see if the lock succeeded */

	switch (h->type) {
	case LOCK_DB_RECORD:
		tdb_chainlock_mark(h->ctdb_db->ltdb->tdb, h->key);
		h->lock_callback(h->lock_private_data);
		tdb_chainlock_unmark(h->ctdb_db->ltdb->tdb, h->key);
		break;

	case LOCK_DB_ONE:
		tdb_lockall_mark(h->ctdb_db->ltdb->tdb);
		h->lock_callback(h->lock_private_data);
		tdb_lockall_unmark(h->ctdb_db->ltdb->tdb);
		break;

	case LOCK_DB_ALL_PRIO:
		ctdb_lockall_mark(h->ctdb, h->priority);
		h->lock_callback(h->lock_private_data);
		ctdb_lockall_unmark(h->ctdb, h->priority);
		break;
	} 

	talloc_free(tmp_ctx);
}


/*
 * Callback routine when required locks are not obtained within timeout
 * Called from parent context
 */
static void lock_db_timeout_handler(struct tevent_context *ev,
				    struct tevent_timer *ttimer,
				    struct timeval current_time,
				    void *private_data)
{
	struct lock_db_handle *h;
	TALLOC_CTX *tmp_ctx;

	h = talloc_get_type_abort(private_data, struct lock_db_handle);

	/* cancel the fd event */
	if (h->tfd) {
		talloc_free(h->tfd);
		h->tfd = NULL;
	}

	tmp_ctx = talloc_new(ev);
	talloc_steal(tmp_ctx, h);

	/* TODO: Find out which process is holding required lock */
	ctdb_lock_find_blocker(h, false);

	if (h->timeout_callback) {
		h->timeout_callback(h->timeout_private_data);
	}

	talloc_free(tmp_ctx);
}


/*
 * Lock record / db / all dbs depending on type
 * Set up callback handler and timeout handler
 */
static struct lock_db_handle *ctdb_lock_internal(struct ctdb_context *ctdb,
						 struct ctdb_db_context *ctdb_db,
						 TDB_DATA key,
						 uint32_t priority,
						 void (*lock_callback)(void *private_data),
						 void *lock_private_data,
						 void (*timeout_callback)(void *private_data),
						 void *timeout_private_data,
						 enum lock_db_type type)
{
	struct lock_db_handle *result;
	int ret;
	pid_t parent;

	if (lock_callback == NULL) {
		DEBUG(DEBUG_WARNING, ("No callback function specified, not locking"));
		return NULL;
	}

	if ((result = talloc_zero(ctdb, struct lock_db_handle)) == NULL) {
		return NULL;
	}

	result->type = type;
	result->ctdb = ctdb;

	switch (type) {
	case LOCK_DB_RECORD:
		result->ctdb_db = ctdb_db;
		result->key = key;
		break;

	case LOCK_DB_ONE:
		result->ctdb_db = ctdb_db;
		break;

	case LOCK_DB_ALL_PRIO:
		result->priority = priority;
		break;
	}

	result->lock_callback = lock_callback;
	result->lock_private_data = lock_private_data;
	result->timeout_callback = timeout_callback;
	result->timeout_private_data = timeout_private_data;
	result->lock_in_parent = false;
	
	result->child = -1;

	if (ctdb_lock_item_nonblock(result) == 0) {
		result->lock_callback(result->lock_private_data);
		ctdb_unlock_item(result);
		/* FIXME: How is result destroyed? */
		return result;
	}

	ret = pipe(result->fd);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to create pipe for ctdb_lock_internal\n"));
		talloc_free(result);
		return NULL;
	}

	parent = getpid();
	result->child = ctdb_fork(ctdb);

	if (result->child == (pid_t)-1) {
		DEBUG(DEBUG_ERR, ("Failed to fork child for ctdb_lock_internal\n"));
		close(result->fd[0]);
		close(result->fd[1]);
		talloc_free(result);
		return NULL;
	}

	/* Child process - do locking here */
	if (result->child == 0) {
		char c;
		close(result->fd[0]);
		if (ctdb_lock_item(result)) {
			c = 0;
		} else {
			c = -1;
		}
		write(result->fd[1], &c, 1);

		/* Hang around, but if parent dies, terminate */
		while (kill(parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	/* Set up callback, when the child process gets lock */
	close(result->fd[1]);
	set_close_on_exec(result->fd[0]);

	talloc_set_destructor(result, lock_db_destructor);

	result->tfd = tevent_add_fd(ctdb->ev, result, result->fd[0],
				EVENT_FD_READ, lock_db_handler, 
				(void *)result);
	if (result->tfd == NULL) {
		talloc_free(result);
		return NULL;
	}
	tevent_fd_set_auto_close(result->tfd);

	/* Set up callback if we timeout waiting for child to get lock */
	result->ttimer = tevent_add_timer(ctdb->ev, 
					  result, 
					  timeval_current_ofs(ctdb->tunable.control_timeout, 0),
					  lock_db_timeout_handler,
					  (void *)result);

	result->start_time = timeval_current();
	return result;
}


/*
 * obtain a lock on a record in a database
 */
struct lock_db_handle *ctdb_lock_record(struct ctdb_context *ctdb,
					struct ctdb_db_context *ctdb_db,
					TDB_DATA key,
					void (*lock_callback)(void *private_data),
					void *lock_private_data,
					void (*timeout_callback)(void *private_data),
					void *timeout_private_data)
{
	return ctdb_lock_internal(ctdb, 
				  ctdb_db, 
				  key, 
				  0,
				  lock_callback, 
				  lock_private_data,
				  timeout_callback,
				  timeout_private_data,
				  LOCK_DB_RECORD);
}


/*
 * obtain a lock on a database
 */
struct lock_db_handle *ctdb_lock_db(struct ctdb_context *ctdb,
					struct ctdb_db_context *ctdb_db,
					void (*lock_callback)(void *private_data),
					void *lock_private_data,
					void (*timeout_callback)(void *private_data),
					void *timeout_private_data)
{
	return ctdb_lock_internal(ctdb, 
				  ctdb_db, 
				  tdb_null, 
				  0,
				  lock_callback, 
				  lock_private_data,
				  timeout_callback,
				  timeout_private_data,
				  LOCK_DB_ONE);
}


/*
 * Obtain locks on all databases
 */
struct lock_db_handle *ctdb_lock_alldb(struct ctdb_context *ctdb,
					uint32_t priority,
					void (*lock_callback)(void *private_data),
					void *lock_private_data,
					void (*timeout_callback)(void *private_data),
					void *timeout_private_data)
{
	return ctdb_lock_internal(ctdb, 
				  NULL, 
				  tdb_null, 
				  priority,
				  lock_callback, 
				  lock_private_data,
				  timeout_callback,
				  timeout_private_data,
				  LOCK_DB_ALL_PRIO);
}
