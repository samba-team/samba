/* 
   Unix SMB/CIFS implementation.
   thread model: standard (1 thread per client connection)
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "pthread.h"
#ifdef HAVE_BACKTRACE
#include "execinfo.h"
#endif

static void *connection_thread(void *thread_parm)
{
	struct event_context *ev = thread_parm;
	/* wait for action */
	event_loop_wait(ev);
	
#if 0
	pthread_cleanup_pop(1);  /* will invoke terminate_mt_connection() */
#endif
	return NULL;
}

static int get_id(struct smbsrv_request *req)
{
	return (int)pthread_self();
}

/*
  called when a listening socket becomes readable
*/
static void accept_connection(struct event_context *ev, struct fd_event *fde, 
			      time_t t, uint16_t flags)
{
	int accepted_fd, rc;
	struct sockaddr addr;
	socklen_t in_addrlen = sizeof(addr);
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	struct model_ops *model_ops = fde->private;
	
	/* accept an incoming connection */
	accepted_fd = accept(fde->fd,&addr,&in_addrlen);
			
	if (accepted_fd == -1) {
		DEBUG(0,("accept_connection_thread: accept: %s\n",
			 strerror(errno)));
		return;
	}
	
	/* create new detached thread for this connection.  The new
	   thread gets a new event_context with a single fd_event for
	   receiving from the new socket. We set that thread running
	   with the main event loop, then return. When we return the
	   main event_context is continued.
	*/
	ev = event_context_init();
	MUTEX_LOCK_BY_ID(MUTEX_SMBD);
	init_smbsession(ev, model_ops, accepted_fd, smbd_read_handler);
	MUTEX_UNLOCK_BY_ID(MUTEX_SMBD);
	
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&thread_id, &thread_attr, &connection_thread, ev);
	pthread_attr_destroy(&thread_attr);
	if (rc == 0) {
		DEBUG(4,("accept_connection_thread: created thread_id=%lu for fd=%d\n", 
			(unsigned long int)thread_id, accepted_fd));
	} else {
		DEBUG(0,("accept_connection_thread: thread create failed for fd=%d, rc=%d\n", accepted_fd, rc));
	}
}


/*
  called when a rpc listening socket becomes readable
*/
static void accept_rpc_connection(struct event_context *ev, struct fd_event *fde, time_t t, uint16_t flags)
{
	int accepted_fd, rc;
	struct sockaddr addr;
	socklen_t in_addrlen = sizeof(addr);
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	
	/* accept an incoming connection */
	accepted_fd = accept(fde->fd,&addr,&in_addrlen);
			
	if (accepted_fd == -1) {
		DEBUG(0,("accept_connection_thread: accept: %s\n",
			 strerror(errno)));
		return;
	}
	
	ev = event_context_init();
	MUTEX_LOCK_BY_ID(MUTEX_SMBD);
	init_rpc_session(ev, fde->private, accepted_fd);
	MUTEX_UNLOCK_BY_ID(MUTEX_SMBD);
	
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&thread_id, &thread_attr, &connection_thread, ev);
	pthread_attr_destroy(&thread_attr);
	if (rc == 0) {
		DEBUG(4,("accept_connection_thread: created thread_id=%lu for fd=%d\n", 
			(unsigned long int)thread_id, accepted_fd));
	} else {
		DEBUG(0,("accept_connection_thread: thread create failed for fd=%d, rc=%d\n", accepted_fd, rc));
	}
}

/* called when a SMB connection goes down */
static void terminate_connection(struct smbsrv_context *server, const char *reason) 
{
	server_terminate(server);

	/* terminate this thread */
	pthread_exit(NULL);  /* thread cleanup routine will do actual cleanup */
}

/* called when a rpc connection goes down */
static void terminate_rpc_connection(void *r, const char *reason) 
{
	rpc_server_terminate(r);

	/* terminate this thread */
	pthread_exit(NULL);  /* thread cleanup routine will do actual cleanup */
}

/*
  mutex init function for thread model
*/
static int thread_mutex_init(smb_mutex_t *mutex, const char *name)
{
	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	mutex->mutex = memdup(&m, sizeof(m));
	if (! mutex->mutex) {
		errno = ENOMEM;
		return -1;
	}
	return pthread_mutex_init((pthread_mutex_t *)mutex->mutex, NULL);
}

/*
  mutex destroy function for thread model
*/
static int thread_mutex_destroy(smb_mutex_t *mutex, const char *name)
{
	return pthread_mutex_destroy((pthread_mutex_t *)mutex->mutex);
}

static void mutex_start_timer(struct timeval *tp1)
{
	gettimeofday(tp1,NULL);
}

static double mutex_end_timer(struct timeval tp1)
{
	struct timeval tp2;
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) + 
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}

/*
  mutex lock function for thread model
*/
static int thread_mutex_lock(smb_mutex_t *mutexP, const char *name)
{
	pthread_mutex_t *mutex = (pthread_mutex_t *)mutexP->mutex;
	int rc;
	double t;
	struct timeval tp1;
	/* Test below is ONLY for debugging */
	if ((rc = pthread_mutex_trylock(mutex))) {
		if (rc == EBUSY) {
			mutex_start_timer(&tp1);
			printf("mutex lock: thread %d, lock %s not available\n", 
				(uint32_t)pthread_self(), name);
			print_suspicious_usage("mutex_lock", name);
			pthread_mutex_lock(mutex);
			t = mutex_end_timer(tp1);
			printf("mutex lock: thread %d, lock %s now available, waited %g seconds\n", 
				(uint32_t)pthread_self(), name, t);
			return 0;
		}
		printf("mutex lock: thread %d, lock %s failed rc=%d\n", 
				(uint32_t)pthread_self(), name, rc);
		SMB_ASSERT(errno == 0); /* force error */
	}
	return 0;
}

/* 
   mutex unlock for thread model
*/
static int thread_mutex_unlock(smb_mutex_t *mutex, const char *name)
{
	return pthread_mutex_unlock((pthread_mutex_t *)mutex->mutex);
}

/*****************************************************************
 Read/write lock routines.
*****************************************************************/  
/*
  rwlock init function for thread model
*/
static int thread_rwlock_init(smb_rwlock_t *rwlock, const char *name)
{
	pthread_rwlock_t m = PTHREAD_RWLOCK_INITIALIZER;
	rwlock->rwlock = memdup(&m, sizeof(m));
	if (! rwlock->rwlock) {
		errno = ENOMEM;
		return -1;
	}
	return pthread_rwlock_init((pthread_rwlock_t *)rwlock->rwlock, NULL);
}

/*
  rwlock destroy function for thread model
*/
static int thread_rwlock_destroy(smb_rwlock_t *rwlock, const char *name)
{
	return pthread_rwlock_destroy((pthread_rwlock_t *)rwlock->rwlock);
}

/*
  rwlock lock for read function for thread model
*/
static int thread_rwlock_lock_read(smb_rwlock_t *rwlockP, const char *name)
{
	pthread_rwlock_t *rwlock = (pthread_rwlock_t *)rwlockP->rwlock;
	int rc;
	double t;
	struct timeval tp1;
	/* Test below is ONLY for debugging */
	if ((rc = pthread_rwlock_tryrdlock(rwlock))) {
		if (rc == EBUSY) {
			mutex_start_timer(&tp1);
			printf("rwlock lock_read: thread %d, lock %s not available\n", 
				(uint32_t)pthread_self(), name);
			print_suspicious_usage("rwlock_lock_read", name);
			pthread_rwlock_rdlock(rwlock);
			t = mutex_end_timer(tp1);
			printf("rwlock lock_read: thread %d, lock %s now available, waited %g seconds\n", 
				(uint32_t)pthread_self(), name, t);
			return 0;
		}
		printf("rwlock lock_read: thread %d, lock %s failed rc=%d\n", 
				(uint32_t)pthread_self(), name, rc);
		SMB_ASSERT(errno == 0); /* force error */
	}
	return 0;
}

/*
  rwlock lock for write function for thread model
*/
static int thread_rwlock_lock_write(smb_rwlock_t *rwlockP, const char *name)
{
	pthread_rwlock_t *rwlock = (pthread_rwlock_t *)rwlockP->rwlock;
	int rc;
	double t;
	struct timeval tp1;
	/* Test below is ONLY for debugging */
	if ((rc = pthread_rwlock_trywrlock(rwlock))) {
		if (rc == EBUSY) {
			mutex_start_timer(&tp1);
			printf("rwlock lock_write: thread %d, lock %s not available\n", 
				(uint32_t)pthread_self(), name);
			print_suspicious_usage("rwlock_lock_write", name);
			pthread_rwlock_wrlock(rwlock);
			t = mutex_end_timer(tp1);
			printf("rwlock lock_write: thread %d, lock %s now available, waited %g seconds\n", 
				(uint32_t)pthread_self(), name, t);
			return 0;
		}
		printf("rwlock lock_write: thread %d, lock %s failed rc=%d\n", 
				(uint32_t)pthread_self(), name, rc);
		SMB_ASSERT(errno == 0); /* force error */
	}
	return 0;
}


/* 
   rwlock unlock for thread model
*/
static int thread_rwlock_unlock(smb_rwlock_t *rwlock, const char *name)
{
	return pthread_rwlock_unlock((pthread_rwlock_t *)rwlock->rwlock);
}

/*****************************************************************
 Log suspicious usage (primarily for possible thread-unsafe behavior.
*****************************************************************/  
static void thread_log_suspicious_usage(const char* from, const char* info)
{
	DEBUG(1,("log_suspicious_usage: from %s info='%s'\n", from, info));
#ifdef HAVE_BACKTRACE
	{
		void *addresses[10];
		int num_addresses = backtrace(addresses, 8);
		char **bt_symbols = backtrace_symbols(addresses, num_addresses);
		int i;

		if (bt_symbols) {
			for (i=0; i<num_addresses; i++) {
				DEBUG(1,("log_suspicious_usage: %s%s\n", DEBUGTAB(1), bt_symbols[i]));
			}
			free(bt_symbols);
		}
	}
#endif
}

/*****************************************************************
 Log suspicious usage to stdout (primarily for possible thread-unsafe behavior.
 Used in mutex code where DEBUG calls would cause recursion.
*****************************************************************/  
static void thread_print_suspicious_usage(const char* from, const char* info)
{
	printf("log_suspicious_usage: from %s info='%s'\n", from, info);
#ifdef HAVE_BACKTRACE
	{
		void *addresses[10];
		int num_addresses = backtrace(addresses, 8);
		char **bt_symbols = backtrace_symbols(addresses, num_addresses);
		int i;

		if (bt_symbols) {
			for (i=0; i<num_addresses; i++) {
				printf("log_suspicious_usage: %s%s\n", DEBUGTAB(1), bt_symbols[i]);
			}
			free(bt_symbols);
		}
	}
#endif
}

static uint32_t thread_get_task_id(void)
{
	return (uint32_t)pthread_self();
}

static void thread_log_task_id(int fd)
{
	char *s;
	
	asprintf(&s, "thread %u: ", (uint32_t)pthread_self());
	write(fd, s, strlen(s));
	free(s);
}
/****************************************************************************
catch serious errors
****************************************************************************/
static void thread_sig_fault(int sig)
{
	DEBUG(0,("===============================================================\n"));
	DEBUG(0,("TERMINAL ERROR: Recursive signal %d in thread %lu (%s)\n",sig,(unsigned long int)pthread_self(),SAMBA_VERSION_STRING));
	DEBUG(0,("===============================================================\n"));
	exit(1); /* kill the whole server for now */
}

/*******************************************************************
setup our recursive fault handlers
********************************************************************/
static void thread_fault_setup(void)
{
#ifdef SIGSEGV
	CatchSignal(SIGSEGV,SIGNAL_CAST thread_sig_fault);
#endif
#ifdef SIGBUS
	CatchSignal(SIGBUS,SIGNAL_CAST thread_sig_fault);
#endif
#ifdef SIGABRT
	CatchSignal(SIGABRT,SIGNAL_CAST thread_sig_fault);
#endif
}

/*******************************************************************
report a fault in a thread
********************************************************************/
static void thread_fault_handler(int sig)
{
	static int counter;
	
	/* try to catch recursive faults */
	thread_fault_setup();
	
	counter++;	/* count number of faults that have occurred */

	DEBUG(0,("===============================================================\n"));
	DEBUG(0,("INTERNAL ERROR: Signal %d in thread %lu (%s)\n",sig,(unsigned long int)pthread_self(),SAMBA_VERSION_STRING));
	DEBUG(0,("Please read the file BUGS.txt in the distribution\n"));
	DEBUG(0,("===============================================================\n"));
#ifdef HAVE_BACKTRACE
	{
		void *addresses[10];
		int num_addresses = backtrace(addresses, 8);
		char **bt_symbols = backtrace_symbols(addresses, num_addresses);
		int i;

		if (bt_symbols) {
			for (i=0; i<num_addresses; i++) {
				DEBUG(1,("fault_report: %s%s\n", DEBUGTAB(1), bt_symbols[i]));
			}
			free(bt_symbols);
		}
	}
#endif
	pthread_exit(NULL); /* terminate failing thread only */
}

/*
  called when the process model is selected
*/
static void model_startup(void)
{
	struct mutex_ops m_ops;
	struct debug_ops d_ops;

	ZERO_STRUCT(m_ops);
	ZERO_STRUCT(d_ops);

	smbd_process_init();

	/* register mutex/rwlock handlers */
	m_ops.mutex_init = thread_mutex_init;
	m_ops.mutex_lock = thread_mutex_lock;
	m_ops.mutex_unlock = thread_mutex_unlock;
	m_ops.mutex_destroy = thread_mutex_destroy;
	
	m_ops.rwlock_init = thread_rwlock_init;
	m_ops.rwlock_lock_write = thread_rwlock_lock_write;
	m_ops.rwlock_lock_read = thread_rwlock_lock_read;
	m_ops.rwlock_unlock = thread_rwlock_unlock;
	m_ops.rwlock_destroy = thread_rwlock_destroy;

	register_mutex_handlers("thread", &m_ops);

	register_fault_handler("thread", thread_fault_handler);

	d_ops.log_suspicious_usage = thread_log_suspicious_usage;
	d_ops.print_suspicious_usage = thread_print_suspicious_usage;
	d_ops.get_task_id = thread_get_task_id;
	d_ops.log_task_id = thread_log_task_id;

	register_debug_handlers("thread", &d_ops);	
}

static void thread_exit_server(struct smbsrv_context *smb, const char *reason)
{
	DEBUG(1,("thread_exit_server: reason[%s]\n",reason));
}

/*
  initialise the thread process model, registering ourselves with the model subsystem
 */
NTSTATUS process_model_thread_init(void)
{
	NTSTATUS ret;
	struct model_ops ops;

	ZERO_STRUCT(ops);

	/* fill in our name */
	ops.name = "thread";

	/* fill in all the operations */
	ops.model_startup = model_startup;
	ops.accept_connection = accept_connection;
	ops.accept_rpc_connection = accept_rpc_connection;
	ops.terminate_connection = terminate_connection;
	ops.terminate_rpc_connection = terminate_rpc_connection;
	ops.exit_server = thread_exit_server;
	ops.get_id = get_id;

	/* register ourselves with the PROCESS_MODEL subsystem. */
	ret = register_backend("process_model", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register process_model 'thread'!\n"));
		return ret;
	}

	return ret;
}
