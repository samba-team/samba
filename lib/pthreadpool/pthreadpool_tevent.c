/*
 * Unix SMB/CIFS implementation.
 * threadpool implementation based on pthreads
 * Copyright (C) Volker Lendecke 2009,2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "system/select.h"
#include "system/threads.h"
#include "system/filesys.h"
#include "pthreadpool_tevent.h"
#include "pthreadpool.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/dlinklist.h"
#include "lib/util/attr.h"

/*
 * We try to give some hints to helgrind/drd
 *
 * Note ANNOTATE_BENIGN_RACE_SIZED(address, size, describtion)
 * takes an memory address range that ignored by helgrind/drd
 * 'description' is just ignored...
 *
 *
 * Note that ANNOTATE_HAPPENS_*(unique_uintptr)
 * just takes a DWORD/(void *) as unique key
 * for the barrier.
 */
#ifdef HAVE_VALGRIND_HELGRIND_H
#include <valgrind/helgrind.h>
#endif
#ifndef ANNOTATE_BENIGN_RACE_SIZED
#define ANNOTATE_BENIGN_RACE_SIZED(address, size, describtion)
#endif
#ifndef ANNOTATE_HAPPENS_BEFORE
#define ANNOTATE_HAPPENS_BEFORE(unique_uintptr)
#endif
#ifndef ANNOTATE_HAPPENS_AFTER
#define ANNOTATE_HAPPENS_AFTER(unique_uintptr)
#endif
#ifndef ANNOTATE_HAPPENS_BEFORE_FORGET_ALL
#define ANNOTATE_HAPPENS_BEFORE_FORGET_ALL(unique_uintptr)
#endif

#define PTHREAD_TEVENT_JOB_THREAD_FENCE_INIT(__job) do { \
	_UNUSED_ const struct pthreadpool_tevent_job *__j = __job; \
	ANNOTATE_BENIGN_RACE_SIZED(&__j->needs_fence, \
				   sizeof(__j->needs_fence), \
				   "race by design, protected by fence"); \
} while(0);

#ifdef WITH_PTHREADPOOL
/*
 * configure checked we have pthread and atomic_thread_fence() available
 */
#define __PTHREAD_TEVENT_JOB_THREAD_FENCE(__order) do { \
	atomic_thread_fence(__order); \
} while(0)
#else
/*
 * we're using lib/pthreadpool/pthreadpool_sync.c ...
 */
#define __PTHREAD_TEVENT_JOB_THREAD_FENCE(__order) do { } while(0)
#ifndef HAVE___THREAD
#define __thread
#endif
#endif

#define PTHREAD_TEVENT_JOB_THREAD_FENCE(__job) do { \
	_UNUSED_ const struct pthreadpool_tevent_job *__j = __job; \
	ANNOTATE_HAPPENS_BEFORE(&__job->needs_fence); \
	__PTHREAD_TEVENT_JOB_THREAD_FENCE(memory_order_seq_cst); \
	ANNOTATE_HAPPENS_AFTER(&__job->needs_fence); \
} while(0);

#define PTHREAD_TEVENT_JOB_THREAD_FENCE_FINI(__job) do { \
	_UNUSED_ const struct pthreadpool_tevent_job *__j = __job; \
	ANNOTATE_HAPPENS_BEFORE_FORGET_ALL(&__job->needs_fence); \
} while(0);

struct pthreadpool_tevent_job_state;

/*
 * We need one pthreadpool_tevent_glue object per unique combintaion of tevent
 * contexts and pthreadpool_tevent objects. Maintain a list of used tevent
 * contexts in a pthreadpool_tevent.
 */
struct pthreadpool_tevent_glue {
	struct pthreadpool_tevent_glue *prev, *next;
	struct pthreadpool_tevent *pool; /* back-pointer to owning object. */
	/* Tuple we are keeping track of in this list. */
	struct tevent_context *ev;
	struct tevent_threaded_context *tctx;
	/* recheck monitor fd event */
	struct tevent_fd *fde;
	/* Pointer to link object owned by *ev. */
	struct pthreadpool_tevent_glue_ev_link *ev_link;
	/* active jobs */
	struct pthreadpool_tevent_job_state *states;
};

/*
 * The pthreadpool_tevent_glue_ev_link and its destructor ensure we remove the
 * tevent context from our list of active event contexts if the event context
 * is destroyed.
 * This structure is talloc()'ed from the struct tevent_context *, and is a
 * back-pointer allowing the related struct pthreadpool_tevent_glue object
 * to be removed from the struct pthreadpool_tevent glue list if the owning
 * tevent_context is talloc_free()'ed.
 */
struct pthreadpool_tevent_glue_ev_link {
	struct pthreadpool_tevent_glue *glue;
};

struct pthreadpool_tevent_wrapper {
	struct pthreadpool_tevent *main_tp;
	struct pthreadpool_tevent *wrap_tp;
	const struct pthreadpool_tevent_wrapper_ops *ops;
	void *private_state;
	bool force_per_thread_cwd;
};

struct pthreadpool_tevent {
	struct pthreadpool_tevent *prev, *next;

	struct pthreadpool *pool;
	struct pthreadpool_tevent_glue *glue_list;

	struct pthreadpool_tevent_job *jobs;

	struct {
		/*
		 * This is used on the main context
		 */
		struct pthreadpool_tevent *list;

		/*
		 * This is used on the wrapper context
		 */
		struct pthreadpool_tevent_wrapper *ctx;
	} wrapper;
};

struct pthreadpool_tevent_job_state {
	struct pthreadpool_tevent_job_state *prev, *next;
	struct pthreadpool_tevent_glue *glue;
	struct tevent_context *ev;
	struct tevent_req *req;
	struct pthreadpool_tevent_job *job;
};

struct pthreadpool_tevent_job {
	struct pthreadpool_tevent_job *prev, *next;

	struct pthreadpool_tevent *pool;
	struct pthreadpool_tevent_wrapper *wrapper;
	struct pthreadpool_tevent_job_state *state;
	struct tevent_immediate *im;

	void (*fn)(void *private_data);
	void *private_data;

	/*
	 * Coordination between threads
	 *
	 * There're only one side writing each element
	 * either the main process or the job thread.
	 *
	 * The coordination is done by a full memory
	 * barrier using atomic_thread_fence(memory_order_seq_cst)
	 * wrapped in PTHREAD_TEVENT_JOB_THREAD_FENCE()
	 */
	struct {
		/*
		 * 'maycancel'
		 * set when tevent_req_cancel() is called.
		 * (only written by main thread!)
		 */
		bool maycancel;

		/*
		 * 'orphaned'
		 * set when talloc_free is called on the job request,
		 * tevent_context or pthreadpool_tevent.
		 * (only written by main thread!)
		 */
		bool orphaned;

		/*
		 * 'started'
		 * set when the job is picked up by a worker thread
		 * (only written by job thread!)
		 */
		bool started;

		/*
		 * 'wrapper'
		 * set before calling the wrapper before_job() or
		 * after_job() hooks.
		 * unset again check the hook finished.
		 * (only written by job thread!)
		 */
		bool wrapper;

		/*
		 * 'executed'
		 * set once the job function returned.
		 * (only written by job thread!)
		 */
		bool executed;

		/*
		 * 'finished'
		 * set when pthreadpool_tevent_job_signal() is entered
		 * (only written by job thread!)
		 */
		bool finished;

		/*
		 * 'dropped'
		 * set when pthreadpool_tevent_job_signal() leaves with
		 * orphaned already set.
		 * (only written by job thread!)
		 */
		bool dropped;

		/*
		 * 'signaled'
		 * set when pthreadpool_tevent_job_signal() leaves normal
		 * and the immediate event was scheduled.
		 * (only written by job thread!)
		 */
		bool signaled;

		/*
		 * 'exit_thread'
		 * maybe set during pthreadpool_tevent_job_fn()
		 * if some wrapper related code generated an error
		 * and the environment isn't safe anymore.
		 *
		 * In such a case pthreadpool_tevent_job_signal()
		 * will pick this up and therminate the current
		 * worker thread by returning -1.
		 */
		bool exit_thread; /* only written/read by job thread! */
	} needs_fence;

	bool per_thread_cwd;
};

static int pthreadpool_tevent_destructor(struct pthreadpool_tevent *pool);

static void pthreadpool_tevent_job_orphan(struct pthreadpool_tevent_job *job);

static struct pthreadpool_tevent_job *orphaned_jobs;

void pthreadpool_tevent_cleanup_orphaned_jobs(void)
{
	struct pthreadpool_tevent_job *job = NULL;
	struct pthreadpool_tevent_job *njob = NULL;

	for (job = orphaned_jobs; job != NULL; job = njob) {
		njob = job->next;

		/*
		 * The job destructor keeps the job alive
		 * (and in the list) or removes it from the list.
		 */
		TALLOC_FREE(job);
	}
}

static int pthreadpool_tevent_job_signal(int jobid,
					 void (*job_fn)(void *private_data),
					 void *job_private_data,
					 void *private_data);

int pthreadpool_tevent_init(TALLOC_CTX *mem_ctx, unsigned max_threads,
			    struct pthreadpool_tevent **presult)
{
	struct pthreadpool_tevent *pool;
	int ret;

	pthreadpool_tevent_cleanup_orphaned_jobs();

	pool = talloc_zero(mem_ctx, struct pthreadpool_tevent);
	if (pool == NULL) {
		return ENOMEM;
	}

	ret = pthreadpool_init(max_threads, &pool->pool,
			       pthreadpool_tevent_job_signal, pool);
	if (ret != 0) {
		TALLOC_FREE(pool);
		return ret;
	}

	talloc_set_destructor(pool, pthreadpool_tevent_destructor);

	*presult = pool;
	return 0;
}

static struct pthreadpool_tevent *pthreadpool_tevent_unwrap(
	struct pthreadpool_tevent *pool)
{
	struct pthreadpool_tevent_wrapper *wrapper = pool->wrapper.ctx;

	if (wrapper != NULL) {
		return wrapper->main_tp;
	}

	return pool;
}

size_t pthreadpool_tevent_max_threads(struct pthreadpool_tevent *pool)
{
	pool = pthreadpool_tevent_unwrap(pool);

	if (pool->pool == NULL) {
		return 0;
	}

	return pthreadpool_max_threads(pool->pool);
}

size_t pthreadpool_tevent_queued_jobs(struct pthreadpool_tevent *pool)
{
	pool = pthreadpool_tevent_unwrap(pool);

	if (pool->pool == NULL) {
		return 0;
	}

	return pthreadpool_queued_jobs(pool->pool);
}

bool pthreadpool_tevent_per_thread_cwd(struct pthreadpool_tevent *pool)
{
	struct pthreadpool_tevent_wrapper *wrapper = pool->wrapper.ctx;

	if (wrapper != NULL && wrapper->force_per_thread_cwd) {
		return true;
	}

	pool = pthreadpool_tevent_unwrap(pool);

	if (pool->pool == NULL) {
		return false;
	}

	return pthreadpool_per_thread_cwd(pool->pool);
}

static int pthreadpool_tevent_destructor(struct pthreadpool_tevent *pool)
{
	struct pthreadpool_tevent_job *job = NULL;
	struct pthreadpool_tevent_job *njob = NULL;
	struct pthreadpool_tevent *wrap_tp = NULL;
	struct pthreadpool_tevent *nwrap_tp = NULL;
	struct pthreadpool_tevent_glue *glue = NULL;
	int ret;

	if (pool->wrapper.ctx != NULL) {
		struct pthreadpool_tevent_wrapper *wrapper = pool->wrapper.ctx;

		pool->wrapper.ctx = NULL;
		pool = wrapper->main_tp;

		DLIST_REMOVE(pool->wrapper.list, wrapper->wrap_tp);

		for (job = pool->jobs; job != NULL; job = njob) {
			njob = job->next;

			if (job->wrapper != wrapper) {
				continue;
			}

			/*
			 * This removes the job from the list
			 *
			 * Note that it waits in case
			 * the wrapper hooks are currently
			 * executing on the job.
			 */
			pthreadpool_tevent_job_orphan(job);
		}

		/*
		 * At this point we're sure that no job
		 * still references the pthreadpool_tevent_wrapper
		 * structure, so we can free it.
		 */
		TALLOC_FREE(wrapper);

		pthreadpool_tevent_cleanup_orphaned_jobs();
		return 0;
	}

	if (pool->pool == NULL) {
		/*
		 * A dangling wrapper without main_tp.
		 */
		return 0;
	}

	ret = pthreadpool_stop(pool->pool);
	if (ret != 0) {
		return ret;
	}

	/*
	 * orphan all jobs (including wrapper jobs)
	 */
	for (job = pool->jobs; job != NULL; job = njob) {
		njob = job->next;

		/*
		 * The job this removes it from the list
		 *
		 * Note that it waits in case
		 * the wrapper hooks are currently
		 * executing on the job (thread).
		 */
		pthreadpool_tevent_job_orphan(job);
	}

	/*
	 * cleanup all existing wrappers, remember we just orphaned
	 * all jobs (including the once of the wrappers).
	 *
	 * So we just mark as broken, so that
	 * pthreadpool_tevent_job_send() won't accept new jobs.
	 */
	for (wrap_tp = pool->wrapper.list; wrap_tp != NULL; wrap_tp = nwrap_tp) {
		nwrap_tp = wrap_tp->next;

		/*
		 * Just mark them as broken, so that we can't
		 * get more jobs.
		 */
		TALLOC_FREE(wrap_tp->wrapper.ctx);

		DLIST_REMOVE(pool->wrapper.list, wrap_tp);
	}

	/*
	 * Delete all the registered
	 * tevent_context/tevent_threaded_context
	 * pairs.
	 */
	for (glue = pool->glue_list; glue != NULL; glue = pool->glue_list) {
		/* The glue destructor removes it from the list */
		TALLOC_FREE(glue);
	}
	pool->glue_list = NULL;

	ret = pthreadpool_destroy(pool->pool);
	if (ret != 0) {
		return ret;
	}
	pool->pool = NULL;

	pthreadpool_tevent_cleanup_orphaned_jobs();

	return 0;
}

struct pthreadpool_tevent *_pthreadpool_tevent_wrapper_create(
				struct pthreadpool_tevent *main_tp,
				TALLOC_CTX *mem_ctx,
				const struct pthreadpool_tevent_wrapper_ops *ops,
				void *pstate,
				size_t psize,
				const char *type,
				const char *location)
{
	void **ppstate = (void **)pstate;
	struct pthreadpool_tevent *wrap_tp = NULL;
	struct pthreadpool_tevent_wrapper *wrapper = NULL;

	pthreadpool_tevent_cleanup_orphaned_jobs();

	if (main_tp->wrapper.ctx != NULL) {
		/*
		 * stacking of wrappers is not supported
		 */
		errno = EINVAL;
		return NULL;
	}

	if (main_tp->pool == NULL) {
		/*
		 * The pool is no longer valid,
		 * most likely it was a wrapper context
		 * where the main pool was destroyed.
		 */
		errno = EINVAL;
		return NULL;
	}

	wrap_tp = talloc_zero(mem_ctx, struct pthreadpool_tevent);
	if (wrap_tp == NULL) {
		return NULL;
	}

	wrapper = talloc_zero(wrap_tp, struct pthreadpool_tevent_wrapper);
	if (wrapper == NULL) {
		TALLOC_FREE(wrap_tp);
		return NULL;
	}
	wrapper->main_tp = main_tp;
	wrapper->wrap_tp = wrap_tp;
	wrapper->ops = ops;
	wrapper->private_state = talloc_zero_size(wrapper, psize);
	if (wrapper->private_state == NULL) {
		TALLOC_FREE(wrap_tp);
		return NULL;
	}
	talloc_set_name_const(wrapper->private_state, type);

	wrap_tp->wrapper.ctx = wrapper;

	DLIST_ADD_END(main_tp->wrapper.list, wrap_tp);

	talloc_set_destructor(wrap_tp, pthreadpool_tevent_destructor);

	*ppstate = wrapper->private_state;
	return wrap_tp;
}

void pthreadpool_tevent_force_per_thread_cwd(struct pthreadpool_tevent *pool,
					     const void *private_state)
{
	struct pthreadpool_tevent_wrapper *wrapper = pool->wrapper.ctx;

	if (wrapper == NULL) {
		abort();
	}

	if (wrapper->private_state != private_state) {
		abort();
	}

	wrapper->force_per_thread_cwd = true;
}

static int pthreadpool_tevent_glue_destructor(
	struct pthreadpool_tevent_glue *glue)
{
	struct pthreadpool_tevent_job_state *state = NULL;
	struct pthreadpool_tevent_job_state *nstate = NULL;

	TALLOC_FREE(glue->fde);

	for (state = glue->states; state != NULL; state = nstate) {
		nstate = state->next;

		/* The job this removes it from the list */
		pthreadpool_tevent_job_orphan(state->job);
	}

	if (glue->pool->glue_list != NULL) {
		DLIST_REMOVE(glue->pool->glue_list, glue);
	}

	/* Ensure the ev_link destructor knows we're gone */
	glue->ev_link->glue = NULL;

	TALLOC_FREE(glue->ev_link);
	TALLOC_FREE(glue->tctx);

	return 0;
}

/*
 * Destructor called either explicitly from
 * pthreadpool_tevent_glue_destructor(), or indirectly
 * when owning tevent_context is destroyed.
 *
 * When called from pthreadpool_tevent_glue_destructor()
 * ev_link->glue is already NULL, so this does nothing.
 *
 * When called from talloc_free() of the owning
 * tevent_context we must ensure we also remove the
 * linked glue object from the list inside
 * struct pthreadpool_tevent.
 */
static int pthreadpool_tevent_glue_link_destructor(
	struct pthreadpool_tevent_glue_ev_link *ev_link)
{
	TALLOC_FREE(ev_link->glue);
	return 0;
}

static void pthreadpool_tevent_glue_monitor(struct tevent_context *ev,
					    struct tevent_fd *fde,
					    uint16_t flags,
					    void *private_data)
{
	struct pthreadpool_tevent_glue *glue =
		talloc_get_type_abort(private_data,
		struct pthreadpool_tevent_glue);
	struct pthreadpool_tevent_job *job = NULL;
	struct pthreadpool_tevent_job *njob = NULL;
	int ret = -1;

	ret = pthreadpool_restart_check_monitor_drain(glue->pool->pool);
	if (ret != 0) {
		TALLOC_FREE(glue->fde);
	}

	ret = pthreadpool_restart_check(glue->pool->pool);
	if (ret == 0) {
		/*
		 * success...
		 */
		goto done;
	}

	/*
	 * There's a problem and the pool
	 * has not a single thread available
	 * for pending jobs, so we can only
	 * stop the jobs and return an error.
	 * This is similar to a failure from
	 * pthreadpool_add_job().
	 */
	for (job = glue->pool->jobs; job != NULL; job = njob) {
		njob = job->next;

		tevent_req_defer_callback(job->state->req,
					  job->state->ev);
		tevent_req_error(job->state->req, ret);
	}

done:
	if (glue->states == NULL) {
		/*
		 * If the glue doesn't have any pending jobs
		 * we remove the glue.
		 *
		 * In order to remove the fd event.
		 */
		TALLOC_FREE(glue);
	}
}

static int pthreadpool_tevent_register_ev(
				struct pthreadpool_tevent *pool,
				struct pthreadpool_tevent_job_state *state)
{
	struct tevent_context *ev = state->ev;
	struct pthreadpool_tevent_glue *glue = NULL;
	struct pthreadpool_tevent_glue_ev_link *ev_link = NULL;
	int monitor_fd = -1;

	/*
	 * See if this tevent_context was already registered by
	 * searching the glue object list. If so we have nothing
	 * to do here - we already have a tevent_context/tevent_threaded_context
	 * pair.
	 */
	for (glue = pool->glue_list; glue != NULL; glue = glue->next) {
		if (glue->ev == state->ev) {
			state->glue = glue;
			DLIST_ADD_END(glue->states, state);
			return 0;
		}
	}

	/*
	 * Event context not yet registered - create a new glue
	 * object containing a tevent_context/tevent_threaded_context
	 * pair and put it on the list to remember this registration.
	 * We also need a link object to ensure the event context
	 * can't go away without us knowing about it.
	 */
	glue = talloc_zero(pool, struct pthreadpool_tevent_glue);
	if (glue == NULL) {
		return ENOMEM;
	}
	*glue = (struct pthreadpool_tevent_glue) {
		.pool = pool,
		.ev = ev,
	};
	talloc_set_destructor(glue, pthreadpool_tevent_glue_destructor);

	monitor_fd = pthreadpool_restart_check_monitor_fd(pool->pool);
	if (monitor_fd == -1 && errno != ENOSYS) {
		int saved_errno = errno;
		TALLOC_FREE(glue);
		return saved_errno;
	}

	if (monitor_fd != -1) {
		glue->fde = tevent_add_fd(ev,
					  glue,
					  monitor_fd,
					  TEVENT_FD_READ,
					  pthreadpool_tevent_glue_monitor,
					  glue);
		if (glue->fde == NULL) {
			close(monitor_fd);
			TALLOC_FREE(glue);
			return ENOMEM;
		}
		tevent_fd_set_auto_close(glue->fde);
	}

	/*
	 * Now allocate the link object to the event context. Note this
	 * is allocated OFF THE EVENT CONTEXT ITSELF, so if the event
	 * context is freed we are able to cleanup the glue object
	 * in the link object destructor.
	 */

	ev_link = talloc_zero(ev, struct pthreadpool_tevent_glue_ev_link);
	if (ev_link == NULL) {
		TALLOC_FREE(glue);
		return ENOMEM;
	}
	ev_link->glue = glue;
	talloc_set_destructor(ev_link, pthreadpool_tevent_glue_link_destructor);

	glue->ev_link = ev_link;

#ifdef HAVE_PTHREAD
	glue->tctx = tevent_threaded_context_create(glue, ev);
	if (glue->tctx == NULL) {
		TALLOC_FREE(ev_link);
		TALLOC_FREE(glue);
		return ENOMEM;
	}
#endif

	state->glue = glue;
	DLIST_ADD_END(glue->states, state);

	DLIST_ADD(pool->glue_list, glue);
	return 0;
}

static void pthreadpool_tevent_job_fn(void *private_data);
static void pthreadpool_tevent_job_done(struct tevent_context *ctx,
					struct tevent_immediate *im,
					void *private_data);
static bool pthreadpool_tevent_job_cancel(struct tevent_req *req);

static int pthreadpool_tevent_job_destructor(struct pthreadpool_tevent_job *job)
{
	/*
	 * We should never be called with needs_fence.orphaned == false.
	 * Only pthreadpool_tevent_job_orphan() will call TALLOC_FREE(job)
	 * after detaching from the request state, glue and pool list.
	 */
	if (!job->needs_fence.orphaned) {
		abort();
	}

	/*
	 * If the job is not finished (job->im still there)
	 * and it's still attached to the pool,
	 * we try to cancel it (before it was starts)
	 */
	if (job->im != NULL && job->pool != NULL) {
		size_t num;

		num = pthreadpool_cancel_job(job->pool->pool, 0,
					     pthreadpool_tevent_job_fn,
					     job);
		if (num != 0) {
			/*
			 * It was not too late to cancel the request.
			 *
			 * We can remove job->im, as it will never be used.
			 */
			TALLOC_FREE(job->im);
		}
	}

	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	if (job->needs_fence.dropped) {
		/*
		 * The signal function saw job->needs_fence.orphaned
		 * before it started the signaling via the immediate
		 * event. So we'll never geht triggered and can
		 * remove job->im and let the whole job go...
		 */
		TALLOC_FREE(job->im);
	}

	/*
	 * TODO?: We could further improve this by adjusting
	 * tevent_threaded_schedule_immediate_destructor()
	 * and allow TALLOC_FREE() during its time
	 * in the main_ev->scheduled_immediates list.
	 *
	 * PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	 * if (state->needs_fence.signaled) {
	 *       *
	 *       * The signal function is completed
	 *       * in future we may be allowed
	 *       * to call TALLOC_FREE(job->im).
	 *       *
	 *      TALLOC_FREE(job->im);
	 * }
	 */

	/*
	 * pthreadpool_tevent_job_orphan() already removed
	 * it from pool->jobs. And we don't need try
	 * pthreadpool_cancel_job() again.
	 */
	job->pool = NULL;

	if (job->im != NULL) {
		/*
		 * state->im still there means, we need to wait for the
		 * immediate event to be triggered or just leak the memory.
		 *
		 * Move it to the orphaned list, if it's not already there.
		 */
		return -1;
	}

	/*
	 * Finally remove from the orphaned_jobs list
	 * and let talloc destroy us.
	 */
	DLIST_REMOVE(orphaned_jobs, job);

	PTHREAD_TEVENT_JOB_THREAD_FENCE_FINI(job);
	return 0;
}

static void pthreadpool_tevent_job_orphan(struct pthreadpool_tevent_job *job)
{
	job->needs_fence.orphaned = true;
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);

	/*
	 * We're the only function that sets
	 * job->state = NULL;
	 */
	if (job->state == NULL) {
		abort();
	}

	/*
	 * Once we marked the request as 'orphaned'
	 * we spin/loop if 'wrapper' is marked as active.
	 *
	 * We need to wait until the wrapper hook finished
	 * before we can set job->wrapper = NULL.
	 *
	 * This is some kind of spinlock, but with
	 * 1 millisecond sleeps in between, in order
	 * to give the thread more cpu time to finish.
	 */
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	while (job->needs_fence.wrapper) {
		poll(NULL, 0, 1);
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	}
	job->wrapper = NULL;

	/*
	 * Once we marked the request as 'orphaned'
	 * we spin/loop if it's already marked
	 * as 'finished' (which means that
	 * pthreadpool_tevent_job_signal() was entered.
	 * If it saw 'orphaned' it will exit after setting
	 * 'dropped', otherwise it dereferences
	 * job->state->glue->{tctx,ev} until it exited
	 * after setting 'signaled'.
	 *
	 * We need to close this potential gab before
	 * we can set job->state = NULL.
	 *
	 * This is some kind of spinlock, but with
	 * 1 millisecond sleeps in between, in order
	 * to give the thread more cpu time to finish.
	 */
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	while (job->needs_fence.finished) {
		if (job->needs_fence.dropped) {
			break;
		}
		if (job->needs_fence.signaled) {
			break;
		}
		poll(NULL, 0, 1);
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	}

	/*
	 * Once the gab is closed, we can remove
	 * the glue link.
	 */
	DLIST_REMOVE(job->state->glue->states, job->state);
	job->state->glue = NULL;

	/*
	 * We need to reparent to a long term context.
	 * And detach from the request state.
	 * Maybe the destructor will keep the memory
	 * and leak it for now.
	 */
	(void)talloc_reparent(job->state, NULL, job);
	job->state->job = NULL;
	job->state = NULL;

	/*
	 * job->pool will only be set to NULL
	 * in the first destructur run.
	 */
	if (job->pool == NULL) {
		abort();
	}

	/*
	 * Dettach it from the pool.
	 *
	 * The job might still be running,
	 * so we keep job->pool.
	 * The destructor will set it to NULL
	 * after trying pthreadpool_cancel_job()
	 */
	DLIST_REMOVE(job->pool->jobs, job);

	/*
	 * Add it to the list of orphaned jobs,
	 * which may be cleaned up later.
	 *
	 * The destructor removes it from the list
	 * when possible or it denies the free
	 * and keep it in the list.
	 */
	DLIST_ADD_END(orphaned_jobs, job);
	TALLOC_FREE(job);
}

static void pthreadpool_tevent_job_cleanup(struct tevent_req *req,
					   enum tevent_req_state req_state)
{
	struct pthreadpool_tevent_job_state *state =
		tevent_req_data(req,
		struct pthreadpool_tevent_job_state);

	if (state->job == NULL) {
		/*
		 * The job request is not scheduled in the pool
		 * yet or anymore.
		 */
		if (state->glue != NULL) {
			DLIST_REMOVE(state->glue->states, state);
			state->glue = NULL;
		}
		return;
	}

	/*
	 * We need to reparent to a long term context.
	 * Maybe the destructor will keep the memory
	 * and leak it for now.
	 */
	pthreadpool_tevent_job_orphan(state->job);
	state->job = NULL; /* not needed but looks better */
	return;
}

struct tevent_req *pthreadpool_tevent_job_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct pthreadpool_tevent *pool,
	void (*fn)(void *private_data), void *private_data)
{
	struct tevent_req *req = NULL;
	struct pthreadpool_tevent_job_state *state = NULL;
	struct pthreadpool_tevent_job *job = NULL;
	int ret;
	struct pthreadpool_tevent *caller_pool = pool;
	struct pthreadpool_tevent_wrapper *wrapper = pool->wrapper.ctx;

	pthreadpool_tevent_cleanup_orphaned_jobs();

	if (wrapper != NULL) {
		pool = wrapper->main_tp;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct pthreadpool_tevent_job_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->req = req;

	tevent_req_set_cleanup_fn(req, pthreadpool_tevent_job_cleanup);

	if (pool == NULL) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	if (pool->pool == NULL) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	ret = pthreadpool_tevent_register_ev(pool, state);
	if (tevent_req_error(req, ret)) {
		return tevent_req_post(req, ev);
	}

	job = talloc_zero(state, struct pthreadpool_tevent_job);
	if (tevent_req_nomem(job, req)) {
		return tevent_req_post(req, ev);
	}
	job->pool = pool;
	job->wrapper = wrapper;
	job->fn = fn;
	job->private_data = private_data;
	job->im = tevent_create_immediate(state->job);
	if (tevent_req_nomem(job->im, req)) {
		return tevent_req_post(req, ev);
	}
	PTHREAD_TEVENT_JOB_THREAD_FENCE_INIT(job);
	job->per_thread_cwd = pthreadpool_tevent_per_thread_cwd(caller_pool);
	talloc_set_destructor(job, pthreadpool_tevent_job_destructor);
	DLIST_ADD_END(job->pool->jobs, job);
	job->state = state;
	state->job = job;

	ret = pthreadpool_add_job(job->pool->pool, 0,
				  pthreadpool_tevent_job_fn,
				  job);
	if (tevent_req_error(req, ret)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_cancel_fn(req, pthreadpool_tevent_job_cancel);
	return req;
}

static __thread struct pthreadpool_tevent_job *current_job;

bool pthreadpool_tevent_current_job_canceled(void)
{
	if (current_job == NULL) {
		/*
		 * Should only be called from within
		 * the job function.
		 */
		abort();
		return false;
	}

	PTHREAD_TEVENT_JOB_THREAD_FENCE(current_job);
	return current_job->needs_fence.maycancel;
}

bool pthreadpool_tevent_current_job_orphaned(void)
{
	if (current_job == NULL) {
		/*
		 * Should only be called from within
		 * the job function.
		 */
		abort();
		return false;
	}

	PTHREAD_TEVENT_JOB_THREAD_FENCE(current_job);
	return current_job->needs_fence.orphaned;
}

bool pthreadpool_tevent_current_job_continue(void)
{
	if (current_job == NULL) {
		/*
		 * Should only be called from within
		 * the job function.
		 */
		abort();
		return false;
	}

	PTHREAD_TEVENT_JOB_THREAD_FENCE(current_job);
	if (current_job->needs_fence.maycancel) {
		return false;
	}
	PTHREAD_TEVENT_JOB_THREAD_FENCE(current_job);
	if (current_job->needs_fence.orphaned) {
		return false;
	}

	return true;
}

bool pthreadpool_tevent_current_job_per_thread_cwd(void)
{
	if (current_job == NULL) {
		/*
		 * Should only be called from within
		 * the job function.
		 */
		abort();
		return false;
	}

	return current_job->per_thread_cwd;
}

static void pthreadpool_tevent_job_fn(void *private_data)
{
	struct pthreadpool_tevent_job *job =
		talloc_get_type_abort(private_data,
		struct pthreadpool_tevent_job);
	struct pthreadpool_tevent_wrapper *wrapper = NULL;

	current_job = job;
	job->needs_fence.started = true;
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	if (job->needs_fence.orphaned) {
		current_job = NULL;
		return;
	}

	wrapper = job->wrapper;
	if (wrapper != NULL) {
		bool ok;

		job->needs_fence.wrapper = true;
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
		if (job->needs_fence.orphaned) {
			job->needs_fence.wrapper = false;
			PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
			current_job = NULL;
			return;
		}
		ok = wrapper->ops->before_job(wrapper->wrap_tp,
					      wrapper->private_state,
					      wrapper->main_tp,
					      __location__);
		job->needs_fence.wrapper = false;
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
		if (!ok) {
			job->needs_fence.exit_thread = true;
			PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
			current_job = NULL;
			return;
		}
	}

	job->fn(job->private_data);

	job->needs_fence.executed = true;
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);

	if (wrapper != NULL) {
		bool ok;

		job->needs_fence.wrapper = true;
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
		if (job->needs_fence.orphaned) {
			job->needs_fence.wrapper = false;
			job->needs_fence.exit_thread = true;
			PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
			current_job = NULL;
			return;
		}
		ok = wrapper->ops->after_job(wrapper->wrap_tp,
					     wrapper->private_state,
					     wrapper->main_tp,
					     __location__);
		job->needs_fence.wrapper = false;
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
		if (!ok) {
			job->needs_fence.exit_thread = true;
			PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
			current_job = NULL;
			return;
		}
	}

	current_job = NULL;
}

static int pthreadpool_tevent_job_signal(int jobid,
					 void (*job_fn)(void *private_data),
					 void *job_private_data,
					 void *private_data)
{
	struct pthreadpool_tevent_job *job =
		talloc_get_type_abort(job_private_data,
		struct pthreadpool_tevent_job);

	job->needs_fence.finished = true;
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	if (job->needs_fence.orphaned) {
		/* Request already gone */
		job->needs_fence.dropped = true;
		PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
		if (job->needs_fence.exit_thread) {
			/*
			 * A problem with the wrapper the current job/worker
			 * thread needs to terminate.
			 *
			 * The pthreadpool_tevent is already gone.
			 */
			return -1;
		}
		return 0;
	}

	/*
	 * state and state->glue are valid,
	 * see the job->needs_fence.finished
	 * "spinlock" loop in
	 * pthreadpool_tevent_job_orphan()
	 */
	if (job->state->glue->tctx != NULL) {
		/* with HAVE_PTHREAD */
		tevent_threaded_schedule_immediate(job->state->glue->tctx,
						   job->im,
						   pthreadpool_tevent_job_done,
						   job);
	} else {
		/* without HAVE_PTHREAD */
		tevent_schedule_immediate(job->im,
					  job->state->glue->ev,
					  pthreadpool_tevent_job_done,
					  job);
	}

	job->needs_fence.signaled = true;
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	if (job->needs_fence.exit_thread) {
		/*
		 * A problem with the wrapper the current job/worker
		 * thread needs to terminate.
		 *
		 * The pthreadpool_tevent is already gone.
		 */
		return -1;
	}
	return 0;
}

static void pthreadpool_tevent_job_done(struct tevent_context *ctx,
					struct tevent_immediate *im,
					void *private_data)
{
	struct pthreadpool_tevent_job *job =
		talloc_get_type_abort(private_data,
		struct pthreadpool_tevent_job);
	struct pthreadpool_tevent_job_state *state = job->state;

	TALLOC_FREE(job->im);

	if (state == NULL) {
		/* Request already gone */
		TALLOC_FREE(job);
		return;
	}

	/*
	 * pthreadpool_tevent_job_cleanup()
	 * (called by tevent_req_done() or
	 * tevent_req_error()) will destroy the job.
	 */

	if (job->needs_fence.executed) {
		tevent_req_done(state->req);
		return;
	}

	tevent_req_error(state->req, ENOEXEC);
	return;
}

static bool pthreadpool_tevent_job_cancel(struct tevent_req *req)
{
	struct pthreadpool_tevent_job_state *state =
		tevent_req_data(req,
		struct pthreadpool_tevent_job_state);
	struct pthreadpool_tevent_job *job = state->job;
	size_t num;

	if (job == NULL) {
		return false;
	}

	job->needs_fence.maycancel = true;
	PTHREAD_TEVENT_JOB_THREAD_FENCE(job);
	if (job->needs_fence.started) {
		/*
		 * It was too late to cancel the request.
		 *
		 * The job still has the chance to look
		 * at pthreadpool_tevent_current_job_canceled()
		 * or pthreadpool_tevent_current_job_continue()
		 */
		return false;
	}

	num = pthreadpool_cancel_job(job->pool->pool, 0,
				     pthreadpool_tevent_job_fn,
				     job);
	if (num == 0) {
		/*
		 * It was too late to cancel the request.
		 */
		return false;
	}

	/*
	 * It was not too late to cancel the request.
	 *
	 * We can remove job->im, as it will never be used.
	 */
	TALLOC_FREE(job->im);

	/*
	 * pthreadpool_tevent_job_cleanup()
	 * will destroy the job.
	 */
	tevent_req_defer_callback(req, state->ev);
	tevent_req_error(req, ECANCELED);
	return true;
}

int pthreadpool_tevent_job_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}
