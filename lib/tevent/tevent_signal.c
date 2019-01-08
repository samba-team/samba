/*
   Unix SMB/CIFS implementation.

   common events code for signal events

   Copyright (C) Andrew Tridgell	2007

     ** NOTE! The following LGPL license applies to the tevent
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

#include "replace.h"
#include "system/filesys.h"
#include "system/wait.h"
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

/* maximum number of SA_SIGINFO signals to hold in the queue.
  NB. This *MUST* be a power of 2, in order for the ring buffer
  wrap to work correctly. Thanks to Petr Vandrovec <petr@vandrovec.name>
  for this. */

#define TEVENT_SA_INFO_QUEUE_COUNT 256

size_t tevent_num_signals(void)
{
	return TEVENT_NUM_SIGNALS;
}

size_t tevent_sa_info_queue_count(void)
{
	return TEVENT_SA_INFO_QUEUE_COUNT;
}

struct tevent_sigcounter {
	uint32_t count;
	uint32_t seen;
};

#if defined(HAVE___SYNC_FETCH_AND_ADD)
#define TEVENT_SIG_INCREMENT(s) __sync_fetch_and_add(&((s).count), 1)
#elif defined(HAVE_ATOMIC_ADD_32)
#define TEVENT_SIG_INCREMENT(s) atomic_add_32(&((s).count), 1)
#else
#define TEVENT_SIG_INCREMENT(s) (s).count++
#endif
#define TEVENT_SIG_SEEN(s, n) (s).seen += (n)
#define TEVENT_SIG_PENDING(s) ((s).seen != (s).count)

struct tevent_common_signal_list {
	struct tevent_common_signal_list *prev, *next;
	struct tevent_signal *se;
};

/*
  the poor design of signals means that this table must be static global
*/
static struct tevent_sig_state {
	struct tevent_common_signal_list *sig_handlers[TEVENT_NUM_SIGNALS+1];
	struct sigaction *oldact[TEVENT_NUM_SIGNALS+1];
	struct tevent_sigcounter signal_count[TEVENT_NUM_SIGNALS+1];
	struct tevent_sigcounter got_signal;
#ifdef SA_SIGINFO
	/* with SA_SIGINFO we get quite a lot of info per signal */
	siginfo_t *sig_info[TEVENT_NUM_SIGNALS+1];
	struct tevent_sigcounter sig_blocked[TEVENT_NUM_SIGNALS+1];
#endif
} *sig_state;

/*
  return number of sigcounter events not processed yet
*/
static uint32_t tevent_sig_count(struct tevent_sigcounter s)
{
	return s.count - s.seen;
}

/*
  signal handler - redirects to registered signals
*/
static void tevent_common_signal_handler(int signum)
{
	struct tevent_common_signal_list *sl;
	struct tevent_context *ev = NULL;
	int saved_errno = errno;

	TEVENT_SIG_INCREMENT(sig_state->signal_count[signum]);
	TEVENT_SIG_INCREMENT(sig_state->got_signal);

	/* Write to each unique event context. */
	for (sl = sig_state->sig_handlers[signum]; sl; sl = sl->next) {
		if (sl->se->event_ctx && sl->se->event_ctx != ev) {
			ev = sl->se->event_ctx;
			tevent_common_wakeup(ev);
		}
	}

	errno = saved_errno;
}

#ifdef SA_SIGINFO
/*
  signal handler with SA_SIGINFO - redirects to registered signals
*/
static void tevent_common_signal_handler_info(int signum, siginfo_t *info,
					      void *uctx)
{
	uint32_t count = tevent_sig_count(sig_state->signal_count[signum]);
	/* sig_state->signal_count[signum].seen % TEVENT_SA_INFO_QUEUE_COUNT
	 * is the base of the unprocessed signals in the ringbuffer. */
	uint32_t ofs = (sig_state->signal_count[signum].seen + count) %
				TEVENT_SA_INFO_QUEUE_COUNT;
	sig_state->sig_info[signum][ofs] = *info;

	tevent_common_signal_handler(signum);

	/* handle SA_SIGINFO */
	if (count+1 == TEVENT_SA_INFO_QUEUE_COUNT) {
		/* we've filled the info array - block this signal until
		   these ones are delivered */
#ifdef HAVE_UCONTEXT_T
		/*
		 * This is the only way for this to work.
		 * By default signum is blocked inside this
		 * signal handler using a temporary mask,
		 * but what we really need to do now is
		 * block it in the callers mask, so it
		 * stays blocked when the temporary signal
		 * handler mask is replaced when we return
		 * from here. The callers mask can be found
		 * in the ucontext_t passed in as the
		 * void *uctx argument.
		 */
		ucontext_t *ucp = (ucontext_t *)uctx;
		sigaddset(&ucp->uc_sigmask, signum);
#else
		/*
		 * WARNING !!! WARNING !!!!
		 *
		 * This code doesn't work.
		 * By default signum is blocked inside this
		 * signal handler, but calling sigprocmask
		 * modifies the temporary signal mask being
		 * used *inside* this handler, which will be
		 * replaced by the callers signal mask once
		 * we return from here. See Samba
		 * bug #9550 for details.
		 */
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, signum);
		sigprocmask(SIG_BLOCK, &set, NULL);
#endif
		TEVENT_SIG_INCREMENT(sig_state->sig_blocked[signum]);
	}
}
#endif

static int tevent_common_signal_list_destructor(struct tevent_common_signal_list *sl)
{
	if (sig_state->sig_handlers[sl->se->signum]) {
		DLIST_REMOVE(sig_state->sig_handlers[sl->se->signum], sl);
	}
	return 0;
}

/*
  destroy a signal event
*/
static int tevent_signal_destructor(struct tevent_signal *se)
{
	if (se->destroyed) {
		tevent_common_check_double_free(se, "tevent_signal double free");
		goto done;
	}
	se->destroyed = true;

	TALLOC_FREE(se->additional_data);

	if (se->event_ctx != NULL) {
		DLIST_REMOVE(se->event_ctx->signal_events, se);
	}

	if (sig_state->sig_handlers[se->signum] == NULL) {
		/* restore old handler, if any */
		if (sig_state->oldact[se->signum]) {
			sigaction(se->signum, sig_state->oldact[se->signum], NULL);
			TALLOC_FREE(sig_state->oldact[se->signum]);
		}
#ifdef SA_SIGINFO
		if (se->sa_flags & SA_SIGINFO) {
			if (sig_state->sig_info[se->signum]) {
				TALLOC_FREE(sig_state->sig_info[se->signum]);
			}
		}
#endif
	}

	se->event_ctx = NULL;
done:
	if (se->busy) {
		return -1;
	}
	se->wrapper = NULL;

	return 0;
}

/*
  add a signal event
  return NULL on failure (memory allocation error)
*/
struct tevent_signal *tevent_common_add_signal(struct tevent_context *ev,
					       TALLOC_CTX *mem_ctx,
					       int signum,
					       int sa_flags,
					       tevent_signal_handler_t handler,
					       void *private_data,
					       const char *handler_name,
					       const char *location)
{
	struct tevent_signal *se;
	struct tevent_common_signal_list *sl;
	sigset_t set, oldset;
	int ret;

	ret = tevent_common_wakeup_init(ev);
	if (ret != 0) {
		errno = ret;
		return NULL;
	}

	if (signum >= TEVENT_NUM_SIGNALS) {
		errno = EINVAL;
		return NULL;
	}

	/* the sig_state needs to be on a global context as it can last across
	   multiple event contexts */
	if (sig_state == NULL) {
		sig_state = talloc_zero(NULL, struct tevent_sig_state);
		if (sig_state == NULL) {
			return NULL;
		}
	}

	se = talloc_zero(mem_ctx?mem_ctx:ev, struct tevent_signal);
	if (se == NULL) return NULL;

	sl = talloc_zero(se, struct tevent_common_signal_list);
	if (!sl) {
		talloc_free(se);
		return NULL;
	}
	sl->se = se;

	*se = (struct tevent_signal) {
		.event_ctx	= ev,
		.signum		= signum,
		.sa_flags	= sa_flags,
		.handler	= handler,
		.private_data	= private_data,
		.handler_name	= handler_name,
		.location	= location,
		.additional_data= sl,
	};

	/* Ensure, no matter the destruction order, that we always have a handle on the global sig_state */
	if (!talloc_reference(se, sig_state)) {
		talloc_free(se);
		return NULL;
	}

	/* only install a signal handler if not already installed */
	if (sig_state->sig_handlers[signum] == NULL) {
		struct sigaction act;
		ZERO_STRUCT(act);
		act.sa_handler = tevent_common_signal_handler;
		act.sa_flags = sa_flags;
#ifdef SA_SIGINFO
		if (sa_flags & SA_SIGINFO) {
			act.sa_handler   = NULL;
			act.sa_sigaction = tevent_common_signal_handler_info;
			if (sig_state->sig_info[signum] == NULL) {
				sig_state->sig_info[signum] =
					talloc_zero_array(sig_state, siginfo_t,
							  TEVENT_SA_INFO_QUEUE_COUNT);
				if (sig_state->sig_info[signum] == NULL) {
					talloc_free(se);
					return NULL;
				}
			}
		}
#endif
		sig_state->oldact[signum] = talloc_zero(sig_state, struct sigaction);
		if (sig_state->oldact[signum] == NULL) {
			talloc_free(se);
			return NULL;
		}
		if (sigaction(signum, &act, sig_state->oldact[signum]) == -1) {
			talloc_free(sig_state->oldact[signum]);
			sig_state->oldact[signum] = NULL;
			talloc_free(se);
			return NULL;
		}
	}

	DLIST_ADD(se->event_ctx->signal_events, se);

	/* Make sure the signal doesn't come in while we're mangling list. */
	sigemptyset(&set);
	sigaddset(&set, signum);
	sigprocmask(SIG_BLOCK, &set, &oldset);
	DLIST_ADD(sig_state->sig_handlers[signum], sl);
	sigprocmask(SIG_SETMASK, &oldset, NULL);

	talloc_set_destructor(se, tevent_signal_destructor);
	talloc_set_destructor(sl, tevent_common_signal_list_destructor);

	return se;
}

int tevent_common_invoke_signal_handler(struct tevent_signal *se,
					int signum, int count, void *siginfo,
					bool *removed)
{
	struct tevent_context *handler_ev = se->event_ctx;
	bool remove = false;

	if (removed != NULL) {
		*removed = false;
	}

	if (se->event_ctx == NULL) {
		return 0;
	}

	se->busy = true;
	if (se->wrapper != NULL) {
		handler_ev = se->wrapper->wrap_ev;

		tevent_wrapper_push_use_internal(handler_ev, se->wrapper);
		se->wrapper->ops->before_signal_handler(
						se->wrapper->wrap_ev,
						se->wrapper->private_state,
						se->wrapper->main_ev,
						se,
						signum,
						count,
						siginfo,
						se->handler_name,
						se->location);
	}
	se->handler(handler_ev, se, signum, count, siginfo, se->private_data);
	if (se->wrapper != NULL) {
		se->wrapper->ops->after_signal_handler(
						se->wrapper->wrap_ev,
						se->wrapper->private_state,
						se->wrapper->main_ev,
						se,
						signum,
						count,
						siginfo,
						se->handler_name,
						se->location);
		tevent_wrapper_pop_use_internal(handler_ev, se->wrapper);
	}
	se->busy = false;

#ifdef SA_RESETHAND
	if (se->sa_flags & SA_RESETHAND) {
		remove = true;
	}
#endif

	if (se->destroyed) {
		talloc_set_destructor(se, NULL);
		remove = true;
	}

	if (remove) {
		TALLOC_FREE(se);
		if (removed != NULL) {
			*removed = true;
		}
	}

	return 0;
}

/*
  check if a signal is pending
  return != 0 if a signal was pending
*/
int tevent_common_check_signal(struct tevent_context *ev)
{
	int i;

	if (!sig_state || !TEVENT_SIG_PENDING(sig_state->got_signal)) {
		return 0;
	}

	for (i=0;i<TEVENT_NUM_SIGNALS+1;i++) {
		struct tevent_common_signal_list *sl, *next;
		struct tevent_sigcounter counter = sig_state->signal_count[i];
		uint32_t count = tevent_sig_count(counter);
		int ret;
#ifdef SA_SIGINFO
		/* Ensure we null out any stored siginfo_t entries
		 * after processing for debugging purposes. */
		bool clear_processed_siginfo = false;
#endif

		if (count == 0) {
			continue;
		}
		for (sl=sig_state->sig_handlers[i];sl;sl=next) {
			struct tevent_signal *se = sl->se;

			next = sl->next;

#ifdef SA_SIGINFO
			if (se->sa_flags & SA_SIGINFO) {
				uint32_t j;

				clear_processed_siginfo = true;

				for (j=0;j<count;j++) {
					/* sig_state->signal_count[i].seen
					 * % TEVENT_SA_INFO_QUEUE_COUNT is
					 * the base position of the unprocessed
					 * signals in the ringbuffer. */
					uint32_t ofs = (counter.seen + j)
						% TEVENT_SA_INFO_QUEUE_COUNT;
					bool removed = false;

					ret = tevent_common_invoke_signal_handler(
						se, i, 1,
						(void*)&sig_state->sig_info[i][ofs],
						&removed);
					if (ret != 0) {
						tevent_abort(ev, "tevent_common_invoke_signal_handler() failed");
					}
					if (removed) {
						break;
					}
				}
				continue;
			}
#endif

			ret = tevent_common_invoke_signal_handler(se, i, count,
								  NULL, NULL);
			if (ret != 0) {
				tevent_abort(ev, "tevent_common_invoke_signal_handler() failed");
			}
		}

#ifdef SA_SIGINFO
		if (clear_processed_siginfo && sig_state->sig_info[i] != NULL) {
			uint32_t j;
			for (j=0;j<count;j++) {
				uint32_t ofs = (counter.seen + j)
					% TEVENT_SA_INFO_QUEUE_COUNT;
				memset((void*)&sig_state->sig_info[i][ofs],
					'\0',
					sizeof(siginfo_t));
			}
		}
#endif

		TEVENT_SIG_SEEN(sig_state->signal_count[i], count);
		TEVENT_SIG_SEEN(sig_state->got_signal, count);

#ifdef SA_SIGINFO
		if (TEVENT_SIG_PENDING(sig_state->sig_blocked[i])) {
			/* We'd filled the queue, unblock the
			   signal now the queue is empty again.
			   Note we MUST do this after the
			   TEVENT_SIG_SEEN(sig_state->signal_count[i], count)
			   call to prevent a new signal running
			   out of room in the sig_state->sig_info[i][]
			   ring buffer. */
			sigset_t set;
			sigemptyset(&set);
			sigaddset(&set, i);
			TEVENT_SIG_SEEN(sig_state->sig_blocked[i],
				 tevent_sig_count(sig_state->sig_blocked[i]));
			sigprocmask(SIG_UNBLOCK, &set, NULL);
		}
#endif
	}

	return 1;
}

void tevent_cleanup_pending_signal_handlers(struct tevent_signal *se)
{
	tevent_signal_destructor(se);
	talloc_set_destructor(se, NULL);
	return;
}
