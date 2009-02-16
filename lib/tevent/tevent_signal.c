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
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

#define NUM_SIGNALS 64

/* maximum number of SA_SIGINFO signals to hold in the queue */
#define SA_INFO_QUEUE_COUNT 100

struct sigcounter {
	uint32_t count;
	uint32_t seen;
};

#define SIG_INCREMENT(s) (s).count++
#define SIG_SEEN(s, n) (s).seen += (n)
#define SIG_PENDING(s) ((s).seen != (s).count)

struct tevent_common_signal_list {
	struct tevent_common_signal_list *prev, *next;
	struct tevent_signal *se;
};

/*
  the poor design of signals means that this table must be static global
*/
static struct sig_state {
	struct tevent_common_signal_list *sig_handlers[NUM_SIGNALS+1];
	struct sigaction *oldact[NUM_SIGNALS+1];
	struct sigcounter signal_count[NUM_SIGNALS+1];
	struct sigcounter got_signal;
	int pipe_hack[2];
#ifdef SA_SIGINFO
	/* with SA_SIGINFO we get quite a lot of info per signal */
	siginfo_t *sig_info[NUM_SIGNALS+1];
	struct sigcounter sig_blocked[NUM_SIGNALS+1];
#endif
} *sig_state;

/*
  return number of sigcounter events not processed yet
*/
static uint32_t sig_count(struct sigcounter s)
{
	if (s.count >= s.seen) {
		return s.count - s.seen;
	}
	return 1 + (0xFFFFFFFF & ~(s.seen - s.count));
}

/*
  signal handler - redirects to registered signals
*/
static void tevent_common_signal_handler(int signum)
{
	char c = 0;
	ssize_t res;
	SIG_INCREMENT(sig_state->signal_count[signum]);
	SIG_INCREMENT(sig_state->got_signal);
	/* doesn't matter if this pipe overflows */
	res = write(sig_state->pipe_hack[1], &c, 1);
}

#ifdef SA_SIGINFO
/*
  signal handler with SA_SIGINFO - redirects to registered signals
*/
static void tevent_common_signal_handler_info(int signum, siginfo_t *info,
					      void *uctx)
{
	uint32_t count = sig_count(sig_state->signal_count[signum]);
	sig_state->sig_info[signum][count] = *info;

	tevent_common_signal_handler(signum);

	/* handle SA_SIGINFO */
	if (count+1 == SA_INFO_QUEUE_COUNT) {
		/* we've filled the info array - block this signal until
		   these ones are delivered */
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, signum);
		sigprocmask(SIG_BLOCK, &set, NULL);
		SIG_INCREMENT(sig_state->sig_blocked[signum]);
	}
}
#endif

static int tevent_common_signal_list_destructor(struct tevent_common_signal_list *sl)
{
	DLIST_REMOVE(sig_state->sig_handlers[sl->se->signum], sl);
	return 0;
}

/*
  destroy a signal event
*/
static int tevent_signal_destructor(struct tevent_signal *se)
{
	struct tevent_common_signal_list *sl;
	sl = talloc_get_type(se->additional_data,
			     struct tevent_common_signal_list);

	if (se->event_ctx) {
		DLIST_REMOVE(se->event_ctx->signal_events, se);
	}

	talloc_free(sl);

	if (sig_state->sig_handlers[se->signum] == NULL) {
		/* restore old handler, if any */
		sigaction(se->signum, sig_state->oldact[se->signum], NULL);
		sig_state->oldact[se->signum] = NULL;
#ifdef SA_SIGINFO
		if (se->sa_flags & SA_SIGINFO) {
			talloc_free(sig_state->sig_info[se->signum]);
			sig_state->sig_info[se->signum] = NULL;
		}
#endif
	}

	return 0;
}

/*
  this is part of the pipe hack needed to avoid the signal race condition
*/
static void signal_pipe_handler(struct tevent_context *ev, struct tevent_fd *fde, 
				uint16_t flags, void *private)
{
	char c[16];
	ssize_t res;
	/* its non-blocking, doesn't matter if we read too much */
	res = read(sig_state->pipe_hack[0], c, sizeof(c));
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

	if (signum >= NUM_SIGNALS) {
		errno = EINVAL;
		return NULL;
	}

	/* the sig_state needs to be on a global context as it can last across
	   multiple event contexts */
	if (sig_state == NULL) {
		sig_state = talloc_zero(talloc_autofree_context(), struct sig_state);
		if (sig_state == NULL) {
			return NULL;
		}
	}

	se = talloc(mem_ctx?mem_ctx:ev, struct tevent_signal);
	if (se == NULL) return NULL;

	se->event_ctx		= ev;
	se->signum              = signum;
	se->sa_flags            = sa_flags;
	se->handler		= handler;
	se->private_data	= private_data;
	se->handler_name	= handler_name;
	se->location		= location;
	se->additional_data	= NULL;

	sl = talloc(se, struct tevent_common_signal_list);
	if (!sl) {
		talloc_free(se);
		return NULL;
	}
	sl->se = se;
	se->additional_data	= sl;

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
				sig_state->sig_info[signum] = talloc_array(sig_state, siginfo_t, SA_INFO_QUEUE_COUNT);
				if (sig_state->sig_info[signum] == NULL) {
					talloc_free(se);
					return NULL;
				}
			}
		}
#endif
		sig_state->oldact[signum] = talloc(sig_state, struct sigaction);
		if (sig_state->oldact[signum] == NULL) {
			talloc_free(se);
			return NULL;			
		}
		if (sigaction(signum, &act, sig_state->oldact[signum]) == -1) {
			talloc_free(se);
			return NULL;
		}
	}

	DLIST_ADD(se->event_ctx->signal_events, se);
	DLIST_ADD(sig_state->sig_handlers[signum], sl);

	talloc_set_destructor(se, tevent_signal_destructor);
	talloc_set_destructor(sl, tevent_common_signal_list_destructor);

	/* we need to setup the pipe hack handler if not already
	   setup */
	if (ev->pipe_fde == NULL) {
		if (sig_state->pipe_hack[0] == 0 && 
		    sig_state->pipe_hack[1] == 0) {
			if (pipe(sig_state->pipe_hack) == -1) {
				talloc_free(se);
				return NULL;
			}
			ev_set_blocking(sig_state->pipe_hack[0], false);
			ev_set_blocking(sig_state->pipe_hack[1], false);
		}
		ev->pipe_fde = tevent_add_fd(ev, ev, sig_state->pipe_hack[0],
					     TEVENT_FD_READ, signal_pipe_handler, NULL);
		if (!ev->pipe_fde) {
			talloc_free(se);
			return NULL;
		}
	}

	return se;
}


/*
  check if a signal is pending
  return != 0 if a signal was pending
*/
int tevent_common_check_signal(struct tevent_context *ev)
{
	int i;

	if (!sig_state || !SIG_PENDING(sig_state->got_signal)) {
		return 0;
	}
	
	for (i=0;i<NUM_SIGNALS+1;i++) {
		struct tevent_common_signal_list *sl, *next;
		struct sigcounter counter = sig_state->signal_count[i];
		uint32_t count = sig_count(counter);

		if (count == 0) {
			continue;
		}
		for (sl=sig_state->sig_handlers[i];sl;sl=next) {
			struct tevent_signal *se = sl->se;
			next = sl->next;
#ifdef SA_SIGINFO
			if (se->sa_flags & SA_SIGINFO) {
				int j;
				for (j=0;j<count;j++) {
					/* note the use of the sig_info array as a
					   ring buffer */
					int ofs = ((count-1) + j) % SA_INFO_QUEUE_COUNT;
					se->handler(ev, se, i, 1, 
						    (void*)&sig_state->sig_info[i][ofs], 
						    se->private_data);
				}
				if (SIG_PENDING(sig_state->sig_blocked[i])) {
					/* we'd filled the queue, unblock the
					   signal now */
					sigset_t set;
					sigemptyset(&set);
					sigaddset(&set, i);
					SIG_SEEN(sig_state->sig_blocked[i], 
						 sig_count(sig_state->sig_blocked[i]));
					sigprocmask(SIG_UNBLOCK, &set, NULL);
				}
				if (se->sa_flags & SA_RESETHAND) {
					talloc_free(se);
				}
				continue;
			}
#endif
			se->handler(ev, se, i, count, NULL, se->private_data);
			if (se->sa_flags & SA_RESETHAND) {
				talloc_free(se);
			}
		}
		SIG_SEEN(sig_state->signal_count[i], count);
		SIG_SEEN(sig_state->got_signal, count);
	}

	return 1;
}
