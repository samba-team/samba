/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2021 Red Hat

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

#include "lib/util/debug.h"
#include "winbindd_traceid.h"
#include "tevent.h"

static void debug_traceid_trace_fde(struct tevent_fd *fde,
                                   enum tevent_event_trace_point point,
                                   void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_ATTACH:
        /* Assign the current traceid id when the event is created. */
        tevent_fd_set_tag(fde, debug_traceid_get());
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the traceid id when a handler is being called. */
        debug_traceid_set(tevent_fd_get_tag(fde));
        break;
    default:
        /* Do nothing. */
        break;
    }
}

static void debug_traceid_trace_signal(struct tevent_signal *se,
                                      enum tevent_event_trace_point point,
                                      void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_ATTACH:
        /* Assign the current traceid id when the event is created. */
        tevent_signal_set_tag(se, debug_traceid_get());
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the traceid id when a handler is being called. */
        debug_traceid_set(tevent_signal_get_tag(se));
        break;
    default:
        /* Do nothing. */
        break;
    }
}

static void debug_traceid_trace_timer(struct tevent_timer *timer,
                                     enum tevent_event_trace_point point,
                                     void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_ATTACH:
        /* Assign the current traceid id when the event is created. */
        tevent_timer_set_tag(timer, debug_traceid_get());
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the traceid id when a handler is being called. */
        debug_traceid_set(tevent_timer_get_tag(timer));
        break;
    default:
        /* Do nothing. */
        break;
    }
}

static void debug_traceid_trace_immediate(struct tevent_immediate *im,
                                         enum tevent_event_trace_point point,
                                         void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_ATTACH:
        /* Assign the current traceid id when the event is created. */
        tevent_immediate_set_tag(im, debug_traceid_get());
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the traceid id when a handler is being called. */
        debug_traceid_set(tevent_immediate_get_tag(im));
        break;
    default:
        /* Do nothing. */
        break;
    }
}

static void debug_traceid_trace_queue(struct tevent_queue_entry *qe,
                                         enum tevent_event_trace_point point,
                                         void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_ATTACH:
        /* Assign the current traceid id when the event is created. */
        tevent_queue_entry_set_tag(qe, debug_traceid_get());
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the traceid id when a handler is being called. */
        debug_traceid_set(tevent_queue_entry_get_tag(qe));
        break;
    default:
        /* Do nothing. */
        break;
    }
}

static void debug_traceid_trace_loop(enum tevent_trace_point point,
                                    void *private_data)
{
    switch (point) {
    case TEVENT_TRACE_AFTER_LOOP_ONCE:
        /* Reset traceid id when we got back to the loop. An event handler
         * that set traceid id was fired. This tracepoint represents a place
         * after the event handler was finished, we need to restore traceid
         * id to 1 (out of request). 0 means not initialized.
         */
        debug_traceid_set(1);
        break;
    default:
        /* Do nothing. */
        break;
    }
}

void winbind_debug_traceid_setup(struct tevent_context *ev)
{
    tevent_set_trace_callback(ev, debug_traceid_trace_loop, NULL);
    tevent_set_trace_fd_callback(ev, debug_traceid_trace_fde, NULL);
    tevent_set_trace_signal_callback(ev, debug_traceid_trace_signal, NULL);
    tevent_set_trace_timer_callback(ev, debug_traceid_trace_timer, NULL);
    tevent_set_trace_immediate_callback(ev, debug_traceid_trace_immediate, NULL);
    tevent_set_trace_queue_callback(ev, debug_traceid_trace_queue, NULL);
    debug_traceid_set(1);
}
