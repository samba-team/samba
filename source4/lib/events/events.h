#ifndef __LIB_EVENTS_H__
#define __LIB_EVENTS_H__
#define TEVENT_COMPAT_DEFINES 1
#include <../lib/tevent/tevent.h>
struct event_context *s4_event_context_init(TALLOC_CTX *mem_ctx);
struct event_context *event_context_find(TALLOC_CTX *mem_ctx);
#endif /* __LIB_EVENTS_H__ */
