[SUBSYSTEM::LIBEVENTS]
PUBLIC_DEPENDENCIES = LIBTEVENT
CFLAGS = -Ilib/events

LIBEVENTS_OBJ_FILES = $(addprefix $(libeventssrcdir)/, events_dummy.o)

PUBLIC_HEADERS += $(addprefix $(libeventssrcdir)/, events.h events_internal.h)
