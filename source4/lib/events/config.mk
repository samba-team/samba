[SUBSYSTEM::LIBEVENTS]
PUBLIC_DEPENDENCIES = LIBTEVENT
CFLAGS = -Ilib/events

LIBEVENTS_OBJ_FILES = $(addprefix $(libeventssrcdir)/, tevent_s4.o)

PUBLIC_HEADERS += $(addprefix $(libeventssrcdir)/, events.h)
