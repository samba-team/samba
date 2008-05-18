################################################
# Start SUBSYSTEM LIBEVENTS
[LIBRARY::LIBEVENTS]
PUBLIC_DEPENDENCIES = LIBTALLOC
OUTPUT_TYPE = STATIC_LIBRARY
CFLAGS = -Ilib/events
#
# End SUBSYSTEM LIBEVENTS
################################################

##############################
[MODULE::EVENTS_AIO]
PRIVATE_DEPENDENCIES = LIBAIO_LINUX
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = s4_events_aio_init
##############################

EVENTS_AIO_OBJ_FILES = $(libeventssrcdir)/events_aio.o

##############################
[MODULE::EVENTS_EPOLL]
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = s4_events_epoll_init
##############################

EVENTS_EPOLL_OBJ_FILES = $(libeventssrcdir)/events_epoll.o

##############################
[MODULE::EVENTS_SELECT]
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = s4_events_select_init
##############################

EVENTS_SELECT_OBJ_FILES = $(libeventssrcdir)/events_select.o

##############################
[MODULE::EVENTS_STANDARD]
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = s4_events_standard_init
##############################

EVENTS_STANDARD_OBJ_FILES = $(libeventssrcdir)/events_standard.o

##############################
# Start SUBSYSTEM LIBEVENTS
[SUBSYSTEM::LIBEVENTS]
# End SUBSYSTEM LIBEVENTS
##############################

LIBEVENTS_OBJ_FILES = $(addprefix $(libeventssrcdir)/, events.o events_timed.o events_signal.o)

PUBLIC_HEADERS += $(addprefix $(libeventssrcdir)/, events.h events_internal.h)

[PYTHON::swig_events]
SWIG_FILE = events.i
PRIVATE_DEPENDENCIES = LIBEVENTS LIBSAMBA-HOSTCONFIG

swig_events_OBJ_FILES = $(libeventssrcdir)/events_wrap.o
