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

################################################
# Start SUBSYSTEM LIBEVENTS
[LIBRARY::LIBEVENTS]
PUBLIC_DEPENDENCIES = LIBTALLOC
OUTPUT_TYPE = MERGED_OBJ
CFLAGS = -Ilib/events
#
# End SUBSYSTEM LIBEVENTS
################################################

LIBEVENTS_OBJ_FILES = $(addprefix $(libeventssrcdir)/, events.o events_timed.o events_signal.o events_debug.o events_util.o events_s4.o)

PUBLIC_HEADERS += $(addprefix $(libeventssrcdir)/, events.h events_internal.h)

[PYTHON::swig_events]
LIBRARY_REALNAME = samba/_events.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBEVENTS LIBSAMBA-HOSTCONFIG LIBSAMBA-UTIL

swig_events_OBJ_FILES = $(libeventssrcdir)/events_wrap.o

$(eval $(call python_py_module_template,samba/events.py,$(libeventssrcdir)/events.py))

$(swig_events_OBJ_FILES): CFLAGS+=$(CFLAG_NO_UNUSED_MACROS) $(CFLAG_NO_CAST_QUAL)

PC_FILES += $(libeventssrcdir)/events.pc
