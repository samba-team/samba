##############################
[MODULE::TEVENT_AIO]
PRIVATE_DEPENDENCIES = LIBAIO_LINUX
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_AIO_OBJ_FILES = $(libteventsrcdir)/tevent_aio.o

##############################
[MODULE::TEVENT_EPOLL]
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_EPOLL_OBJ_FILES = $(libteventsrcdir)/tevent_epoll.o

##############################
[MODULE::TEVENT_SELECT]
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_SELECT_OBJ_FILES = $(libteventsrcdir)/tevent_select.o

##############################
[MODULE::TEVENT_STANDARD]
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_STANDARD_OBJ_FILES = $(libteventsrcdir)/tevent_standard.o

################################################
# Start SUBSYSTEM LIBTEVENT
[LIBRARY::LIBTEVENT]
PUBLIC_DEPENDENCIES = LIBTALLOC
OUTPUT_TYPE = MERGED_OBJ
CFLAGS = -I../lib/tevent
#
# End SUBSYSTEM LIBTEVENT
################################################

LIBTEVENT_OBJ_FILES = $(addprefix $(libteventsrcdir)/, tevent.o tevent_timed.o tevent_signal.o tevent_debug.o tevent_util.o tevent_s4.o)

PUBLIC_HEADERS += $(addprefix $(libteventsrcdir)/, tevent.h tevent_internal.h)

# TODO: Change python stuff to tevent
[PYTHON::swig_events]
LIBRARY_REALNAME = tevent.$(SHLIBEXT)
PRIVATE_DEPENDENCIES = LIBTEVENT PYTALLOC LIBSAMBA-UTIL

swig_events_OBJ_FILES = $(libteventsrcdir)/pytevent.o

$(swig_events_OBJ_FILES): CFLAGS+=$(CFLAG_NO_CAST_QUAL)

PC_FILES += $(libteventsrcdir)/tevent.pc
