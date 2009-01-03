##############################
[MODULE::TEVENT_AIO]
PRIVATE_DEPENDENCIES = LIBAIO_LINUX
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_AIO_OBJ_FILES = $(libteventsrcdir)/tevent_aio.o

##############################
[MODULE::TEVENT_EPOLL]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_EPOLL_OBJ_FILES = $(libteventsrcdir)/tevent_epoll.o

##############################
[MODULE::TEVENT_SELECT]
OUTPUT_TYPE = MERGED_OBJ
SUBSYSTEM = LIBTEVENT
##############################

TEVENT_SELECT_OBJ_FILES = $(libteventsrcdir)/tevent_select.o

##############################
[MODULE::TEVENT_STANDARD]
OUTPUT_TYPE = MERGED_OBJ
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

LIBTEVENT_OBJ_FILES = $(addprefix $(libteventsrcdir)/, tevent.o tevent_fd.o tevent_timed.o tevent_signal.o tevent_debug.o tevent_util.o)

PUBLIC_HEADERS += $(addprefix $(libteventsrcdir)/, tevent.h tevent_internal.h)
