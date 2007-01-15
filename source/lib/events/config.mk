##############################
[MODULE::EVENTS_AIO]
OBJ_FILES = events_aio.o
PRIVATE_DEPENDENCIES = LIBAIO_LINUX
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = events_aio_init
##############################

##############################
[MODULE::EVENTS_EPOLL]
OBJ_FILES = events_epoll.o
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = events_epoll_init
##############################

##############################
[MODULE::EVENTS_SELECT]
OBJ_FILES = events_select.o
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = events_select_init
##############################

##############################
[MODULE::EVENTS_STANDARD]
OBJ_FILES = events_standard.o
SUBSYSTEM = LIBEVENTS
INIT_FUNCTION = events_standard_init
##############################


##############################
# Start SUBSYSTEM LIBEVENTS
[SUBSYSTEM::LIBEVENTS]
OBJ_FILES = events.o events_timed.o
PUBLIC_DEPENDENCIES = LIBTALLOC
# End SUBSYSTEM LIBEVENTS
##############################
