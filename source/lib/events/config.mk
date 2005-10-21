##############################
# Start SUBSYSTEM LIBEVENTS
[SUBSYSTEM::LIBEVENTS]
NOPROTO = YES
INIT_OBJ_FILES = events.o
ADD_OBJ_FILES = events_standard.o
REQUIRED_SUBSYSTEMS = LIBTALLOC
# End SUBSYSTEM LIBEVENTS
##############################
