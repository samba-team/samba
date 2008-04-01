# Server process model subsystem

################################################
# Start MODULE process_model_single
[MODULE::process_model_single]
INIT_FUNCTION = process_model_single_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_single.o
# End MODULE process_model_single
################################################

################################################
# Start MODULE process_model_standard
[MODULE::process_model_standard]
INIT_FUNCTION = process_model_standard_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_standard.o
PRIVATE_DEPENDENCIES = SETPROCTITLE
# End MODULE process_model_standard
################################################

################################################
# Start MODULE process_model_thread
[MODULE::process_model_thread]
INIT_FUNCTION = process_model_thread_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_thread.o
PRIVATE_DEPENDENCIES = PTHREAD
# End MODULE process_model_thread
################################################

################################################
# Start MODULE process_model_prefork
[MODULE::process_model_prefork]
INIT_FUNCTION = process_model_prefork_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_prefork.o
# End MODULE process_model_thread
################################################

[SUBSYSTEM::process_model]
PRIVATE_PROTO_HEADER = process_model_proto.h
OBJ_FILES = \
		process_model.o
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBSAMBA-HOSTCONFIG
