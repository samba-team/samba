# Server process model subsystem

################################################
# Start MODULE process_model_single
[MODULE::process_model_single]
INIT_FUNCTION = process_model_single_init 
SUBSYSTEM = process_model
# End MODULE process_model_single
################################################

process_model_single_OBJ_FILES = smbd/process_single.o

################################################
# Start MODULE process_model_standard
[MODULE::process_model_standard]
INIT_FUNCTION = process_model_standard_init 
SUBSYSTEM = process_model
PRIVATE_DEPENDENCIES = SETPROCTITLE
# End MODULE process_model_standard
################################################

process_model_standard_OBJ_FILES = smbd/process_standard.o

################################################
# Start MODULE process_model_thread
[MODULE::process_model_thread]
INIT_FUNCTION = process_model_thread_init 
SUBSYSTEM = process_model
PRIVATE_DEPENDENCIES = PTHREAD
# End MODULE process_model_thread
################################################

process_model_thread_OBJ_FILES = smbd/process_thread.o

################################################
# Start MODULE process_model_prefork
[MODULE::process_model_prefork]
INIT_FUNCTION = process_model_prefork_init 
SUBSYSTEM = process_model
# End MODULE process_model_thread
################################################

process_model_prefork_OBJ_FILES = smbd/process_prefork.o

[SUBSYSTEM::process_model]
PRIVATE_PROTO_HEADER = process_model_proto.h
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBSAMBA-HOSTCONFIG

process_model_OBJ_FILES = smbd/process_model.o
