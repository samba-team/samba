# Server process model subsystem

################################################
# Start MODULE process_model_single
[MODULE::process_model_single]
INIT_FUNCTION = process_model_single_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_single.o
PRIVATE_DEPENDENCIES = KERBEROS_LIB
# End MODULE process_model_single
################################################

################################################
# Start MODULE process_model_standard
[MODULE::process_model_standard]
INIT_FUNCTION = process_model_standard_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_standard.o
PUBLIC_DEPENDENCIES = SETPROCTITLE
PRIVATE_DEPENDENCIES = KERBEROS_LIB
# End MODULE process_model_standard
################################################

################################################
# Start MODULE process_model_thread
[MODULE::process_model_thread]
INIT_FUNCTION = process_model_thread_init 
SUBSYSTEM = process_model
OBJ_FILES = \
		process_thread.o
PUBLIC_DEPENDENCIES = PTHREAD KERBEROS_LIB
# End MODULE process_model_thread
################################################

################################################
# Start SUBSYSTEM process_model
[LIBRARY::process_model]
VERSION = 0.0.1
SO_VERSION = 0
PRIVATE_PROTO_HEADER = process_model_proto.h
OBJ_FILES = \
		process_model.o
#
# End SUBSYSTEM process_model
################################################
