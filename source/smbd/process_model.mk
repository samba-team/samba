# Server process model subsystem

################################################
# Start MODULE process_model_single
[MODULE::process_model_single]
INIT_OBJ_FILES = \
		smbd/process_single.o
# End MODULE process_model_single
################################################

################################################
# Start MODULE process_model_standard
[MODULE::process_model_standard]
INIT_OBJ_FILES = \
		smbd/process_standard.o
# End MODULE process_model_standard
################################################

################################################
# Start MODULE process_model_thread
[MODULE::process_model_thread]
INIT_OBJ_FILES = \
		smbd/process_thread.o
REQUIRED_LIBRARIES = \
		PTHREAD
# End MODULE process_model_thread
################################################

################################################
# Start SUBSYSTEM PROCESS_MODEL
[SUBSYSTEM::PROCESS_MODEL]
INIT_OBJ_FILES = \
		smbd/process_model.o
#
# End SUBSYSTEM PROCESS_MODEL
################################################