# server subsystem

################################################
# Start MODULE server_auth
[MODULE::server_auth]
REQUIRED_SUBSYSTEMS = \
		AUTH
# End MODULE server_auth
################################################

################################################
# Start MODULE server_smb
[MODULE::server_smb]
REQUIRED_SUBSYSTEMS = \
		SMB
# End MODULE server_smb
################################################

################################################
# Start MODULE server_rpc
[MODULE::server_rpc]
REQUIRED_SUBSYSTEMS = \
		DCERPC
# End MODULE server_rpc
################################################

#######################
# Start SUBSYSTEM SERVER
[SUBSYSTEM::SERVER]
INIT_OBJ_FILES = \
		smbd/server.o
ADD_OBJ_FILES = \
		smbd/process.o \
		lib/server_mutex.o \
		smbd/build_options.o \
		smbd/rewrite.o
REQUIRED_SUBSYSTEMS = \
		PROCESS_MODEL
# End SUBSYSTEM SERVER
#######################

#################################
# Start BINARY smbd
[BINARY::smbd]
REQUIRED_SUBSYSTEMS = \
		SERVER \
		CONFIG \
		LIBCMDLINE \
		LIBBASIC
# End BINARY smbd
#################################
