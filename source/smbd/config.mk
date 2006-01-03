# server subsystem

################################################
# Start MODULE server_service_auth
[MODULE::server_service_auth]
INIT_FUNCTION = server_service_auth_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		AUTH
# End MODULE server_auth
################################################

################################################
# Start MODULE server_service_smb
[MODULE::server_service_smb]
INIT_FUNCTION = server_service_smb_init
OUTPUT_TYPE = MERGEDOBJ
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		SMB
# End MODULE server_smb
################################################

################################################
# Start MODULE server_service_rpc
[MODULE::server_service_rpc]
INIT_FUNCTION = server_service_rpc_init
SUBSYSTEM = SERVER_SERVICE
OUTPUT_TYPE = MERGEDOBJ
REQUIRED_SUBSYSTEMS = \
		DCERPC_SERVER
# End MODULE server_rpc
################################################

################################################
# Start MODULE server_service_ldap
[MODULE::server_service_ldap]
INIT_FUNCTION = server_service_ldap_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		LDAP
# End MODULE server_ldap
################################################

################################################
# Start MODULE server_service_nbtd
[MODULE::server_service_nbtd]
INIT_FUNCTION = server_service_nbtd_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		NBTD
# End MODULE server_service_nbtd
################################################

################################################
# Start MODULE server_service_wrepl
[MODULE::server_service_wrepl]
INIT_FUNCTION = server_service_wrepl_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		WREPL_SRV
# End MODULE server_service_wrepl
################################################

################################################
# Start MODULE server_service_cldapd
[MODULE::server_service_cldap]
INIT_FUNCTION = server_service_cldapd_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		CLDAPD
# End MODULE server_service_cldapd
################################################

################################################
# Start MODULE server_service_web
[MODULE::server_service_web]
INIT_FUNCTION = server_service_web_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		WEB
# End MODULE server_service_web
################################################

################################################
# Start MODULE server_service_web
[MODULE::server_service_kdc]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		KDC
# End MODULE server_service_web
################################################

################################################
# Start MODULE server_service_winbind
[MODULE::server_service_winbind]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = SERVER_SERVICE
REQUIRED_SUBSYSTEMS = \
		WINBIND
# End MODULE server_service_winbind
################################################

#######################
# Start SUBSYSTEM SERVICE
[SUBSYSTEM::SERVER_SERVICE]
OBJ_FILES = \
		service.o \
		service_stream.o \
		service_task.o
REQUIRED_SUBSYSTEMS = \
		MESSAGING
# End SUBSYSTEM SERVER
#######################

#################################
# Start BINARY smbd
[BINARY::smbd]
INSTALLDIR = SBINDIR
OBJ_FILES = \
		server.o
REQUIRED_SUBSYSTEMS = \
		PROCESS_MODEL \
		SERVER_SERVICE \
		CONFIG \
		LIBBASIC \
		PIDFILE \
		POPT_SAMBA \
		LIBPOPT
# End BINARY smbd
#################################
