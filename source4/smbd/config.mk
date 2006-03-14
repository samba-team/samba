# server subsystem

################################################
# Start MODULE service_auth
[MODULE::service_auth]
INIT_FUNCTION = server_service_auth_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		auth
# End MODULE server_auth
################################################

################################################
# Start MODULE service_smb
[MODULE::service_smb]
INIT_FUNCTION = server_service_smb_init
OUTPUT_TYPE = MERGEDOBJ
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		SMB
# End MODULE server_smb
################################################

################################################
# Start MODULE service_rpc
[MODULE::service_rpc]
INIT_FUNCTION = server_service_rpc_init
SUBSYSTEM = service
OUTPUT_TYPE = MERGEDOBJ
REQUIRED_SUBSYSTEMS = \
		dcerpc_server
# End MODULE server_rpc
################################################

################################################
# Start MODULE service_ldap
[MODULE::service_ldap]
INIT_FUNCTION = server_service_ldap_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		LDAP
# End MODULE server_ldap
################################################

################################################
# Start MODULE service_nbtd
[MODULE::service_nbtd]
INIT_FUNCTION = server_service_nbtd_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		NBTD
# End MODULE service_nbtd
################################################

################################################
# Start MODULE service_wrepl
[MODULE::service_wrepl]
INIT_FUNCTION = server_service_wrepl_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		WREPL_SRV
# End MODULE service_wrepl
################################################

################################################
# Start MODULE service_cldapd
[MODULE::service_cldap]
INIT_FUNCTION = server_service_cldapd_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		CLDAPD
# End MODULE service_cldapd
################################################

################################################
# Start MODULE service_web
[MODULE::service_web]
INIT_FUNCTION = server_service_web_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		WEB
# End MODULE service_web
################################################

################################################
# Start MODULE service_web
[MODULE::service_kdc]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		KDC
# End MODULE service_web
################################################

################################################
# Start MODULE service_winbind
[MODULE::service_winbind]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = service
REQUIRED_SUBSYSTEMS = \
		WINBIND
# End MODULE service_winbind
################################################

#######################
# Start SUBSERVICE
[SUBSYSTEM::service]
PRIVATE_PROTO_HEADER = service_proto.h
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
MANPAGE = smbd.8
OBJ_FILES = \
		server.o
REQUIRED_SUBSYSTEMS = \
		process_model \
		service \
		CONFIG \
		LIBBASIC \
		PIDFILE \
		POPT_SAMBA \
		LIBPOPT
# End BINARY smbd
#################################
