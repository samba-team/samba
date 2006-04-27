# server subsystem

################################################
# Start MODULE service_auth
[MODULE::service_auth]
INIT_FUNCTION = server_service_auth_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		auth
# End MODULE server_auth
################################################

################################################
# Start MODULE service_smb
[MODULE::service_smb]
INIT_FUNCTION = server_service_smb_init
OUTPUT_TYPE = INTEGRATED
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		SMB_SERVER
# End MODULE server_smb
################################################

################################################
# Start MODULE service_rpc
[MODULE::service_rpc]
INIT_FUNCTION = server_service_rpc_init
SUBSYSTEM = service
OUTPUT_TYPE = INTEGRATED
PUBLIC_DEPENDENCIES = \
		dcerpc_server
# End MODULE server_rpc
################################################

################################################
# Start MODULE service_ldap
[MODULE::service_ldap]
INIT_FUNCTION = server_service_ldap_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		LDAP
# End MODULE server_ldap
################################################

################################################
# Start MODULE service_nbtd
[MODULE::service_nbtd]
INIT_FUNCTION = server_service_nbtd_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		NBTD
# End MODULE service_nbtd
################################################

################################################
# Start MODULE service_wrepl
[MODULE::service_wrepl]
INIT_FUNCTION = server_service_wrepl_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		WREPL_SRV
# End MODULE service_wrepl
################################################

################################################
# Start MODULE service_cldapd
[MODULE::service_cldap]
INIT_FUNCTION = server_service_cldapd_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		CLDAPD
# End MODULE service_cldapd
################################################

################################################
# Start MODULE service_web
[MODULE::service_web]
INIT_FUNCTION = server_service_web_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		WEB
# End MODULE service_web
################################################

################################################
# Start MODULE service_web
[MODULE::service_kdc]
INIT_FUNCTION = server_service_kdc_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
		KDC
# End MODULE service_web
################################################

################################################
# Start MODULE service_winbind
[MODULE::service_winbind]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = service
PUBLIC_DEPENDENCIES = \
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
PUBLIC_DEPENDENCIES = \
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
PRIVATE_DEPENDENCIES = \
		process_model \
		service \
		LIBSAMBA-CONFIG \
		LIBSAMBA-UTIL \
		PIDFILE \
		POPT_SAMBA \
		LIBPOPT \
		gensec \
		registry \
		ntptr \
		ntvfs
# End BINARY smbd
#################################
