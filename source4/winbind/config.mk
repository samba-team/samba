# server subsystem

################################################
# Start MODULE server_service_winbind
[MODULE::server_service_winbind]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = SERVER_SERVICE
INIT_OBJ_FILES = \
		winbind/wb_server.o \
		winbind/wb_samba3_protocol.o \
		winbind/wb_samba3_cmd.o \
		winbind/wb_init_domain.o \
		winbind/wb_sid2domain.o \
		winbind/wb_domain_request.o \
		winbind/wb_connect_lsa.o \
		winbind/wb_connect_sam.o \
		winbind/wb_cmd_lookupname.o \
		winbind/wb_cmd_lookupsid.o \
		winbind/wb_cmd_getdcname.o \
		winbind/wb_cmd_userdomgroups.o \
		winbind/wb_cmd_usersids.o \
		winbind/wb_pam_auth.o \
		winbind/wb_async_helpers.o
REQUIRED_SUBSYSTEMS = RPC_NDR_LSA
# End MODULE server_service_winbind
################################################
