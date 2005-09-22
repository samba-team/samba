# server subsystem

################################################
# Start MODULE server_service_winbind
[MODULE::server_service_winbind]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = SERVER_SERVICE
INIT_OBJ_FILES = \
		winbind/wb_server.o \
		winbind/wb_samba3_protocol.o \
		winbind/wb_samba3_cmd.o
REQUIRED_SUBSYSTEMS = 
# End MODULE server_service_winbind
################################################
