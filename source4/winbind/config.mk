# server subsystem

################################################
# Start MODULE server_service_auth
[MODULE::server_service_winbind]
INIT_FUNCTION = server_service_winbind_init
SUBSYSTEM = SERVER_SERVICE
INIT_OBJ_FILES = \
		winbind/wb_server.o
REQUIRED_SUBSYSTEMS = 
# End MODULE server_service_winbind
################################################
